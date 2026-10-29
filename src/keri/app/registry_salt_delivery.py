"""Bounded registry-salt delivery on the caller's existing HIO scheduler.

The service owns authority, signing and exact recipient selection; the state
owner retains immutable attempts before I/O. Transport completion never proves
root retention. Only the service's authenticated receipt path completes a job.
This module creates no Parser, mailbox, database environment or signing runtime.
"""

from datetime import datetime, timezone
import math
import time

from hio.base import doing

from .. import Vrsn_2_0
from ..core import SerderKERI
from ..help import helping
from ..kering import AuthError, ConfigurationError, KeriError, MissingEntryError, ValidationError
from .forwarding import StreamPoster
from .registry_salt_state import SaltScanLimit


class SaltTransportAttempt(doing.DoDoer):
    """Supervise one finite salt delivery without failing its caller's runtime.

    The caller owns scheduling/cancellation and interprets ``done`` together
    with ``error``. Success means TCP submission or HTTP 2xx, never protocol
    acceptance, group consent or retained custody. This owner opens no store.
    """

    def __init__(self, children, timeout, **kwa):
        """Own finite children for at most timeout scheduler seconds; open no store."""
        self.children = tuple(children)
        self.timeout = timeout
        self.started = None
        self.wallStarted = time.monotonic()
        self.error = None
        super().__init__(doers=list(children), **kwa)

    def recur(self, tyme, deeds=None):
        """Return completion, recording timeout/error/non-2xx as transport failure.

        tyme/deeds follow the borrowed HIO scheduler. TCP success is buffer drain;
        HTTP success additionally requires a 2xx response, never a custody claim.
        """
        if self.started is None:
            self.started = tyme
        if (tyme - self.started >= self.timeout or
                time.monotonic() - self.wallStarted >= self.timeout):
            self.error = 'transport timeout'
        else:
            try:
                complete = super().recur(tyme, deeds)
            except Exception:
                self.error = 'transport failure'
            else:
                if not complete:
                    return False
                for child in self.children:
                    if hasattr(child, 'rep'):
                        # HIO Client.respond returns a Response namedtuple.
                        status = getattr(child.rep, 'status', None)
                        if not isinstance(status, int) or not 200 <= status < 300:
                            self.error = 'HTTP delivery rejected'
        self.remove(list(self.children))
        return True


class RegistrySaltDelivery(doing.DoDoer):
    """Run finite attempts for one explicit logical source and local receipts."""

    def __init__(self, service, source, *, limit=4, timeout=5.0,
                 receiptTimeout=2.0, clock=None, tock=0.1, **kwa):
        """Borrow service/state/runtime owners and bound I/O concurrency and waits.

        Parameters: service supplies hby/state/parser/maxAge and the agreed
            prepareProvision/prepareReceipt methods; source is the explicit
            logical sending party. limit bounds active finite attempts; timeout
            bounds network I/O; receiptTimeout bounds the application-ack wait;
            clock returns Unix seconds; tock controls the existing HIO schedule.
        Returns: an unscheduled DoDoer. Raises: ConfigurationError for bad bounds.
        """
        if (isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or
                any(isinstance(value, bool) or not isinstance(value, (int, float))
                    or not math.isfinite(value) or value <= 0
                    for value in (timeout, receiptTimeout, tock))):
            raise ConfigurationError('registry-salt delivery requires positive finite bounds')
        self.service, self.state, self.source = service, service.state, source
        self.limit, self.timeout, self.receiptTimeout = limit, timeout, receiptTimeout
        self.clock = clock if clock is not None else time.time
        self.active = {}
        self.cursors = {True: None, False: None}
        self.error = None
        super().__init__(doers=[doing.doify(self.deliveryDo)], tock=tock, **kwa)

    @staticmethod
    def _delay(attempts):
        """Return a small capped local delay after actual launched attempts."""
        return min(4.0, 0.25 * 2 ** min(max(attempts - 1, 0), 4))

    def _children(self, body, essr, target):
        """Return finite transport owners for an already sealed ultimate envelope.

        body is the signed inner reply; essr is exact persisted outer bytes;
        target is its individual destination. Raises before launch when routing
        or local signing ownership is unavailable. Never seals a second time.
        """
        outer = SerderKERI(raw=essr)
        q = outer.sad.get('q', {})
        hab = self.service.hby.habByPre(body.pre)
        if (hab is None or outer.pre != body.pre or outer.route != '/essr/req' or
                q.get('src') != body.pre or q.get('dest') != target):
            raise ValidationError('registry-salt outgoing envelope has invalid local binding')
        if self.service.hby.habByPre(target) is not None:
            raise ConfigurationError('registry-salt local custody needs no network loopback')
        poster = StreamPoster(hby=self.service.hby, hab=hab, recp=target,
                              topic='multisig', essr=False, version=Vrsn_2_0)
        poster.send(outer, attachment=essr[outer.size:], gvrsn=Vrsn_2_0)
        children = poster.deliver()
        if not children:
            raise ConfigurationError('registry-salt recipient transport is unavailable')
        return children

    def _prepare(self, row, receipt, now):
        """Retain a service-prepared immutable attempt before constructing any I/O.

        row is a due SaltDelivery/receipt intent; receipt selects that workflow;
        now is Unix time. Returns the CAS-updated row, body and envelope, or None
        on conflict. No failed-send count is changed by preparation/readiness.
        """
        stamp = helping.toIso8601(datetime.fromtimestamp(now, timezone.utc))
        if receipt:
            body, signed, essr = self.service.prepareReceipt(row.provision, stamp=stamp)
            prior = self.state.attempt(row.reply) if row.reply else None
        else:
            body, signed, essr = self.service.prepareProvision(row, self.source, stamp=stamp)
            prior = self.state.currentAttempt(row.key)
        if prior is not None and prior.reply == body.said:
            if prior.signedBytes != signed or prior.essrBytes != essr:
                raise ValidationError('registry-salt immutable attempt bytes changed')
            return row, body, essr
        outer = SerderKERI(raw=essr)
        q = outer.sad['q']
        recipientEst = dict(s=q['sn'], d=q['dig'])
        created = helping.fromIso8601(body.stamp).timestamp()
        expires = created + self.service.maxAge
        if expires <= now:
            raise ConfigurationError('registry-salt outgoing reply is already stale')
        record = self.state.recordReceiptAttempt if receipt else self.state.recordAttempt
        updated = record(row, body, signed, essr, recipientEst, created, expires)
        return (updated, body, essr) if updated is not None else None

    def _start(self, row, receipt, now):
        """Prepare and launch one due row; readiness failures remain pending.

        Returns no value. Only actual HIO child launch increments attempts;
        a small local roster-index stagger grants no ownership or authority.
        """
        key = ('receipt', row.provision) if receipt else ('provision', row.key)
        if key in self.active:
            return
        now = self.clock()
        try:
            prepared = self._prepare(row, receipt, now)
            if prepared is None:
                return
            row, body, essr = prepared
            if not receipt:
                roster = self.state.roster(self.source)
                rank = next((member.index for member in roster.members if member.aid == body.pre), 0) if roster else 0
                ready = helping.fromIso8601(body.stamp).timestamp() + min(1.0, 0.2 * rank)
                if now < ready:
                    return
            target = row.source if receipt else row.member
            now = self.clock()
            remaining = helping.fromIso8601(body.stamp).timestamp() + self.service.maxAge - now
            if remaining <= 0:
                raise ConfigurationError('registry-salt outgoing live authentication expired')
            children = self._children(body, essr, target)
        except AuthError:
            self.error = 'registry-salt custody authorization is unavailable'
            return
        except MissingEntryError:
            self.error = 'registry-salt authenticated evidence is unavailable'
            return
        except (KeriError, ValueError, OSError):
            self.error = 'registry-salt delivery is not ready'
            return
        now = self.clock()
        remaining = min(remaining, helping.fromIso8601(body.stamp).timestamp() + self.service.maxAge - now)
        if remaining <= 0:
            self.error = 'registry-salt outgoing live authentication expired'
            return
        deadline = now + (self.timeout if receipt else self.receiptTimeout + self._delay(row.attempts + 1))
        mark = self.state.markReceiptAttempt if receipt else self.state.markAttempt
        try:
            launched = mark(row, now, deadline)
        except KeriError:
            self.error = 'registry-salt outgoing attempt is not ready'
            return
        if launched is None:
            return
        attempt = SaltTransportAttempt(children, min(self.timeout, remaining), tock=self.tock)
        self.active[key] = (attempt, launched, receipt)
        try:
            self.extend([attempt])
        except Exception:
            self._finish(key, now, 'transport launch failed')

    def _finish(self, key, now, error=None):
        """Close one actual attempt and persist failure or receipt transport status.

        key selects an active attempt; now is Unix time; error overrides its
        outcome. Provision transport success leaves the custody job pending.
        """
        attempt, row, receipt = self.active.pop(key)
        self.remove([attempt])
        error = error or attempt.error
        if error:
            self.error = error
            fail = self.state.failReceiptAttempt if receipt else self.state.failAttempt
            fail(row, now, self._delay(row.attempts))
        elif receipt:
            self.state.markReceiptSent(row)

    def deliveryDo(self, tymth, tock=0.1, **kwa):
        """Process bounded due work while the caller schedules this worker.

        HIO supplies tymth/tock/kwa. Yields scheduler ticks indefinitely; no new
        scheduler, parser or mailbox is created, and readiness never backs off.
        Each tick examines at most SaltScanLimit persisted candidate rows;
        page reads close their transactions before any scheduler yield.
        """
        self.wind(tymth)
        yield self.tock
        while True:
            now = self.clock()
            for key, (attempt, row, receipt) in tuple(self.active.items()):
                current = self.state.receipt(row.provision) if receipt else self.state.delivery(*row.key)
                if current is None or current.state != 'pending':
                    self.active.pop(key)
                    self.remove([attempt])
                elif attempt.done:
                    self._finish(key, now)
            budget = SaltScanLimit
            for receipt in (True, False):
                if len(self.active) >= self.limit:
                    break
                candidates = self.state.receiptCandidates if receipt else self.state.deliveryCandidates
                # Reserve half the scan budget for provisions even when receipt
                # history has no due items. Returned rows fit remaining I/O slots.
                page = candidates(now, limit=self.limit - len(self.active),
                    after=self.cursors[receipt], scanLimit=budget // 2 if receipt else budget)
                budget -= page.examined
                self.cursors[receipt] = page.after
                for row in page.items:
                    self._start(row, receipt, now)
                if budget == 0:
                    break
            yield self.tock

    def exit(self, deeds=None):
        """Cancel owned finite I/O on caller exit without recording false failures.

        deeds is HIO's optional narrower removal queue. Only whole-worker exit
        clears in-memory tracking; durable attempt/deadline state remains intact.
        """
        try:
            super().exit(deeds=deeds)
        finally:
            if deeds is None:
                self.active.clear()
