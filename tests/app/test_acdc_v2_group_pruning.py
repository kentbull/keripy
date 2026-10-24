"""ACDC v2 group cache maintenance follows the concrete Kramer runtime owner."""
import pytest
from hio.base import doing

from keri.acdc import grant, loadHandlers
from keri.app.acdc_v2_grouping import AcdcV2GroupCoordinator
from keri.core import Pruner
from keri.peer.exchanging import Exchanger, serializeMessage
from tests.app.test_acdc_v2_groups import Notices, groupMembers


@pytest.mark.parametrize('shared', [False, True])
def test_group_pruner_has_one_owner_and_cancels_with_its_runtime(fakeHelpingClock, shared):
    """Scheduled expiry preserves retained EXNs and stops when its runtime stops.

    Args:
        fakeHelpingClock: Controllable protocol clock; scheduler time advances
            separately so expiry is exercised without long sleeps.
        shared (bool): Use a caller-owned Kramer/Pruner or coordinator-owned pair.

    Returns:
        None. Assertions cover real signed grant intake, one maintenance owner,
        eligible expiry, cancellation, and renewed scheduling without losing EXNs.
    """
    with groupMembers('pruning-shared' if shared else 'pruning-owned') as members:
        hbys, groups, rgys, owners = members
        owner = owners[0]
        assert isinstance(owner.pruner, Pruner)
        assert owner.pruner.kramer is owner.mux.kvy.kramer
        assert [child for child in owner.doers if isinstance(child, Pruner)] == [owner.pruner]
        runtimes = [owner]
        receiver = owner
        if shared:
            exc = Exchanger(hbys[0], handlers=[])
            loadHandlers(hbys[0], exc, Notices(), rgy=rgys[0])
            receiver = AcdcV2GroupCoordinator(hbys[0], rgys[0], groups[0], exc, Notices(),
                                   kramer=owner.mux.kvy.kramer)
            assert receiver.pruner is None
            assert not any(isinstance(child, Pruner) for child in receiver.doers)
            runtimes.append(receiver)
        sender = groups[0].mhab

        def receiveGrant(message):
            """Authenticate one real empty ACDC v2 IPEX Grant to populate the group KRAM cache.

            Args:
                message (str): Human payload distinguishing independent signed Grants.

            Returns:
                tuple: Exchange, exact transactional cache key, and retained cache record.
                Assertions require ordinary group exchange acceptance before returning."""
            exn, atc = grant(sender, groups[0].pre, message)
            receiver.receive(exn.raw + atc)
            assert receiver.completeExchange(exn.said)
            key = (sender.pre, exn.sad['x'], exn.said)
            cache = hbys[0].db.kramTMSC.get(key)
            assert cache is not None
            return exn, key, cache

        first, firstKey, firstCache = receiveGrant('before scheduled expiry')
        retained = serializeMessage(hbys[0], first.said)
        scheduler = doing.Doist(tock=0.1, real=False, doers=runtimes)
        scheduler.enter()
        try:
            scheduler.recur()
            assert hbys[0].db.kramTMSC.get(firstKey) is not None
            fakeHelpingClock.advance(milliseconds=firstCache.pxl + 60000)
            for _ in range(20):
                scheduler.recur()
            assert hbys[0].db.kramTMSC.get(firstKey) is None
            assert serializeMessage(hbys[0], first.said) == retained
        finally:
            scheduler.exit()
        # Intake remains usable after stopping runtime work. Expired cache rows
        # remain until the owner is scheduled again, proving cancellation matters.
        later, laterKey, laterCache = receiveGrant('after runtime cancellation')
        fakeHelpingClock.advance(milliseconds=laterCache.pxl + 60000)
        assert hbys[0].db.kramTMSC.get(laterKey) is not None
        resumed = doing.Doist(tock=0.1, real=False, doers=runtimes)
        resumed.enter()
        try:
            for _ in range(20):
                resumed.recur()
            assert hbys[0].db.kramTMSC.get(laterKey) is None
            assert receiver.completeExchange(later.said)
            assert serializeMessage(hbys[0], first.said) == retained
        finally:
            resumed.exit()
