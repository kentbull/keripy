"""Installed presentation selects admitted views; Unblind never grants use by itself."""
import json
import shutil
import subprocess
import time
from contextlib import ExitStack, closing
from uuid import uuid4

from hio.base import doing

from keri import Vrsn_2_0 as V2
from keri.acdc import Regery, Registrar, regeventing
from keri.app import Habery, Receiptor, StreamPoster, multisigExn
from keri.cli.common import setupHby
from keri.core import BlindState, Blinder, Kevery, Kramer, Parser, SealSource, SerderACDC, SerderKERI, messagize
from keri.db import Baser
from keri.help import toIso8601
from keri.peer import Exchanger
from keri.peer.exchanging import loadParsedNestedSubstreams, serializeParsedSubstream, verify
from keri.acdc.ipexing import admit as native_admit, loadHandlers
from types import SimpleNamespace

from tests.cli.commands.test_native_issuance_cli import PASSCODE, issue, live_parties, witnessed
from tests.cli.commands.test_native_registry_root_cli import group_copy, last_result, retained
from tests.cli.commands.test_native_negotiation_cli import enable_kram, exchange_deadline, kli

import pytest
pytestmark = pytest.mark.real_store_roots


def state(side):
    return setupHby(name=side['name'], base=side['base'], bran=PASSCODE, noPrompt=True, version=V2)


def update(side, credential, output, *, value='', bound=False):
    """Use the existing real witness receipt path for each exact native BUP anchor."""
    hby = state(side)
    rgy = Regery(hby, name=side['name'], base=side['base'])
    try:
        hab = hby.habByName(side['alias'])
        reg = rgy.regs[credential.regid]
        root = hab.mgr.getRegistryRoot(hab.pre, reg.regk)
        kwargs = dict(salt=root.qb64)
        if bound:
            issuee = hby.db.kevers[credential.iseaid]
            kwargs.update(bound=True, bsn=issuee.sn, bd=issuee.serder.said)
        registrar = Registrar(rgy)
        proof, event = (registrar.issue(reg, credential, state=value, **kwargs) if value else
            registrar.vacate(reg, **(dict(kwargs, bsn=0, bd='') if bound else kwargs)))
        anchor = SerderKERI(raw=hab.interact(
            data=[dict(i=reg.regk, s=event.sad['n'], d=event.said)], gvrsn=V2))
        receipts = Receiptor(hby=hby)
        def receipt(tymth, tock=0.03125, **kwa):
            yield tock
            yield from receipts.receipt(hab.pre, sn=anchor.sn)
            owner.remove([receipts])
        owner = doing.DoDoer(doers=[receipts, doing.doify(receipt)])
        doing.Doist(real=True, tock=0.03125, limit=10).do(doers=[owner])
        assert owner.done and reg.anchorMsg(event.said)
        output.write_bytes(bytes(hab.replay(gvrsn=V2)) + messagize(event,
            bonds=[SealSource(s=anchor.snh, d=anchor.said)], gvrsn=V2))
        return event, proof
    finally:
        rgy.close()
        hby.close()


def intake(side, raw, *, proof=None, event=None):
    hby = state(side)
    rgy = Regery(hby, name=side['name'], base=side['base'])
    try:
        exc = Exchanger(hby, handlers=[])
        loadHandlers(hby, exc, SimpleNamespace(add=lambda **_: None), rgy=rgy)
        # Receive like installed kli: through the Habery's configured KRAM.
        kvy = Kevery(db=hby.db, rvy=hby.rvy, exc=exc, local=False, direct=False, lax=True,
                     kramer=Kramer(db=hby.db, cf=hby.cf))
        Parser(kvy=kvy, rvy=hby.rvy, rgy=rgy, exc=exc, version=V2).parse(ims=bytearray(raw))
        if proof:
            assert rgy.store.putOpening(event.said, proof)
    finally:
        rgy.close()
        hby.close()


def present(tmp_path, sender, receiver, source, filename, *extra, succeeds=True, admit_options=()):
    evidence, log = tmp_path / (filename + '.cesr'), tmp_path / (filename + '.log')
    with log.open('w') as output:
        process = subprocess.Popen([shutil.which('kli'), 'ipex', 'present', *sender['args'],
            '--from-grant', source, '--recipient', receiver['pre'], '--input', str(receiver['public']),
            '--respond-unblind', '--deliver', '--output', str(evidence), '--timeout', '12', *extra],
            cwd=tmp_path, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while not evidence.exists():
                assert process.poll() is None, log.read_text()
                assert time.monotonic() < deadline, log.read_text()
                time.sleep(0.03)
            selected = next(json.loads(line) for line in log.read_text().splitlines() if line.startswith('{'))
            intake(receiver, evidence.read_bytes())
            before = inspect(tmp_path, receiver, selected['grant'])
            admitted = kli(tmp_path, 'ipex', 'admit', *receiver['args'], '--unblind', '--said', selected['grant'],
                '--deliver', '--timeout', '10', *admit_options, succeeds=succeeds)
            if succeeds:
                process.wait(timeout=15)
                assert process.returncode == 0 and 'ERR:' not in log.read_text(), log.read_text()
                result = last_result(admitted)
                assert result == last_result(log.read_text())
                return selected['grant'], before, inspect(tmp_path, receiver, selected['grant'])
            assert 'current verified issued state' in admitted, admitted
            return selected['grant'], before, inspect(tmp_path, receiver, selected['grant'])
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


def inspect(tmp_path, side, said, *, current=False):
    args = ['--name', side['name'], '--base', side['base'], '--version', '2.0', '--said', said]
    return last_result(kli(tmp_path, 'ipex', 'inspect', *args, *(['--current'] if current else [])))


def snapshot(side):
    hby = state(side)
    rgy = Regery(hby, name=side['name'], base=side['base'])
    try:
        return [(label, bytes(key), bytes(value)) for owner in (hby.db, rgy.baser)
                for label, suber in vars(owner).items() if hasattr(suber, 'sdb')
                for key, value in owner.env.begin().cursor(suber.sdb)]
    finally:
        rgy.close()
        hby.close()


def test_selected_admitted_view_unblind_refresh_and_read_only_inspection(tmp_path, live_parties):
    issuer, holder = live_parties
    selected, body = issue(tmp_path, live_parties,
        data='{"d":"","shown":{"d":"","name":"Ada"},"secret":{"d":"","name":"hidden"}}')
    old = inspect(tmp_path, holder, selected['grant'])
    refused = kli(tmp_path, 'ipex', 'present', *issuer['args'], '--from-grant', selected['grant'],
        '--recipient', holder['pre'], '--deliver', succeeds=False)
    assert 'local recipient' in refused
    assert inspect(tmp_path, holder, selected['grant'], current=True)['current']['observations'][body.said]['state'] == 'issued'
    later = tmp_path / 'vacate.cesr'
    update(issuer, body, later)
    public = Parser(version=V2).parse(ims=bytearray(later.read_bytes()), processive=False)
    intake(holder, b''.join(serializeParsedSubstream(child) for child in public[:-1]))
    # Recipient knows a newer vacuous head; sender still carries the issued proof.
    presented, before, received = present(tmp_path, holder, issuer, selected['grant'], 'partial',
        '--disclose', 'a/shown/')
    assert received['deadline'] == before['deadline'] and received['terminal']
    assert not before['accepted'] and received['accepted']
    assert received['grant'] == before['grant']
    assert received['disclosure'][0]['raw_b64'] == before['disclosure'][0]['raw_b64']
    assert received['disclosure'][0]['evidence_b64'] != before['disclosure'][0]['evidence_b64']
    assert received['disclosure'][0]['body']['a']['shown']['name'] == 'Ada'
    assert isinstance(received['disclosure'][0]['body']['a']['secret'], str)
    assert inspect(tmp_path, holder, selected['grant']) == old

    # The issuer also holds the full same-SAID body, but must use its admitted partial.
    update(issuer, body, later, value='issued')
    intake(holder, later.read_bytes())
    rejected = kli(tmp_path, 'ipex', 'present', *issuer['args'], '--from-grant', presented,
        '--recipient', holder['pre'], '--deliver', succeeds=False)
    assert 'current verified issued state' in rejected
    original = inspect(tmp_path, issuer, presented)
    second, _, received2 = present(tmp_path, issuer, holder, presented, 'refreshed', '--refresh', '--derive')
    assert second != presented
    assert [node['raw_b64'] for node in received2['disclosure']] == [node['raw_b64'] for node in original['disclosure']]
    assert inspect(tmp_path, issuer, presented) == original
    cannot_widen = kli(tmp_path, 'ipex', 'present', *issuer['args'], '--from-grant', presented,
        '--recipient', holder['pre'], '--refresh', '--derive', '--disclose', 'a/secret/', '--deliver', succeeds=False)
    assert 'Invalid disclosure' in cannot_widen
    state_before = snapshot(issuer)
    assert inspect(tmp_path, issuer, presented)['observations'] == original['observations']
    assert inspect(tmp_path, issuer, presented, current=True)['current']['verdict']['verdict'] == 'unknown'
    assert snapshot(issuer) == state_before
    assert inspect(tmp_path, holder, selected['grant']) == old


def test_provisioned_nonlead_presents_exact_group_view_at_native_threshold(tmp_path, live_parties):
    issuer, holders, body, selected = group_copy(tmp_path, live_parties,
        data='{"d":"","shown":{"d":"","name":"Ada"},"secret":{"d":"","name":"hidden"}}')
    before = [inspect(tmp_path, side, selected['grant']) for side in holders]
    later = tmp_path / 'group-issued2.cesr'
    update(issuer, body, later, value='issued')
    for side in holders:
        intake(side, later.read_bytes())
    # The verifier has independent keys and public history, never a registry root.
    name, base = f'group-verifier-{uuid4().hex}', issuer['base']
    hby = Habery(name=name, base=base, bran=PASSCODE, version=V2)
    try:
        enable_kram(hby)  # Its live Unblind needs the accepted KRAM transaction, like any kli verifier.
        witness = (tmp_path / 'witness.cesr').read_bytes()
        Parser(kvy=hby.kvy, rvy=hby.rvy, version=V2).parse(ims=bytearray(witness))
        wit = Parser(version=V2).parseOneBare(ims=bytearray(witness), processive=False).serder.pre
        hab = hby.makeHab(name='verifier', wits=[wit], toad=1)
        witnessed(hby, hab)
        public = tmp_path / 'group-verifier.cesr'
        public.write_bytes(bytes(hab.replay(gvrsn=V2)))
        verifier = dict(name=name, base=base, alias='verifier', pre=hab.pre, public=public,
            args=['--name', name, '--base', base, '--alias', 'verifier', '--passcode', PASSCODE, '--version', '2.0'])
    finally:
        hby.close()
    hby = state(issuer)
    rgy = Regery(hby, name=issuer['name'], base=issuer['base'])
    try:
        evidence = bytes(hby.habByName(issuer['alias']).replay(gvrsn=V2))
        for raw in rgy.store.cloneTelIter(body.regid):
            event = SerderACDC(raw=raw)
            sn, said = regeventing.vetAnchor(event, db=hby.db, issuer=issuer['pre'])
            evidence += messagize(event, bonds=[SealSource(s=f'{sn:x}', d=said)], gvrsn=V2)
        history = tmp_path / 'group-history.cesr'
        history.write_bytes(evidence)
    finally:
        rgy.close()
        hby.close()
    common = ['--from-grant', selected['grant'], '--recipient', verifier['pre'],
              '--input', str(public), '--disclose', 'a/shown/', '--deliver', '--timeout', '20']
    proposal = tmp_path / 'group-present-proposal.cesr'
    refused = kli(tmp_path, 'ipex', 'present', *holders[1]['args'], *common,
        '--proposal-output', str(proposal), succeeds=False)
    assert 'current verified issued state' in refused and not proposal.exists()
    logs = [tmp_path / 'group-present-creator.log', tmp_path / 'group-present-contributor.log']
    outputs = [tmp_path / 'group-present-creator.cesr', tmp_path / 'group-present-contributor.cesr']
    processes = []
    with logs[0].open('w') as first, logs[1].open('w') as second:
        try:
            processes.append(subprocess.Popen([shutil.which('kli'), 'ipex', 'present', *holders[1]['args'],
                *common, '--refresh', '--derive', '--proposal-output', str(proposal), '--output', str(outputs[0])],
                cwd=tmp_path, stdout=first, stderr=subprocess.STDOUT))
            deadline = time.monotonic() + 10
            while '"phase": "group_proposed"' not in logs[0].read_text():
                assert processes[0].poll() is None, logs[0].read_text()
                assert time.monotonic() < deadline, logs[0].read_text()
                time.sleep(.03)
            proposed = next(json.loads(line) for line in logs[0].read_text().splitlines() if line.startswith('{'))
            assert not proposed['locally_accepted'] and not outputs[0].exists()
            db = Baser(name=holders[1]['name'], base=base, readonly=True, reopen=True)
            try:
                assert db.exns.get((proposed['grant'],)) is None
                # A partial proposal has no authenticated KRAM lifetime before threshold intake.
                assert exchange_deadline(db, proposed['grant']) is None
            finally:
                db.close()
            processes.append(subprocess.Popen([shutil.which('kli'), 'ipex', 'present', *holders[0]['args'],
                *common, '--refresh', '--proposal', str(proposal), '--output', str(outputs[1])],
                cwd=tmp_path, stdout=second, stderr=subprocess.STDOUT))
            for process in processes:
                process.wait(timeout=25)
            assert all(p.returncode == 0 for p in processes), '\n'.join(log.read_text() for log in logs)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
    results = [next(json.loads(line) for line in reversed(log.read_text().splitlines()) if line.startswith('{'))
               for log in logs]
    assert not results[0]['transmitted'] and results[1]['transmitted']
    assert all(result['grant'] == proposed['grant'] and result['locally_accepted'] for result in results)
    # A retained authenticated proposal cannot authorize a different recipient in another invocation.
    invalid = tmp_path / 'group-wrong-recipient.cesr'
    rejected = kli(tmp_path, 'ipex', 'present', *holders[0]['args'], '--from-grant', selected['grant'],
        '--recipient', issuer['pre'], '--disclose', 'a/shown/', '--refresh', '--proposal', str(proposal),
        '--output', str(invalid), '--deliver', succeeds=False)
    assert 'selected admitted-view scope' in rejected and not invalid.exists()
    admitted_result = kli(tmp_path, 'ipex', 'admit', *verifier['args'], '--unblind', '--said', proposed['grant'],
        '--input', str(history), '--input', str(outputs[1]), '--deliver', '--timeout', '15')
    result = next(json.loads(line) for line in reversed(admitted_result.splitlines()) if line.startswith('{'))
    assert result['admitted'] and result['grant'] == proposed['grant']
    received = inspect(tmp_path, verifier, proposed['grant'])
    assert isinstance(received['disclosure'][0]['body']['a']['secret'], str)
    assert received['disclosure'][0]['body']['a']['shown']['name'] == 'Ada'
    for side in holders:
        assert inspect(tmp_path, side, selected['grant']) == before[holders.index(side)]
    hby = state(holders[1])
    try:
        assert exchange_deadline(hby.db, proposed['grant']) is not None
        # Authenticate a fuller disclosure of the SAME SAID; selected a/shown/ must still cap approval.
        packet = Parser(version=V2).parseOneBare(ims=bytearray(proposal.read_bytes()), processive=False)
        child = packet.nests[0]
        partial = child.nests[0].serder
        full = loadParsedNestedSubstreams(hby, selected['grant'])[0].serder
        assert partial.said == full.said and partial.raw != full.raw
        child.nests[0].serder = full
        hab = hby.habByName(holders[1]['alias'])
        wrapper, atc = multisigExn(hab, hab.endorse(child.serder, framed=False, gvrsn=V2,
            nests=[serializeParsedSubstream(node) for node in child.nests]), version=V2)
        fuller = tmp_path / 'group-fuller-same-said.cesr'
        fuller.write_bytes(wrapper.raw + atc)
    finally:
        hby.close()
    rejected = kli(tmp_path, 'ipex', 'present', *holders[0]['args'], *common,
        '--refresh', '--proposal', str(fuller), '--output', str(invalid), succeeds=False)
    assert 'selected admitted-view scope' in rejected and not invalid.exists()
    hby = state(verifier)
    try:
        accepted = hby.db.exns.get((proposed['grant'],))
        tsgs, _ = verify(hby, accepted)
        assert {sig.index for pre, _, _, sigers in tsgs if pre.qb64 == holders[0]['pre']
                for sig in sigers} == {0, 1}
        assert not list(hby.ks.rroots.getTopItemIter())
    finally:
        hby.close()


def test_group_unblind_uses_live_member_thresholds_before_exact_admit(tmp_path, live_parties):
    issuer, holders, body, selected = group_copy(tmp_path, live_parties)
    history_before = [inspect(tmp_path, side, selected['grant']) for side in holders]
    witness = (tmp_path / 'witness.cesr').read_bytes()
    wit = Parser(version=V2).parseOneBare(ims=bytearray(witness), processive=False).serder.pre

    # Form an independent rootless verifier group, with real witnessed member and group KELs.
    with ExitStack() as stack:
        environments = [Habery(name=f'verifier-{uuid4().hex}', base=issuer['base'], bran=PASSCODE,
                               version=V2) for _ in range(2)]
        for hby in environments:
            stack.callback(hby.close)
            config = hby.cf.get()
            config['kram'] = dict(enabled=True, denials=[],
                caches={'~': [1000, 5000, 60000, 300000, 5000, 60000, 300000]})
            hby.cf.put(config)
            Parser(kvy=hby.kvy, rvy=hby.rvy, version=V2).parse(ims=bytearray(witness))
        members = [hby.makeHab(name='member', wits=[wit], toad=1) for hby in environments]
        for hby, member in zip(environments, members):
            witnessed(hby, member)
        for hby in environments:
            for member in members:
                Parser(kvy=hby.kvy, rvy=hby.rvy, version=V2).parse(ims=member.replay(gvrsn=V2))
        groups = [hby.makeGroupHab(group='verifiers', mhab=member, smids=[m.pre for m in members],
            isith='2', nsith='2', wits=[wit], toad=1, version=V2) for hby, member in zip(environments, members)]
        partials = [g.msgOwnInception(allowPartiallySigned=True, framed=False, gvrsn=V2) for g in groups]
        for hby in environments:
            for raw in partials:
                Parser(kvy=hby.kvy, rvy=hby.rvy, version=V2).parse(ims=bytearray(raw), local=True)
            hby.kvy.processEscrows()
        witnessed(environments[0], groups[0])
        Parser(kvy=environments[1].kvy, rvy=environments[1].rvy, version=V2).parse(
            ims=groups[0].replay(gvrsn=V2), local=True)
        public = tmp_path / 'verifier-group-public.cesr'
        public.write_bytes(b''.join(bytes(m.replay(gvrsn=V2)) for m in members) + bytes(groups[0].replay(gvrsn=V2)))
        verifiers = [dict(name=hby.name, base=issuer['base'], alias='verifiers', pre=group.pre,
            member=member.pre, args=['--name', hby.name, '--base', issuer['base'], '--alias', 'verifiers',
                                    '--passcode', PASSCODE, '--version', '2.0'])
                     for hby, group, member in zip(environments, groups, members)]

    # Publish only public dependencies; the new verifiers never receive RegistrySalt or private keys.
    history = tmp_path / 'unblind-public-history.cesr'
    evidence = bytearray()
    for side in (issuer, holders[0]):
        with closing(state(side)) as hby:
            hab = hby.habByName(side['alias'])
            if side is holders[0]:
                for member in hby.db.signingMembers(pre=hab.pre):
                    evidence.extend(b''.join(hby.db.clonePreIter(member, gvrsn=V2)))
            evidence.extend(hab.replay(gvrsn=V2))
            if side is issuer:
                rgy = Regery(hby, name=side['name'], base=side['base'])
                try:
                    for raw in rgy.store.cloneTelIter(body.regid):
                        event = SerderACDC(raw=raw)
                        sn, said = regeventing.vetAnchor(event, db=hby.db, issuer=issuer['pre'])
                        evidence.extend(messagize(event, bonds=[SealSource(s=f'{sn:x}', d=said)], gvrsn=V2))
                finally:
                    rgy.close()
    history.write_bytes(evidence)
    # As in the individual fixture, source KEL is an explicit precondition; TEL advances only via the query.
    later = tmp_path / 'unblind-issued2.cesr'
    event, expected_opening = update(issuer, body, later, value='issued')
    updates = Parser(version=V2).parse(ims=bytearray(later.read_bytes()), processive=False)
    for side in holders:
        intake(side, b''.join(serializeParsedSubstream(child) for child in updates[:-1]))
    proposal = tmp_path / 'unblind-present-proposal.cesr'
    outputs = [tmp_path / f'unblind-present-{i}.cesr' for i in range(2)]
    logs = [tmp_path / f'unblind-live-{i}.log' for i in range(4)]
    processes = []
    def phase(index, name):
        deadline = time.monotonic() + 15
        while f'"phase": "{name}"' not in logs[index].read_text():
            assert processes[index].poll() is None, logs[index].read_text()
            assert time.monotonic() < deadline, logs[index].read_text()
            time.sleep(.03)
    with ExitStack() as stack:
        # Unlock before the original presentation lifetime starts; release before verifier0's CLI owns it.
        signing = state(verifiers[0])
        stack.callback(signing.close)
        def start(command, index):
            log = stack.enter_context(logs[index].open('w'))
            processes.append(subprocess.Popen([shutil.which('kli'), *command], cwd=tmp_path,
                stdout=log, stderr=subprocess.STDOUT))
        try:
            # A provisioned nonlead proposes the presentation; both members explicitly stay for Unblind.
            common = ['--from-grant', selected['grant'], '--recipient', verifiers[0]['pre'],
                '--input', str(public), '--respond-unblind', '--deliver', '--timeout', '40']
            start(['ipex', 'present', *holders[1]['args'], *common,
                   '--proposal-output', str(proposal), '--output', str(outputs[0])], 0)
            phase(0, 'group_proposed')
            start(['ipex', 'present', *holders[0]['args'], *common,
                   '--proposal', str(proposal), '--output', str(outputs[1])], 1)
            deadline = time.monotonic() + 15
            while not all(p.exists() for p in outputs):
                assert all(p.poll() is None for p in processes), '\n'.join(log.read_text() for log in logs[:2])
                assert time.monotonic() < deadline
                time.sleep(.03)
            grant = next(json.loads(line)['grant'] for line in logs[0].read_text().splitlines() if line.startswith('{'))
            # Observe the recorded clock without another CLI startup inside the live exchange.
            with closing(Baser(name=holders[0]['name'], base=holders[0]['base'], readonly=True, reopen=True)) as db:
                original_deadline = exchange_deadline(db, grant)

            # Only the selected nonlead authors a query; its partial alone cannot complete or disclose.
            options = ['--unblind', '--said', grant, '--input', str(history), '--input', str(outputs[1]),
                '--input', str(later), '--unblind-proposer', verifiers[1]['member'], '--deliver', '--timeout', '30']
            start(['ipex', 'admit', *verifiers[1]['args'], *options], 2)
            phase(2, 'group_unblind_proposed')
            with closing(Baser(name=verifiers[1]['name'], base=verifiers[1]['base'], readonly=True, reopen=True)) as db:
                requester_deadline = exchange_deadline(db, grant)
            assert processes[2].poll() is None and '"admitted": true' not in logs[2].read_text()
            assert all('"kind": "rpy"' not in log.read_text() for log in logs[:2])
            # An authenticated non-proposer queues different Admit bytes before the real author is ready.
            hab = signing.habByName('verifiers')
            presented = next(p.serder for p in Parser(version=V2).parse(
                ims=bytearray(outputs[1].read_bytes()), processive=False) if p.serder.route == '/ipex/grant')
            alternate, atc = native_admit(hab, '', presented, gvrsn=V2)
            wrapper, watc = multisigExn(hab, alternate.raw + atc, version=V2)
            poster = StreamPoster(hby=signing, hab=hab.mhab, recp=verifiers[1]['member'],
                                  topic='multisig', version=V2)
            poster.send(wrapper, attachment=watc, gvrsn=V2)
            delivery = doing.DoDoer(doers=poster.deliver())
            doing.Doist(real=True, tock=.03125, limit=3).do(doers=[delivery])
            assert delivery.done
            signing.close()
            deadline = time.monotonic() + 3
            while True:
                db = Baser(name=verifiers[1]['name'], base=issuer['base'], readonly=True, reopen=True)
                try:
                    queued = db.exns.get((wrapper.said,)) is not None
                finally:
                    db.close()
                if queued:
                    break
                assert time.monotonic() < deadline
                time.sleep(.03)
            start(['ipex', 'admit', *verifiers[0]['args'], *options], 3)
            for process in processes:
                process.wait(timeout=45)
            assert all(p.returncode == 0 for p in processes), '\n'.join(log.read_text() for log in logs)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
    results = [last_result(log.read_text()) for log in logs]
    assert all(r['admitted'] and r['grant'] == grant for r in results)
    assert len({r['admit'] for r in results}) == 1
    assert not results[2]['transmitted'] and results[3]['transmitted']
    query_views, reply_views = set(), set()
    for side in verifiers:
        current = inspect(tmp_path, side, grant)
        assert current['deadline'] == toIso8601(requester_deadline)
        assert current['observations'][body.said]['said'] == event.said
        with closing(state(side)) as hby:
            assert not list(hby.ks.rroots.getTopItemIter())
            assert hby.db.exns.get((alternate.said,)) is None
            tsgs, _ = verify(hby, hby.db.exns.get((results[2]['admit'],)))
            assert {sig.index for _, _, _, sigs in tsgs for sig in sigs} == {0, 1}
            for _, packet in hby.db.exns.getTopItemIter():
                if packet.route == '/multisig/qry':
                    child = loadParsedNestedSubstreams(hby, packet.said)[0]
                    assert child.nests[0].serder.raw == event.raw
                    query_views.add((child.serder.raw, bytes(serializeParsedSubstream(child.nests[0]))))
    for side in holders:
        with closing(state(side)) as hby:
            for _, packet in hby.db.exns.getTopItemIter():
                if packet.route != '/multisig/rpy':
                    continue
                child = loadParsedNestedSubstreams(hby, packet.said)[0]
                if child.serder.route == '/ipex/unblind':
                    proofs = tuple(Blinder(data=BlindState(*data), verify=False).qb64b for data in child.bsqs)
                    assert proofs == (expected_opening.qb64b,) and not child.bsss
                    reply_views.add((child.serder.raw, proofs))
    assert len(query_views) == len(reply_views) == 1  # Wrapping never regenerates bodies or evidence.
    assert [inspect(tmp_path, side, selected['grant']) for side in holders] == history_before
    assert inspect(tmp_path, holders[0], grant)['deadline'] == toIso8601(original_deadline)


def test_held_bound_refresh_and_invalid_revoked_refusal(tmp_path, live_parties):
    issuer, holder = live_parties
    selected, body = issue(tmp_path, live_parties)
    original = inspect(tmp_path, holder, selected['grant'])
    later, proof_file = tmp_path / 'bound-history.cesr', tmp_path / 'opening.cesr'
    event, proof = update(issuer, body, later, value='issued', bound=True)
    proof_file.write_bytes(proof.qb64b)
    intake(holder, later.read_bytes())
    # Explicit bound opening refreshes only the new outgoing presentation.
    _, _, accepted = present(tmp_path, holder, issuer, selected['grant'], 'bound',
        '--refresh', '--opening', str(proof_file))
    assert accepted['observations'][body.said]['state'] == 'issued'
    assert inspect(tmp_path, holder, selected['grant']) == original
    # Native Unblind preserves the carried bound proof and discovers revoked state.
    update(issuer, body, later, value='revoked')
    public = Parser(version=V2).parse(ims=bytearray(later.read_bytes()), processive=False)
    intake(holder, b''.join(serializeParsedSubstream(child) for child in public[:-1]))
    _, before, refused = present(tmp_path, holder, issuer, selected['grant'], 'revoked',
        '--refresh', '--opening', str(proof_file), succeeds=False)
    assert refused['accepted'] and refused['observations'][body.said]['state'] == 'revoked'
    assert refused['terminal'] is None and refused['deadline'] == before['deadline']
    proof_file.write_bytes(b'invalid')
    refused = kli(tmp_path, 'ipex', 'present', *holder['args'], '--from-grant', selected['grant'],
        '--recipient', issuer['pre'], '--refresh', '--opening', str(proof_file), '--deliver', succeeds=False)
    assert 'complete CESR state opening' in refused
    assert inspect(tmp_path, holder, selected['grant']) == original
