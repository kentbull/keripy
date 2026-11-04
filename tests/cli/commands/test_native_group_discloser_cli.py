"""Installed group discloser keeps issuer consent, member thresholds and old views distinct."""
from contextlib import ExitStack, closing
from hashlib import sha256
import json
import shutil
import subprocess
import time
from uuid import uuid4

import pytest
from hio.base import doing

from keri import Kinds, Vrsn_2_0 as V2
from keri.acdc import Regery
from keri.acdc.ipexing import loadHandlers
from keri.app import Habery, MailboxDirector, Notifier
from keri.core import BlindState, Blinder, Diger, Kevery, Kramer, Parser
from keri.db import Baser, fetchTsgs
from keri.help import fromIso8601, nowUTC
from keri.peer.exchanging import loadParsedNestedSubstreams, serializeParsedSubstream, verify
from keri.peer import Exchanger
from tests.cli.commands.test_native_issuance_cli import PASSCODE, holder_group, issue, live_parties, witnessed
from tests.cli.commands.test_native_negotiation_cli import kli
from tests.cli.commands.test_native_presentation_cli import intake, inspect, state, update
from tests.cli.commands.test_native_registry_root_cli import last_result

pytestmark = pytest.mark.real_store_roots


def root_fingerprint(side, registry):
    with closing(state(side)) as hby:
        root = hby.habByName(side['alias']).mgr.getRegistryRoot(side['pre'], registry)
        return sha256(root.qb64b).hexdigest() if root else None


def receive_grant(side, sender, said):
    """Poll the real witness using native IPEX/KRAM; import no Grant file."""
    with closing(state(side)) as hby:
        rgy, notifier = Regery(hby, name=side['name'], base=side['base']), Notifier(hby)
        try:
            exc = Exchanger(hby, handlers=[])
            loadHandlers(hby, exc, notifier, rgy=rgy)
            kvy = Kevery(db=hby.db, rvy=hby.rvy, exc=exc, local=False, direct=False, lax=True,
                         kramer=Kramer(db=hby.db, cf=hby.cf))
            mbx = MailboxDirector(hby=hby, topics=['/credential', '/receipt', '/replay'],
                kvy=kvy, exc=exc, rvy=hby.rvy, rgy=rgy, version=V2, gvrsn=V2, kind=Kinds.json)
            def wait(tymth, tock=.03125, **kwa):
                yield tock
                while exc.presentationContext(said, xid=said, sender=sender, recipient=side['pre']) is None:
                    yield tock
                owner.remove([mbx])
            owner = doing.DoDoer(doers=[mbx, doing.doify(wait)])
            doing.Doist(real=True, tock=.03125, limit=5).do(doers=[owner])
            assert owner.done, 'exact authenticated pending Grant never arrived through the witness mailbox'
        finally:
            notifier.noter.close()
            rgy.close()


def test_separate_group_discloser_resumes_only_issuer_endorsed_exact_preparation(tmp_path, live_parties):
    issuer, holder = live_parties
    issued, body = issue(tmp_path, live_parties,
        data='{"d":"","shown":{"d":"","name":"Ada"},"secret":{"d":"","name":"hidden"}}')
    witness = (tmp_path / 'witness.cesr').read_bytes()
    wit = Parser(version=V2).parseOneBare(ims=bytearray(witness), processive=False).serder.pre
    extra = []
    # Independent encrypted stores and the existing real witnessed 2-of-2 group owner.
    for alias in ('discloser-member', 'verifier'):
        with closing(Habery(name=f'{alias}-{uuid4().hex}', base=issuer['base'], bran=PASSCODE, version=V2)) as hby:
            Parser(kvy=hby.kvy, rvy=hby.rvy, version=V2).parse(ims=bytearray(witness))
            hab = hby.makeHab(name=alias, wits=[wit], toad=1)
            witnessed(hby, hab)
            public = tmp_path / f'{alias}.cesr'
            public.write_bytes(bytes(hab.replay(gvrsn=V2)))
            extra.append(dict(name=hby.name, base=issuer['base'], alias=alias, pre=hab.pre, public=public,
                args=['--name', hby.name, '--base', issuer['base'], '--alias', alias,
                      '--passcode', PASSCODE, '--version', '2.0']))
    member, verifier = extra
    _, members, public, _ = holder_group(tmp_path, (issuer, member))
    for side in (issuer, holder, *members, verifier):
        with closing(state(side)) as hby:
            config = hby.cf.get()
            config['kram'] = dict(enabled=True, denials=[],
                caches={'~': [1000, 5000, 60000, 300000, 5000, 60000, 300000]})
            hby.cf.put(config)
        intake(side, public.read_bytes() + verifier['public'].read_bytes())
    for side in (*members, verifier):
        intake(side, (tmp_path / 'grant.cesr').read_bytes())

    processes, logs = [], []
    with ExitStack() as stack:
        def start(side, verb, *args, label):
            log = tmp_path / f'{label}.log'
            output = stack.enter_context(log.open('w'))
            processes.append(subprocess.Popen([shutil.which('kli'), 'ipex', verb, *side['args'], *args],
                cwd=tmp_path, stdout=output, stderr=subprocess.STDOUT))
            logs.append(log)
            return log

        def phase(log, name):
            deadline = time.monotonic() + 12
            while True:
                for line in log.read_text().splitlines():
                    if line.startswith('{') and json.loads(line).get('phase') == name:
                        return json.loads(line)
                assert processes[logs.index(log)].poll() is None, log.read_text()
                assert time.monotonic() < deadline, log.read_text()
                time.sleep(.03)

        def finish():
            for process, log in zip(processes, logs):
                process.wait(timeout=40)
                assert process.returncode == 0, log.read_text()

        try:
            # A real holder hop is admitted by the discloser group before any root or new preparation exists.
            forwarded = tmp_path / 'discloser-held.cesr'
            log = start(holder, 'present', '--from-grant', issued['grant'], '--recipient', members[0]['pre'],
                '--disclose', 'a/shown/', '--respond-unblind', '--deliver', '--output', str(forwarded),
                '--timeout', '30', label='forward')
            selected = phase(log, 'selected')
            deadline = time.monotonic() + 5
            while not forwarded.exists():
                assert time.monotonic() < deadline
                time.sleep(.03)
            for index, side in enumerate(members):
                start(side, 'admit', '--unblind', '--said', selected['grant'], '--input', str(forwarded),
                    '--unblind-proposer', members[0]['member'], '--deliver', '--timeout', '25', label=f'held-{index}')
            finish()
            old = [inspect(tmp_path, side, selected['grant']) for side in members]
            holder_before = inspect(tmp_path, holder, issued['grant'])
            assert old[0]['accepted'] and old[0]['terminal'] and old[0] == old[1]
            assert isinstance(old[0]['disclosure'][0]['body']['a']['secret'], str)
            private_keys = []
            for side in members:
                with closing(state(side)) as hby:
                    private_keys.append(sha256(b''.join(bytes(key) + bytes(value)
                        for key, value in hby.ks.env.begin().cursor(hby.ks.pris.sdb))).hexdigest())

            # Explicit issuer-authorized ciphertext to the nonlead; the other member never receives a root.
            root_member = members[1]
            with closing(state(root_member)) as hby:
                rgy = Regery(hby, name=root_member['name'], base=root_member['base'])
                try:
                    event1 = rgy.store.headEvent(body.regid)
                    held = tmp_path / 'held-opening.cesr'
                    held.write_bytes(Blinder(data=BlindState(*loadParsedNestedSubstreams(hby, selected['grant'])[0].bsqs[0])).qb64b)
                finally:
                    rgy.close()
            copied = tmp_path / 'encrypted-group-root.cesr'
            kli(tmp_path, 'vc', 'registry', 'provision', *issuer['args'], '--registry', body.regid,
                '--recipient', root_member['pre'], '--target', root_member['member'], '--output', str(copied))
            assert root_fingerprint(root_member, body.regid) is None
            received = last_result(kli(tmp_path, 'vc', 'registry', 'receive', *root_member['args'],
                '--registry', body.regid, '--sender', issuer['pre'], '--event', event1.said,
                '--opening', str(held), '--message', str(copied)))
            assert received['received']
            expected_root = root_fingerprint(issuer, body.regid)
            assert root_fingerprint(root_member, body.regid) == expected_root
            later = tmp_path / 'public-bup2.cesr'
            event2, expected_opening = update(issuer, body, later, value='issued')
            for side in (*members, verifier):
                intake(side, later.read_bytes())
            common = ['--from-grant', selected['grant'], '--recipient', verifier['pre']]
            prepared = [tmp_path / f'prepared-{i}.cesr' for i in range(2)]
            proposal = tmp_path / 'exact-proposal.cesr'
            refused = kli(tmp_path, 'ipex', 'present', *root_member['args'], *common, '--prepare',
                '--deliver', '--output', str(prepared[1]), succeeds=False)
            assert 'without --deliver' in refused and not prepared[1].exists()
            refused = kli(tmp_path, 'ipex', 'present', *holder['args'], '--from-grant', issued['grant'],
                '--recipient', verifier['pre'], '--prepare', '--send-proposal', '--output', str(prepared[0]), succeeds=False)
            assert 'require group --prepare' in refused

            # First partial freezes explicit original consent; one signature cannot export a prepared Grant.
            preparation = [*common, '--prepare', '--send-proposal', '--consent-lifetime', '60', '--timeout', '40']
            log = start(root_member, 'present', *preparation, '--proposal-output', str(proposal),
                '--output', str(prepared[1]), label='prepare-nonlead')
            proposed = phase(log, 'group_proposed')
            grant = proposed['grant']
            assert not proposed['locally_accepted'] and not prepared[1].exists()
            with closing(Baser(name=root_member['name'], base=root_member['base'], readonly=True, reopen=True)) as db:
                assert db.exns.get((grant,)) is None and db.erpy.get((grant,)) is None
                first_deadline = db.epsd.get((grant,)).dts
                assert 10 < (fromIso8601(first_deadline) - nowUTC()).total_seconds() <= 60
            start(members[0], 'present', *preparation, '--proposal', str(proposal),
                '--output', str(prepared[0]), label='prepare-lead')
            finish()
            preparations = [inspect(tmp_path, side, grant) for side in members]
            assert all(not saved['accepted'] and saved['terminal'] is None for saved in preparations)
            assert preparations[1]['deadline'] == first_deadline
            original = Parser(version=V2).parseOneBare(ims=bytearray(prepared[1].read_bytes()), processive=False)
            assert prepared[0].read_bytes() == prepared[1].read_bytes()
            assert {sig.index for pre, _, _, sigs in original.tsgs if pre.qb64 == root_member['pre']
                    for sig in sigs} == {0, 1}
            resume = [*common, '--resume', grant, '--unblind-proposer', root_member['member'],
                      '--respond-unblind', '--deliver', '--timeout', '30']
            refused = kli(tmp_path, 'ipex', 'present', *root_member['args'], *resume,
                '--input', str(prepared[1]), succeeds=False)
            assert 'issuer endorsement' in refused
            with closing(Baser(name=verifier['name'], base=verifier['base'], readonly=True, reopen=True)) as db:
                assert db.exns.get((grant,)) is None and db.epse.get((grant,)) is None
            endorsed = tmp_path / 'issuer-endorsed.cesr'
            result = last_result(kli(tmp_path, 'ipex', 'endorse', *issuer['args'], '--said', grant,
                '--grant', str(prepared[1]), '--sender', root_member['pre'], '--recipient', verifier['pre'],
                '--output', str(endorsed)))
            assert result['endorsed'] and not result['transmitted']
            authorized = Parser(version=V2).parseOneBare(ims=bytearray(endorsed.read_bytes()), processive=False)
            assert authorized.serder.raw == original.serder.raw
            assert [serializeParsedSubstream(node) for node in authorized.nests] == [serializeParsedSubstream(node) for node in original.nests]

            # The root-bearing nonlead can derive a reply, but cannot satisfy the ordinary reply threshold alone.
            outputs = [tmp_path / f'resumed-{i}.cesr' for i in range(2)]
            log = start(root_member, 'present', *resume, '--input', str(endorsed),
                '--output', str(outputs[1]), label='resume-nonlead')
            assert not phase(log, 'group_resumed')['transmitted']
            delivery_log = start(members[0], 'present', *resume, '--input', str(endorsed),
                '--output', str(outputs[0]), '--timeout', '3', label='deliver-lead')
            delivery = phase(delivery_log, 'group_resumed')
            # The finite sender exits before the query; its later reply approval remains genuinely withheld.
            sender_process = processes.pop()
            logs.pop()
            sender_process.wait(timeout=6)
            assert sender_process.returncode != 0 and 'before --timeout' in delivery_log.read_text()
            receive_grant(verifier, root_member['pre'], grant)
            assert delivery['transmitted']
            with closing(state(members[0])) as hby:
                rgy = Regery(hby, name=members[0]['name'], base=members[0]['base'])
                try:
                    exc = Exchanger(hby, handlers=[])
                    loadHandlers(hby, exc, None, rgy=rgy)
                    hab = hby.habByName(members[0]['alias'])
                    deadline = hby.db.epsd.get((grant,)).dts
                    assert not exc.lead(hab, grant)
                    assert exc.lead(hab, grant, pendingPresentation=True)
                    assert hby.db.exns.get((grant,)) is None and hby.db.epsd.get((grant,)).dts == deadline
                finally:
                    rgy.close()
            verify_log = start(verifier, 'admit', '--unblind', '--said', grant,
                '--deliver', '--timeout', '25', label='rootless-verifier')
            assert phase(log, 'group_unblind_proposed')['kind'] == 'rpy'
            assert '"admitted": true' not in verify_log.read_text()
            with closing(Baser(name=root_member['name'], base=root_member['base'], readonly=True, reopen=True)) as db:
                assert db.exns.get((grant,)) is None and db.erpy.get((grant,)) is None
            start(members[0], 'present', *resume, '--input', str(endorsed),
                '--output', str(tmp_path / 'resumed-lead-retry.cesr'), label='resume-lead')
            finish()
            result = last_result(verify_log.read_text())
            assert result['admitted'] and result['grant'] == grant
            assert not last_result(log.read_text())['transmitted'] and last_result(logs[-1].read_text())['transmitted']
            verified = inspect(tmp_path, verifier, grant)
            assert verified['accepted'] and verified['terminal'] == result['admit']
            assert verified['observations'][body.said]['said'] == event2.said
            assert verified['observations'][body.said]['state'] == 'issued'
            assert verified['disclosure'][0]['raw_b64'] == old[0]['disclosure'][0]['raw_b64']
            replies = set()
            for index, side in enumerate(members):
                current = inspect(tmp_path, side, grant)
                assert current['deadline'] == preparations[index]['deadline']
                assert current['grant'] == preparations[index]['grant'] and current['terminal'] == result['admit']
                assert current['observations'][body.said]['said'] == event2.said
                assert inspect(tmp_path, side, selected['grant']) == old[index]
                with closing(state(side)) as hby:
                    verify(hby, hby.db.exns.get((grant,)))
                    assert sha256(b''.join(bytes(key) + bytes(value) for key, value in
                        hby.ks.env.begin().cursor(hby.ks.pris.sdb))).hexdigest() == private_keys[index]
                    for _, packet in hby.db.exns.getTopItemIter():
                        if packet.route == '/multisig/rpy':
                            child = loadParsedNestedSubstreams(hby, packet.said)[0]
                            if child.serder.route == '/ipex/unblind':
                                assert child.serder.sad['a']['re'] == {body.regid: [event2.said]}
                                assert not child.nests and not child.bsss
                                proofs = tuple(Blinder(data=BlindState(*data)).qb64b for data in child.bsqs)
                                assert proofs == (expected_opening.qb64b,)
                                groups = fetchTsgs(db=hby.db.tsgs, diger=Diger(qb64=child.serder.said))
                                assert {sig.index for pre, _, _, sigs in groups if pre.qb64 == side['pre']
                                        for sig in sigs} == {0, 1}
                                replies.add((child.serder.raw, proofs))
            assert len(replies) == 1
            assert inspect(tmp_path, holder, issued['grant']) == holder_before
            assert root_fingerprint(root_member, body.regid) == expected_root
            assert all(root_fingerprint(side, body.regid) is None for side in (members[0], verifier))
            with closing(state(issuer)) as hby:
                root = hby.habByName(issuer['alias']).mgr.getRegistryRoot(issuer['pre'], body.regid)
                leaked = any(root.qb64b in path.read_bytes() for path in tmp_path.glob('*.cesr'))
            assert not leaked

            # A later invocation cannot renew a different preparation's expired original partial lifetime.
            expired, unavailable = tmp_path / 'expired-proposal.cesr', tmp_path / 'expired-prepared.cesr'
            refused = kli(tmp_path, 'ipex', 'present', *root_member['args'], *common, '--prepare',
                '--send-proposal', '--consent-lifetime', '2', '--proposal-output', str(expired),
                '--output', str(unavailable), '--timeout', '5', succeeds=False)
            assert 'original native Grant deadline' in refused and not unavailable.exists()
            dead_grant = Parser(version=V2).parseOneBare(ims=bytearray(expired.read_bytes()), processive=False).nests[0].serder.said
            with closing(Baser(name=root_member['name'], base=root_member['base'], readonly=True, reopen=True)) as db:
                saved = db.epsd.get((dead_grant,)).dts
            refused = kli(tmp_path, 'ipex', 'present', *root_member['args'], *common, '--prepare',
                '--send-proposal', '--consent-lifetime', '60', '--proposal', str(expired),
                '--output', str(unavailable), succeeds=False)
            assert 'original native Grant deadline' in refused and not unavailable.exists()
            with closing(Baser(name=root_member['name'], base=root_member['base'], readonly=True, reopen=True)) as db:
                assert db.epsd.get((dead_grant,)).dts == saved
                assert db.exns.get((dead_grant,)) is None and db.erpy.get((dead_grant,)) is None
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
