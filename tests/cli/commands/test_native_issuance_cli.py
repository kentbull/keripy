"""Installed live Grant and Admit with independent stores and a real witness."""
import json
import shutil
import subprocess
import sys
import time
from contextlib import ExitStack
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from uuid import uuid4

import pytest
from hio.base import doing

from keri import Kinds, Vrsn_2_0 as V2
from keri.acdc import Regery
from keri.app import Habery, Receiptor, StreamPoster
from keri.cli.common import setupHby
from keri.core import Parser, SerderACDC, exchange
from keri.cli.common.groupadmitting import ProofRoute
from keri.db import Baser
from keri.app import Keeper
from keri.peer.exchanging import loadParsedNestedSubstreams, serializeParsedSubstream, verify
from keri.kering import KeriError
from keri.help import fromIso8601

from tests.cli.commands.test_native_negotiation_cli import kli


pytestmark = pytest.mark.real_store_roots
PASSCODE = '0123456789abcdefghijk'


def witnessed(hby, hab):
    receipts = Receiptor(hby=hby)
    def receipt(tymth, tock=0.03125, **kwa):
        yield tock
        yield from receipts.receipt(hab.pre, sn=0)
        owner.remove([receipts])
    owner = doing.DoDoer(doers=[receipts, doing.doify(receipt)])
    doing.Doist(real=True, tock=0.03125, limit=10).do(doers=[owner])
    assert owner.done


@pytest.fixture
def live_parties(tmp_path, unused_tcp_port_factory):
    port = unused_tcp_port_factory()
    base = f'live-{uuid4().hex}'
    ready = tmp_path / 'witness.cesr'
    witness = subprocess.Popen([sys.executable, '-c', '''
import sys
from pathlib import Path
from hio.base import doing
from keri import Vrsn_2_0 as V2
from keri.app import Habery, setupWitness
hby = Habery(name='witness', base=sys.argv[1], version=V2)
doers = setupWitness(hby, alias='witness', tcpPort=None, httpPort=int(sys.argv[3]), version=V2)
hab = hby.habByName('witness')
raw = bytes(hab.replay(gvrsn=V2)) + hab.makeLocScheme('http://127.0.0.1:' + sys.argv[3], pvrsn=V2, gvrsn=V2)
Path(sys.argv[2]).write_bytes(raw)
doing.Doist(real=True, tock=0.03125).do(doers=doers)
''', base, str(ready), str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        while not ready.exists():
            assert witness.poll() is None
            assert time.monotonic() < deadline
            time.sleep(0.03)
        sides = []
        witness_raw = ready.read_bytes()
        witness_pre = Parser(version=V2).parseOneBare(ims=bytearray(witness_raw), processive=False).serder.pre
        for alias in ('issuer', 'holder'):
            name = f'{alias}-{uuid4().hex}'
            hby = Habery(name=name, base=base, bran=PASSCODE, version=V2)
            try:
                Parser(kvy=hby.kvy, rvy=hby.rvy, version=V2).parse(ims=bytearray(witness_raw))
                hab = hby.makeHab(name=alias, wits=[witness_pre], toad=1)
                witnessed(hby, hab)
                public = tmp_path / f'{alias}.cesr'
                public.write_bytes(bytes(hab.replay(gvrsn=V2)))
                sides.append(dict(name=name, base=base, alias=alias, pre=hab.pre, public=public,
                    args=['--name', name, '--base', base, '--alias', alias, '--passcode', PASSCODE, '--version', '2.0']))
            finally:
                hby.close()
        yield sides
    finally:
        witness.terminate()
        witness.communicate(timeout=10)


def issue(tmp_path, live_parties, data='{"role":"reader"}', *, admit_options=(), succeeds=True,
          issuer_process=None):
    issuer, holder = live_parties
    kli(tmp_path, 'vc', 'registry', 'incept', *issuer['args'], '--registry-name', 'fresh')
    bodyfile = tmp_path / 'body.cesr'
    kli(tmp_path, 'vc', 'create', *issuer['args'], '--registry-name', 'fresh',
        '--recipient', holder['pre'], '--data', data, '--output', str(bodyfile))
    application = tmp_path / 'apply.cesr'
    # Preserve the Apply opener XID through the entire live issuance.
    body = SerderACDC(raw=bodyfile.read_bytes())
    applied = next(json.loads(line) for line in kli(tmp_path, 'ipex', 'apply', *holder['args'],
        '--recipient', issuer['pre'], '--plan', json.dumps([[[body.schema['$id'], '/', []]]]),
        '--output', str(application)).splitlines() if line.startswith('{'))
    grantfile, issuerlog = tmp_path / 'grant.cesr', tmp_path / 'issuer.log'
    with issuerlog.open('w+') as output:
        process = subprocess.Popen([shutil.which('kli'), 'ipex', 'grant', *issuer['args'],
            '--credential', str(bodyfile), '--recipient', holder['pre'], '--prior', applied['exchange'],
            '--input', str(holder['public']), '--input', str(application),
            '--issue', '--deliver', '--output', str(grantfile), '--timeout', '20'],
            cwd=tmp_path, stdout=output, stderr=subprocess.STDOUT)
        if issuer_process is not None:
            issuer_process.append(process)
        try:
            deadline = time.monotonic() + 10
            while not grantfile.exists():
                output.flush()
                assert process.poll() is None, issuerlog.read_text()
                assert time.monotonic() < deadline, issuerlog.read_text()
                time.sleep(0.03)
            selected = next(json.loads(line) for line in issuerlog.read_text().splitlines() if line.startswith('{'))
            assert selected['xid'] == applied['exchange'] != selected['grant']
            refused = kli(tmp_path, 'ipex', 'admit', *holder['args'], '--said', applied['exchange'],
                '--input', str(issuer['public']), '--input', str(grantfile), '--deliver', succeeds=False)
            assert 'exact pending native Grant' in refused
            holderfile = tmp_path / 'holder-evidence.cesr'
            admitted = kli(tmp_path, 'ipex', 'admit', *holder['args'], '--said', selected['grant'],
                '--output', str(holderfile), '--deliver', '--timeout', '20', *admit_options, succeeds=succeeds)
            if not succeeds:
                return selected, body, admitted
            process.wait(timeout=25)
            assert process.returncode == 0 and 'ERR:' not in issuerlog.read_text(), issuerlog.read_text()
            result = next(json.loads(line) for line in reversed(admitted.splitlines()) if line.startswith('{'))
            assert result['admitted'] and result['registry_issued']
            assert result == next(json.loads(line) for line in reversed(issuerlog.read_text().splitlines())
                                  if line.startswith('{'))
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
    roots = []
    for side in live_parties:
        hby = setupHby(name=side['name'], base=side['base'], bran=PASSCODE, noPrompt=True, version=V2)
        rgy = Regery(hby=hby, name=side['name'], base=side['base'])
        try:
            for said in (selected['grant'], result['admit']):
                message = hby.db.exns.get((said,))
                assert message is not None
                verify(hby, message)
            assert hby.db.exrs.get((selected['grant'], body.said)).state == 'issued'
            assert rgy.store.headEvent(body.regid).ilk == 'bup'
            roots.append(hby.habByName(side['alias']).mgr.getRegistryRoot(side['pre'], body.regid).qb64)
        finally:
            rgy.close()
            hby.close()
    assert roots[0] == roots[1]
    assert roots[0].encode() not in grantfile.read_bytes()
    assert roots[0].encode() not in holderfile.read_bytes()
    evidence = Parser(version=V2).parse(ims=bytearray(holderfile.read_bytes()), processive=False)
    assert [parsed.serder.said for parsed in evidence] == [selected['grant'], result['admit']]
    return selected, body


def test_installed_witnessed_apply_grant_dh_bup_and_selected_admit(tmp_path, live_parties):
    issue(tmp_path, live_parties)


def group_parties(tmp_path, live_parties, data='{"role":"group reader"}'):
    """Build the same independent, encrypted two-member group and fresh witnessed registry."""
    issuer, first = live_parties
    witness_raw = (tmp_path / 'witness.cesr').read_bytes()
    witness_pre = Parser(version=V2).parseOneBare(ims=bytearray(witness_raw), processive=False).serder.pre
    second = dict(name=f'holder-peer-{uuid4().hex}', base=first['base'])
    with ExitStack() as stack:
        left = setupHby(name=first['name'], base=first['base'], bran=PASSCODE, noPrompt=True, version=V2)
        right = Habery(name=second['name'], base=second['base'], bran=PASSCODE, version=V2)
        stack.callback(left.close)
        stack.callback(right.close)
        configured_issuer = setupHby(name=issuer['name'], base=issuer['base'], bran=PASSCODE,
                                     noPrompt=True, version=V2)
        stack.callback(configured_issuer.close)
        # Use the native actors() conversation policy, not Exchanger's short no-KRAM fallback.
        # Provenance: tests/acdc/test_unblind_routes.py; all actors are configured before the first Grant.
        for environment in (configured_issuer, left, right):
            config = environment.cf.get()
            config['kram'] = dict(enabled=True, denials=[],
                caches={'~': [1000, 5000, 60000, 300000, 5000, 60000, 300000]})
            environment.cf.put(config)
        Parser(kvy=right.kvy, rvy=right.rvy, version=V2).parse(ims=bytearray(witness_raw))
        members = [left.habByName(first['alias']), right.makeHab(name='peer', wits=[witness_pre], toad=1)]
        witnessed(right, members[1])
        for hby, other in ((left, members[1]), (right, members[0])):
            Parser(kvy=hby.kvy, rvy=hby.rvy, version=V2).parse(ims=other.replay(gvrsn=V2))
        mids = [member.pre for member in members]
        groups = [hby.makeGroupHab(group='holder-group', mhab=member, smids=mids,
            isith='2', nsith='2', wits=[witness_pre], toad=1, version=V2)
            for hby, member in zip((left, right), members)]
        partials = [group.msgOwnInception(allowPartiallySigned=True, framed=False, gvrsn=V2)
                    for group in groups]
        for hby in (left, right):
            for raw in partials:
                Parser(kvy=hby.kvy, rvy=hby.rvy, version=V2).parse(ims=bytearray(raw), local=True)
            hby.kvy.processEscrows()
        witnessed(left, groups[0])
        Parser(kvy=right.kvy, rvy=right.rvy, version=V2).parse(ims=groups[0].replay(gvrsn=V2), local=True)
        coordinator = groups[0].kever.serder.said
        group_pre = groups[0].pre
        public = tmp_path / 'holder-group.cesr'
        public.write_bytes(b''.join(bytes(member.replay(gvrsn=V2)) for member in members)
                           + bytes(groups[0].replay(gvrsn=V2)))
        holders = []
        for side, member in zip((first, second), members):
            holders.append(dict(name=side['name'], base=side['base'], member=member.pre,
                pre=group_pre, alias='holder-group', args=['--name', side['name'], '--base', side['base'],
                    '--alias', 'holder-group', '--passcode', PASSCODE, '--version', '2.0']))

    kli(tmp_path, 'vc', 'registry', 'incept', *issuer['args'], '--registry-name', 'group-fresh')
    bodyfile, grantfile = tmp_path / 'group-body.cesr', tmp_path / 'group-grant.cesr'
    kli(tmp_path, 'vc', 'create', *issuer['args'], '--registry-name', 'group-fresh',
        '--recipient', group_pre, '--data', data, '--output', str(bodyfile))
    body = SerderACDC(raw=bodyfile.read_bytes())
    return issuer, holders, body, bodyfile, grantfile, public, coordinator


def group_issue(tmp_path, live_parties, data='{"role":"group reader"}'):
    issuer, holders, body, bodyfile, grantfile, public, coordinator = group_parties(tmp_path, live_parties, data)
    group_pre = holders[0]['pre']
    logs = [tmp_path / name for name in ('group-issuer.log', 'group-lead.log', 'group-peer.log')]
    processes = []
    with ExitStack() as stack:
        def start(arguments, log):
            output = stack.enter_context(log.open('w'))
            process = subprocess.Popen([shutil.which('kli'), *arguments], cwd=tmp_path,
                stdout=output, stderr=subprocess.STDOUT)
            processes.append(process)
            return process

        def phase(log, name):
            deadline = time.monotonic() + 12
            while True:
                for line in log.read_text().splitlines():
                    if line.startswith('{') and json.loads(line).get('phase') == name:
                        return json.loads(line)
                assert all(p.poll() is None for p in processes), log.read_text()
                assert time.monotonic() < deadline, log.read_text()
                time.sleep(0.03)

        # Open the sole signing store before the live query; release it before either member command.
        signing = setupHby(name=holders[0]['name'], base=holders[0]['base'], bran=PASSCODE,
                           noPrompt=True, version=V2)
        stack.callback(signing.close)
        try:
            start(['ipex', 'grant', *issuer['args'], '--credential', str(bodyfile), '--recipient', group_pre,
                '--input', str(public), '--issue', '--deliver', '--output', str(grantfile), '--timeout', '35'], logs[0])
            selected = phase(logs[0], 'selected')
            deadline = time.monotonic() + 5
            while True:
                stream = bytearray(grantfile.read_bytes()) if grantfile.exists() else bytearray()
                frames = []
                try:
                    while stream:
                        frames.append(Parser(version=V2).parseOneBare(ims=stream, framed=True, processive=False))
                except KeriError:
                    frames = []
                if frames and frames[-1].serder.said == selected['grant']:
                    break
                assert time.monotonic() < deadline
                time.sleep(0.03)
            common = ['--said', selected['grant'], '--input', str(grantfile), '--deliver', '--timeout', '30']
            # A signed wrong-Grant envelope must not alter the selected pending disclosure or block its completion.
            member = signing.habByName('holder-group').mhab
            wrong = exchange(sender=member.pre, route=ProofRoute,
                attributes=dict(gid=group_pre, grant=body.said), version=V2, gvrsn=V2, kind=Kinds.json)
            raw = member.endorse(wrong, last=False, framed=False, gvrsn=V2,
                nests=[serializeParsedSubstream(frames[-1])])
            poster = StreamPoster(hby=signing, hab=member, recp=holders[1]['member'],
                                  topic='multisig', version=V2)
            poster.send(wrong, attachment=raw[wrong.size:], gvrsn=V2)
            delivery = doing.DoDoer(doers=poster.deliver())
            doing.Doist(real=True, tock=0.03125, limit=5).do(doers=[delivery])
            assert delivery.done
            signing.close()
            # The original short-lag query is live: start members promptly; unrelated refusal startup is separate.
            start(['ipex', 'admit', *holders[0]['args'], *common, '--coordinator', coordinator,
                '--custodian', holders[0]['member'], '--output', str(tmp_path / 'group-lead.cesr')], logs[1])
            phase(logs[1], 'group_dh_proposed')
            # A lone lead proposal cannot retain a root or accept the pending issuer Grant.
            store = Baser(name=holders[0]['name'], base=holders[0]['base'], readonly=True, reopen=True)
            keeper = Keeper(name=holders[0]['name'], base=holders[0]['base'], readonly=True, reopen=True)
            try:
                assert store.exns.get((selected['grant'],)) is None
                assert not list(keeper.rroots.getTopItemIter())
                lead_deadline = store.epsd.get((selected['grant'],)).dts
            finally:
                keeper.close()
                store.close()
            start(['ipex', 'admit', *holders[1]['args'], *common, '--coordinator', coordinator,
                '--custodian', holders[0]['member'], '--output', str(tmp_path / 'group-peer.cesr')], logs[2])
            phase(logs[2], 'selected')
            store = Baser(name=holders[1]['name'], base=holders[1]['base'], readonly=True, reopen=True)
            try:
                original_deadline = store.epsd.get((selected['grant'],)).dts
                cache = store.kramTMSC.get((issuer['pre'], selected['xid'], selected['grant']))
                assert original_deadline == lead_deadline
                assert cache is not None and cache.rdt and cache.xl == 300000
                assert fromIso8601(original_deadline) == fromIso8601(cache.xdt) + timedelta(milliseconds=cache.xl)
            finally:
                store.close()
            for process in processes:
                process.wait(timeout=40)
            assert all(p.returncode == 0 for p in processes), '\n'.join(p.read_text() for p in logs)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
    results = [next(json.loads(line) for line in reversed(log.read_text().splitlines())
                    if line.startswith('{')) for log in logs]
    assert len({result['admit'] for result in results}) == 1
    assert results[1]['transmitted'] and not results[2]['transmitted']
    roots = []
    for side in (issuer, *holders):
        hby = setupHby(name=side['name'], base=side['base'], bran=PASSCODE, noPrompt=True, version=V2)
        try:
            hab = hby.habByName(side['alias'])
            root = hab.mgr.getRegistryRoot(hab.pre, body.regid)
            roots.append(root.qb64 if root else None)
            for said in (selected['grant'], results[0]['admit']):
                accepted = hby.db.exns.get((said,))
                assert accepted is not None
                if said == selected['grant']:
                    assert accepted.raw == frames[-1].serder.raw
                tsgs, _ = verify(hby, accepted)
                if accepted.route == '/ipex/admit':
                    assert {sig.index for pre, _, _, sigers in tsgs if pre.qb64 == group_pre
                            for sig in sigers} == {0, 1}
            assert hby.db.exrs.get((selected['grant'], body.said)).state == 'issued'
            if side is holders[1]:
                assert hby.db.epsd.get((selected['grant'],)).dts == original_deadline
                assert hby.db.exns.get((wrong.said,)) is None
                assert hby.db.kramMSGC.get((holders[0]['member'], wrong.said)) is not None
        finally:
            hby.close()
    assert roots[0] == roots[1] and roots[0] is not None and roots[2] is None
    assert all(roots[0].encode() not in file.read_bytes() for file in
               (grantfile, tmp_path / 'group-lead.cesr', tmp_path / 'group-peer.cesr'))
    return issuer, holders, body, selected


def test_installed_group_holder_contributes_to_live_dh_and_one_exact_admit(tmp_path, live_parties):
    group_issue(tmp_path, live_parties)


def issuer_group(tmp_path, live_parties):
    from tests.cli.commands.vc.test_native_registry_cli import group_registry
    issuers, holder, coordinator = group_registry(tmp_path, live_parties)
    lead, _ = issuers
    # Conversation policy is configured before the first native Grant, separately from PSE consent.
    for side in (*issuers, holder):
        hby = setupHby(name=side['name'], base=side['base'], bran=PASSCODE, noPrompt=True, version=V2)
        try:
            config = hby.cf.get()
            config['kram'] = dict(enabled=True, denials=[],
                caches={'~': [1000, 60000, 60000, 300000, 60000, 60000, 300000]})
            hby.cf.put(config)
        finally:
            hby.close()
    bodyfile = tmp_path / 'issuer-body.cesr'
    kli(tmp_path, 'vc', 'create', *lead['args'], '--registry-name', 'issuer-fresh',
        '--recipient', holder['pre'], '--data', '{"role":"group issuer"}', '--output', str(bodyfile))
    return issuers, holder, coordinator, bodyfile


def test_installed_group_issuer_exact_grant_query_and_bup_join(tmp_path, live_parties):
    issuers, holder, coordinator, bodyfile = issuer_group(tmp_path, live_parties)
    lead, peer = issuers
    body = SerderACDC(raw=bodyfile.read_bytes())
    proposal, grantfile = tmp_path / 'issuer-proposal.cesr', tmp_path / 'issuer-grant.cesr'
    logs = [tmp_path / name for name in ('issuer-lead.log', 'issuer-peer.log', 'individual-holder.log')]
    common = ['--credential', str(bodyfile), '--recipient', holder['pre'], '--issue', '--deliver',
        '--coordinator', coordinator, '--custodian', lead['member'], '--consent-lifetime', '70', '--timeout', '65']
    processes = []
    with ExitStack() as stack:
        def start(arguments, log):
            output = stack.enter_context(log.open('w'))
            process = subprocess.Popen([shutil.which('kli'), *arguments], cwd=tmp_path,
                stdout=output, stderr=subprocess.STDOUT)
            processes.append(process)
            return process

        def phase(log, name):
            deadline = time.monotonic() + 15
            while True:
                for line in log.read_text().splitlines():
                    if line.startswith('{') and json.loads(line).get('phase') == name:
                        return json.loads(line)
                assert all(p.poll() in (None, 0) for p in processes), '\n'.join(path.read_text() for path in logs if path.exists())
                assert time.monotonic() < deadline, log.read_text()
                time.sleep(0.03)

        try:
            # The first partial Grant survives ten seconds only by the original explicit consent policy.
            start(['ipex', 'grant', *lead['args'], *common, '--input', str(holder['public']),
                '--proposal-output', str(proposal), '--output', str(grantfile)], logs[0])
            selected = phase(logs[0], 'group_proposed')
            store = Baser(name=lead['name'], base=lead['base'], readonly=True, reopen=True)
            try:
                original = store.epsd.get((selected['grant'],)).dts
            finally:
                store.close()
            time.sleep(10.2)
            store = Baser(name=lead['name'], base=lead['base'], readonly=True, reopen=True)
            keeper = Keeper(name=lead['name'], base=lead['base'], readonly=True, reopen=True)
            try:
                assert store.exns.get((selected['grant'],)) is None and store.erpy.get((selected['grant'],)) is None
                assert store.epsd.get((selected['grant'],)).dts == original
                assert not list(keeper.rroots.getTopItemIter())
            finally:
                keeper.close()
                store.close()
            # Fresh explicit peer consent signs this packet and the authenticated custodian query, then exits.
            contributor = start(['ipex', 'grant', *peer['args'], *common, '--proposal', str(proposal),
                '--input', str(holder['public'])], logs[1])
            contributor.wait(timeout=20)
            assert contributor.returncode == 0 and '"phase": "contributed"' in logs[1].read_text(), logs[1].read_text()
            store = Baser(name=peer['name'], base=peer['base'], readonly=True, reopen=True)
            keeper = Keeper(name=peer['name'], base=peer['base'], readonly=True, reopen=True)
            try:
                assert not list(keeper.rroots.getTopItemIter())
                assert store.exns.get((selected['grant'],)) is None
            finally:
                keeper.close()
                store.close()
            start(['ipex', 'admit', *holder['args'], '--said', selected['grant'],
                '--input', str(lead['public']), '--input', str(grantfile), '--deliver', '--timeout', '35'], logs[2])
            # DH roots alone do not authorize an accepted BUP or Admit without the second anchor signature.
            bup = phase(logs[0], 'group_bup_proposed')
            hby = setupHby(name=peer['name'], base=peer['base'], bran=PASSCODE, noPrompt=True, version=V2)
            rgy = Regery(hby, name=peer['name'], base=peer['base'])
            try:
                assert body.regid not in rgy.regs
                assert rgy.store.headEvent(body.regid).ilk == 'rip'
            finally:
                rgy.close()
                hby.close()
            store = Baser(name=lead['name'], base=lead['base'], readonly=True, reopen=True)
            try:
                assert store.erpy.get((selected['grant'],)) is None
                assert store.kels.getLast(keys=lead['pre'], on=2) != bup['anchor']
                assert store.epsd.get((selected['grant'],)).dts == original
            finally:
                store.close()
            joined = subprocess.run([shutil.which('kli'), 'multisig', 'join', '--name', peer['name'],
                '--base', peer['base'], '--passcode', PASSCODE, '--version', '2.0'],
                input='\n', text=True, capture_output=True, cwd=tmp_path, timeout=25)
            assert joined.returncode == 0 and 'Approve exact BUP anchor' in joined.stdout, joined.stdout + joined.stderr
            for process in processes:
                process.wait(timeout=25)
            assert all(p.returncode == 0 for p in processes), '\n'.join(path.read_text() for path in logs)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
    result = next(json.loads(line) for line in reversed(logs[0].read_text().splitlines()) if line.startswith('{'))
    assert result['admitted'] and result['registry_issued']
    assert result == next(json.loads(line) for line in reversed(logs[2].read_text().splitlines()) if line.startswith('{'))
    roots, queries = [], []
    for side in (*issuers, holder):
        hby = setupHby(name=side['name'], base=side['base'], bran=PASSCODE, noPrompt=True, version=V2)
        rgy = Regery(hby, name=side['name'], base=side['base'])
        try:
            hab = hby.habByName(side['alias'])
            root = hab.mgr.getRegistryRoot(hab.pre, body.regid)
            roots.append(root.qb64 if root else None)
            assert rgy.store.headEvent(body.regid).said == bup['bup']
            if side is not peer:
                grant = hby.db.exns.get((selected['grant'],))
                assert grant is not None
                tsgs, _ = verify(hby, grant)
                assert {sig.index for pre, _, _, sigers in tsgs if pre.qb64 == lead['pre'] for sig in sigers} == {0, 1}
                response = hby.db.exns.get((result['admit'],))
                verify(hby, response)
                assert response.pre == holder['pre'] and response.sad['p'] == selected['grant']
                assert hby.db.exrs.get((selected['grant'], body.said)).state == 'issued'
            else:
                assert hby.db.exns.get((selected['grant'],)) is None
                assert not list(hby.ks.rroots.getTopItemIter())
            for _, packet in hby.db.exns.getTopItemIter():
                if packet.route == '/multisig/qry':
                    child = loadParsedNestedSubstreams(hby, packet.said)[0]
                    queries.append((child.serder.raw, {sig.index for pre, sigers in child.lsgs
                                                       if pre.qb64 == lead['pre'] for sig in sigers}))
        finally:
            rgy.close()
            hby.close()
    assert roots[0] == roots[2] and roots[0] is not None and roots[1] is None
    assert len(queries) == 2 and len({raw for raw, _ in queries}) == 1
    assert set.union(*(indices for _, indices in queries)) == {0, 1}
    assert all(roots[0].encode() not in path.read_bytes() for path in (proposal, grantfile))


def test_group_issuer_expired_consent_cannot_be_renewed(tmp_path, live_parties):
    issuers, holder, coordinator, bodyfile = issuer_group(tmp_path, live_parties)
    lead, _ = issuers
    proposal = tmp_path / 'expired-proposal.cesr'
    arguments = ['ipex', 'grant', *lead['args'], '--credential', str(bodyfile), '--recipient', holder['pre'],
        '--input', str(holder['public']), '--issue', '--deliver', '--coordinator', coordinator,
        '--custodian', lead['member']]
    output = kli(tmp_path, *arguments, '--proposal-output', str(proposal), '--consent-lifetime', '1',
                 '--timeout', '5', succeeds=False)
    assert 'original native deadline' in output
    selected = next(json.loads(line) for line in output.splitlines() if line.startswith('{'))
    store = Baser(name=lead['name'], base=lead['base'], readonly=True, reopen=True)
    try:
        original = store.epsd.get((selected['grant'],)).dts
    finally:
        store.close()
    output = kli(tmp_path, *arguments, '--proposal', str(proposal), '--consent-lifetime', '300',
                 '--timeout', '5', succeeds=False)
    assert 'original native deadline' in output
    store = Baser(name=lead['name'], base=lead['base'], readonly=True, reopen=True)
    keeper = Keeper(name=lead['name'], base=lead['base'], readonly=True, reopen=True)
    try:
        assert store.epsd.get((selected['grant'],)).dts == original
        assert store.exns.get((selected['grant'],)) is None and store.erpy.get((selected['grant'],)) is None
        assert not list(keeper.rroots.getTopItemIter())
    finally:
        keeper.close()
        store.close()


def test_group_custodian_refusal_and_finite_timeout_leave_exact_pending_grant(tmp_path, live_parties):
    """Cancellation preserves pending evidence, without claiming recovery of an aged DH query."""
    issuer, holders, body, bodyfile, grantfile, public, coordinator = group_parties(tmp_path, live_parties)
    issuerlog = tmp_path / 'group-negative-issuer.log'
    with issuerlog.open('w') as output:
        process = subprocess.Popen([shutil.which('kli'), 'ipex', 'grant', *issuer['args'],
            '--credential', str(bodyfile), '--recipient', holders[0]['pre'], '--input', str(public),
            '--issue', '--deliver', '--output', str(grantfile), '--timeout', '35'],
            cwd=tmp_path, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while True:
                selections = [json.loads(line) for line in issuerlog.read_text().splitlines() if line.startswith('{')]
                frames, stream = [], bytearray(grantfile.read_bytes()) if grantfile.exists() else bytearray()
                try:
                    while stream:
                        frames.append(Parser(version=V2).parseOneBare(ims=stream, framed=True, processive=False))
                except KeriError:
                    frames = []
                if selections and frames and frames[-1].serder.said == selections[0]['grant']:
                    selected = selections[0]
                    break
                assert process.poll() is None, issuerlog.read_text()
                assert time.monotonic() < deadline, issuerlog.read_text()
                time.sleep(.03)
            common = ['--said', selected['grant'], '--input', str(grantfile), '--deliver', '--timeout', '30']
            # These independent-store failures consume startup time, not the success flow's live query window.
            with ThreadPoolExecutor(max_workers=2) as pool:
                refused = pool.submit(kli, tmp_path, 'ipex', 'admit', *holders[0]['args'], *common,
                    '--coordinator', coordinator, '--custodian', holders[1]['member'], succeeds=False)
                timedout = pool.submit(kli, tmp_path, 'ipex', 'admit', *holders[1]['args'], '--said', selected['grant'],
                    '--input', str(grantfile), '--deliver', '--timeout', '0.2', '--coordinator', coordinator,
                    '--custodian', holders[0]['member'], succeeds=False)
                refused, timedout = refused.result(), timedout.result()
            assert 'custodian' in refused
            assert 'before --timeout' in timedout and '"admitted": true' not in timedout
            for side in holders:
                store = Baser(name=side['name'], base=side['base'], readonly=True, reopen=True)
                keeper = Keeper(name=side['name'], base=side['base'], readonly=True, reopen=True)
                try:
                    assert store.exns.get((selected['grant'],)) is None
                    assert not list(keeper.rroots.getTopItemIter())
                    assert store.epse.get((selected['grant'],)).raw == frames[-1].serder.raw
                    original_deadline = store.epsd.get((selected['grant'],)).dts
                    cache = store.kramTMSC.get((issuer['pre'], selected['xid'], selected['grant']))
                    assert cache is not None and cache.rdt and cache.xl == 300000
                    assert fromIso8601(original_deadline) == fromIso8601(cache.xdt) + timedelta(milliseconds=cache.xl)
                    store.close()
                    store.reopen(readonly=True)
                    assert store.epsd.get((selected['grant'],)).dts == original_deadline
                    assert store.epse.get((selected['grant'],)).raw == frames[-1].serder.raw
                finally:
                    keeper.close()
                    store.close()
            assert process.poll() is None and '"admitted": true' not in issuerlog.read_text()
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
    # Stopping this failed attempt neither issues the RIP nor persists ephemeral restart keys.
    hby = setupHby(name=issuer['name'], base=issuer['base'], bran=PASSCODE, noPrompt=True, version=V2)
    rgy = Regery(hby=hby, name=issuer['name'], base=issuer['base'])
    try:
        assert rgy.store.headEvent(body.regid).ilk == 'rip'
        assert hby.db.exns.get((selected['grant'],)) is None
        assert not list(hby.ks.rroots.getTopItemIter())
    finally:
        rgy.close()
        hby.close()


def test_finite_grant_timeout_keeps_registry_unissued_and_has_no_restart_keys(tmp_path, live_parties):
    issuer, holder = live_parties
    kli(tmp_path, 'vc', 'registry', 'incept', *issuer['args'], '--registry-name', 'fresh')
    bodyfile, grantfile = tmp_path / 'body.cesr', tmp_path / 'pending.cesr'
    kli(tmp_path, 'vc', 'create', *issuer['args'], '--registry-name', 'fresh',
        '--recipient', holder['pre'], '--data', '{"role":"reader"}', '--output', str(bodyfile))
    arguments = ['ipex', 'grant', *issuer['args'], '--credential', str(bodyfile),
        '--recipient', holder['pre'], '--input', str(holder['public']), '--deliver', '--output', str(grantfile)]
    assert 'requires --credential and --issue' in kli(tmp_path, *arguments, succeeds=False)
    assert not grantfile.exists()
    output = kli(tmp_path, *arguments, '--issue', '--timeout', '0.4', succeeds=False)
    assert 'before --timeout' in output
    selected = next(json.loads(line) for line in output.splitlines() if line.startswith('{'))
    hby = setupHby(name=issuer['name'], base=issuer['base'], bran=PASSCODE, noPrompt=True, version=V2)
    rgy = Regery(hby=hby, name=issuer['name'], base=issuer['base'])
    try:
        body = SerderACDC(raw=bodyfile.read_bytes())
        assert rgy.store.headEvent(body.regid).ilk == 'rip'
        assert hby.db.epse.get((selected['grant'],)) is not None
        assert hby.db.exns.get((selected['grant'],)) is None
        assert hby.habByName('issuer').mgr.getRegistryRoot(issuer['pre'], body.regid) is None
        assert list(hby.ks.rroots.getTopItemIter()) == []
    finally:
        rgy.close()
        hby.close()
    before = grantfile.read_bytes()
    assert 'output already exists' in kli(tmp_path, *arguments, '--issue', succeeds=False)
    assert grantfile.read_bytes() == before
