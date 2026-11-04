"""Installed bilateral issuance with two independently encrypted 2-of-2 groups."""
import json
import shutil
import subprocess
import time
from contextlib import ExitStack

import pytest

from keri import Vrsn_2_0 as V2
from keri.acdc import RegBaser, Regery, RegistryStore, regeventing
from keri.app import Keeper
from keri.cli.common import setupHby
from keri.core import SerderACDC
from keri.db import Baser
from keri.peer.exchanging import loadParsedNestedSubstreams, verify
from tests.cli.commands.test_native_issuance_cli import PASSCODE, holder_group
from tests.cli.commands.test_native_issuance_cli import live_parties as live_parties
from tests.cli.commands.test_native_negotiation_cli import kli
from tests.cli.commands.vc.test_native_registry_cli import group_registry


pytestmark = pytest.mark.real_store_roots


def test_installed_both_groups_require_native_thresholds_before_issuance_and_admit(tmp_path, live_parties):
    # Establish each party independently; existing installed commands approve the issuer RIP.
    issuers, individual, icoordinator = group_registry(tmp_path, live_parties)
    _, holders, holder_public, hcoordinator = holder_group(tmp_path, (issuers[0], individual))
    actors = [*issuers, *holders]
    for side in actors:
        hby = setupHby(name=side['name'], base=side['base'], bran=PASSCODE, noPrompt=True, version=V2)
        try:
            # This new conversation's original policy precedes its first partial Grant.
            config = hby.cf.get()
            config['kram'] = dict(enabled=True, denials=[],
                caches={'~': [1000, 60000, 60000, 300000, 60000, 60000, 300000]})
            hby.cf.put(config)
        finally:
            hby.close()
    bodyfile = tmp_path / 'both-group-body.cesr'
    kli(tmp_path, 'vc', 'create', *issuers[0]['args'], '--registry-name', 'issuer-fresh',
        '--recipient', holders[0]['pre'], '--data', '{"role":"both groups"}', '--output', str(bodyfile))
    body = SerderACDC(raw=bodyfile.read_bytes())
    proposal, grantfile = tmp_path / 'both-group-proposal.cesr', tmp_path / 'both-group-grant.cesr'
    outputs = [tmp_path / name for name in ('holder-lead.cesr', 'holder-peer.cesr')]
    logs = [tmp_path / name for name in ('issuer-lead.log', 'issuer-peer.log', 'holder-lead.log', 'holder-peer.log')]
    grant_args = ['--credential', str(bodyfile), '--recipient', holders[0]['pre'], '--issue', '--deliver',
        '--coordinator', icoordinator, '--custodian', issuers[0]['member'], '--consent-lifetime', '70', '--timeout', '65',
        '--input', str(holder_public)]
    processes, deadlines = [], {}

    def roots(side):
        keeper = Keeper(name=side['name'], base=side['base'], readonly=True, reopen=True)
        try:
            return bool(list(keeper.rroots.getTopItemIter()))
        finally:
            keeper.close()

    def deadline(side, grant):
        db = Baser(name=side['name'], base=side['base'], readonly=True, reopen=True)
        try:
            return db.epsd.get((grant,)).dts
        finally:
            db.close()

    with ExitStack() as stack:
        def start(arguments, log):
            output = stack.enter_context(log.open('w'))
            process = subprocess.Popen([shutil.which('kli'), *arguments], cwd=tmp_path,
                stdout=output, stderr=subprocess.STDOUT)
            processes.append(process)
            return process

        def phase(log, name):
            limit = time.monotonic() + 10
            while True:
                for line in log.read_text().splitlines():
                    if line.startswith('{') and json.loads(line).get('phase') == name:
                        return json.loads(line)
                assert all(p.poll() in (None, 0) for p in processes), '\n'.join(p.read_text() for p in logs if p.exists())
                assert time.monotonic() < limit, log.read_text()
                time.sleep(.03)

        try:
            # A partial issuer Grant cannot authorize native DH or create a root.
            start(['ipex', 'grant', *issuers[0]['args'], *grant_args, '--proposal-output', str(proposal),
                   '--output', str(grantfile)], logs[0])
            selected = phase(logs[0], 'group_proposed')
            deadlines[issuers[0]['name']] = deadline(issuers[0], selected['grant'])
            assert not grantfile.exists() and not any(roots(side) for side in actors)
            contributor = start(['ipex', 'grant', *issuers[1]['args'], *grant_args,
                                 '--proposal', str(proposal)], logs[1])
            contributor.wait(timeout=20)
            assert contributor.returncode == 0 and '"phase": "contributed"' in logs[1].read_text(), logs[1].read_text()
            phase(logs[0], 'group_dh_proposed')
            deadlines[issuers[1]['name']] = deadline(issuers[1], selected['grant'])
            admit_args = ['--said', selected['grant'], '--input', str(issuers[0]['public']), '--input', str(grantfile),
                '--coordinator', hcoordinator, '--custodian', holders[0]['member'], '--deliver', '--timeout', '30']
            # The elected holder proposes its partial reply; neither elected lead may retain a root yet.
            start(['ipex', 'admit', *holders[0]['args'], *admit_args, '--output', str(outputs[0])], logs[2])
            phase(logs[2], 'group_dh_proposed')
            deadlines[holders[0]['name']] = deadline(holders[0], selected['grant'])
            assert not any(roots(side) for side in actors)
            start(['ipex', 'admit', *holders[1]['args'], *admit_args, '--output', str(outputs[1])], logs[3])
            phase(logs[3], 'selected')
            deadlines[holders[1]['name']] = deadline(holders[1], selected['grant'])
            # Bilateral DH is distinct from issued/witnessed registry state and the group Admit.
            proposed = phase(logs[0], 'group_bup_proposed')
            assert [roots(side) for side in actors] == [True, False, True, False]
            for side in actors:
                baser = RegBaser(name=side['name'], base=side['base'], readonly=True, reopen=True)
                db = Baser(name=side['name'], base=side['base'], readonly=True, reopen=True)
                try:
                    assert RegistryStore(baser).headEvent(body.regid).ilk == 'rip'
                    assert db.erpy.get((selected['grant'],)) is None
                finally:
                    db.close()
                    baser.close()
            joined = subprocess.run([shutil.which('kli'), 'multisig', 'join', '--name', issuers[1]['name'],
                '--base', issuers[1]['base'], '--passcode', PASSCODE, '--version', '2.0'],
                input='\n', text=True, capture_output=True, cwd=tmp_path, timeout=25)
            assert joined.returncode == 0 and 'Approve exact BUP anchor' in joined.stdout, joined.stdout + joined.stderr
            assert proposed['anchor'] in joined.stdout
            for process in processes:
                process.wait(timeout=35)
            assert all(p.returncode == 0 for p in processes), '\n'.join(p.read_text() for p in logs)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)

    results = [next(json.loads(line) for line in reversed(log.read_text().splitlines()) if line.startswith('{'))
               for log in (logs[0], logs[2], logs[3])]
    assert all(r['admitted'] and r['registry_issued'] and r['grant'] == selected['grant'] for r in results)
    assert len({r['admit'] for r in results}) == 1
    assert results[1]['transmitted'] and not results[2]['transmitted']
    retained, queries, replies = [], [], []
    for side in actors:
        hby = setupHby(name=side['name'], base=side['base'], bran=PASSCODE, noPrompt=True, version=V2)
        rgy = Regery(hby, name=side['name'], base=side['base'])
        try:
            root = hby.habByName(side['alias']).mgr.getRegistryRoot(side['pre'], body.regid)
            retained.append(root.qb64 if root else None)
            assert hby.db.epsd.get((selected['grant'],)).dts == deadlines[side['name']]
            head = rgy.store.headEvent(body.regid)
            assert head.said == proposed['bup']
            _, said = regeventing.vetAnchor(head, db=hby.db, issuer=issuers[0]['pre'])
            assert said == proposed['anchor']
            assert hby.db.fullyWitnessed(hby.db.evts.get((issuers[0]['pre'], said)))
            assert {sig.index for sig in hby.db.sigs.get((issuers[0]['pre'], said))} == {0, 1}
            if side is issuers[1]:
                assert body.regid not in rgy.regs and hby.db.exns.get((selected['grant'],)) is None
            else:
                for said, sender in ((selected['grant'], issuers[0]['pre']), (results[0]['admit'], holders[0]['pre'])):
                    accepted = hby.db.exns.get((said,))
                    tsgs, _ = verify(hby, accepted)
                    assert {sig.index for pre, _, _, sigers in tsgs if pre.qb64 == sender for sig in sigers} == {0, 1}
                assert accepted.sad['p'] == selected['grant'] and accepted.sad['ri'] == issuers[0]['pre']
                assert loadParsedNestedSubstreams(hby, selected['grant'])[0].serder.raw == body.raw
                assert hby.db.exrs.get((selected['grant'], body.said)).state == 'issued'
            for _, packet in hby.db.exns.getTopItemIter():
                if packet.route in ('/multisig/qry', '/multisig/rpy'):
                    child = loadParsedNestedSubstreams(hby, packet.said)[0]
                    indices = {sig.index for pre, sigers in child.lsgs if pre.qb64 == side['pre'] for sig in sigers}
                    indices.update(sig.index for pre, _, _, sigers in child.tsgs if pre.qb64 == side['pre'] for sig in sigers)
                    (queries if packet.route.endswith('/qry') else replies).append((child.serder.raw, indices))
        finally:
            rgy.close()
            hby.close()
    assert retained[0] == retained[2] and retained[0] is not None and retained[1] is retained[3] is None
    for contributions in (queries, replies):
        assert len(contributions) == 2 and len({raw for raw, _ in contributions}) == 1
        assert set.union(*(indices for _, indices in contributions)) == {0, 1}
    assert all(retained[0].encode() not in path.read_bytes() for path in (proposal, grantfile, *outputs))
