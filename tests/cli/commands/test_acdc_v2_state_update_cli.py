"""Installed v2 ACDC state updates retain root custody and admitted evidence."""
import json
from uuid import uuid4

import pytest

from keri import Vrsn_2_0 as V2
from keri.acdc import Regery, Registrar, acdcmap, grant, regeventing
from keri.app import openHby
from keri.cli.common import setupHby
from keri.core import Blinder, Kevery, Parser, Salter, messagize
from tests.cli.commands.test_ipex_v2_issuance_cli import PASSCODE, issue
from tests.cli.commands.test_ipex_v2_issuance_cli import live_parties as live_parties
from tests.cli.commands.test_ipex_v2_negotiation_cli import enable_kram, kli
from tests.cli.commands.test_registry_root_cli import last_result


pytestmark = pytest.mark.real_store_roots


def snapshot(side, credential, grant):
    hby = setupHby(name=side['name'], base=side['base'], bran=PASSCODE, noPrompt=True, version=V2)
    rgy = Regery(hby=hby, name=side['name'], base=side['base'])
    try:
        hab = hby.habByName(side['alias'])
        return (hab.mgr.getRegistryRoot(hab.pre, credential.regid).qb64,
                tuple(hby.db.enst.get((grant,))), hby.db.erpy.get((grant,)).qb64,
                rgy.store.headEvent(credential.regid).said)
    finally:
        rgy.close()
        hby.close()


def test_installed_witnessed_state_updates_preserve_admitted_proof(tmp_path, live_parties):
    selected, body = issue(tmp_path, live_parties)
    issuer, holder = live_parties
    before = [snapshot(side, body, selected['grant']) for side in live_parties]
    issued = tmp_path / 'issued-update.cesr'
    result = last_result(kli(tmp_path, 'vc', 'registry', 'update', *issuer['args'],
        '--credential', str(tmp_path / 'body.cesr'), '--state', 'issued',
        '--output', str(issued), '--timeout', '20'))
    assert result['accepted'] and result['regid'] == body.regid and result['sequence'] == 2
    assert result['priorHead'] == before[0][3] and result['head'] != result['priorHead']
    public = issued.read_bytes()
    frames = Parser(version=V2).parse(ims=bytearray(public), framed=False, processive=False)
    assert all(not frame.bsqs and not frame.bsss for frame in frames)
    assert before[0][0].encode() not in public and body.raw not in public
    with openHby(name='v2-update-independent', version=V2) as observer:
        rgy = Regery(observer, temp=True)
        try:
            kvy = Kevery(db=observer.db, rvy=observer.rvy, lax=True, local=False)
            Parser(version=V2, kvy=kvy, rvy=observer.rvy, rgy=rgy).parse(
                ims=bytearray(public), framed=False)
            kvy.processEscrows()
            rgy.processEscrows()
            head = rgy.store.headEvent(body.regid)
            assert head.said == result['head']
            sn, said = regeventing.vetAnchor(head, db=observer.db, issuer=issuer['pre'])
            event = observer.db.evts.get((issuer['pre'], said))
            assert event.sn == sn and observer.db.fullyWitnessed(event)
        finally:
            rgy.close()
    assert snapshot(issuer, body, selected['grant'])[:3] == before[0][:3]
    assert snapshot(holder, body, selected['grant']) == before[1]
    assert 'output already exists' in kli(tmp_path, 'vc', 'registry', 'update', *issuer['args'],
        '--credential', str(tmp_path / 'body.cesr'), '--state', 'issued',
        '--output', str(issued), succeeds=False)
    assert issued.read_bytes() == public

    vacant = tmp_path / 'vacuous-update.cesr'
    vacuous = last_result(kli(tmp_path, 'vc', 'registry', 'update', *issuer['args'],
        '--credential', str(tmp_path / 'body.cesr'), '--state', 'vacuous',
        '--output', str(vacant), '--timeout', '20'))
    assert vacuous['accepted'] and vacuous['sequence'] == 3 and vacuous['priorHead'] == result['head']
    assert snapshot(issuer, body, selected['grant'])[:3] == before[0][:3]
    revoked = tmp_path / 'revoked-update.cesr'
    result = last_result(kli(tmp_path, 'vc', 'registry', 'update', *issuer['args'],
        '--credential', str(tmp_path / 'body.cesr'), '--state', 'revoked',
        '--output', str(revoked), '--timeout', '20'))
    assert result['accepted'] and result['sequence'] == 4 and result['state'] == 'revoked'
    hby = setupHby(name=issuer['name'], base=issuer['base'], bran=PASSCODE, noPrompt=True, version=V2)
    rgy = Regery(hby, name=issuer['name'], base=issuer['base'])
    try:
        hab = hby.habByName('issuer')
        head = rgy.store.headEvent(body.regid)
        proof = Blinder.unblind(head.sad['b'], salt=before[0][0], sn=4,
                                acdc=body.said, states=('issued', 'revoked', ''))
        assert proof.state == 'revoked'
        presented, atc = grant(hab, holder['pre'], 'revoked state cannot authorize Admit',
            origin=messagize(body, bonds=[proof.data], gvrsn=V2))
        refused = tmp_path / 'revoked-grant.cesr'
        refused.write_bytes(presented.raw + atc)
    finally:
        rgy.close()
        hby.close()
    output = kli(tmp_path, 'ipex', 'admit', *holder['args'], '--said', presented.said,
        '--unblind', '--input', str(revoked), '--input', str(refused), '--deliver',
        '--timeout', '2', succeeds=False)
    assert 'current verified issued state' in output
    assert snapshot(issuer, body, selected['grant'])[:3] == before[0][:3]
    assert snapshot(holder, body, selected['grant'])[:3] == before[1][:3]
    assert before[0][0].encode() not in revoked.read_bytes()


def test_acdc_v2_update_refuses_rip_only_and_staged_successors(tmp_path):
    name, base = f'update-refusal-{uuid4().hex}', 'v2-update'
    with openHby(name=name, base=base, bran=PASSCODE, temp=False, version=V2) as hby:
        hab = hby.makeHab(name='issuer')
        rgy = Regery(hby, name=name, base=base)
        try:
            registry = Registrar(rgy).makeRegistry('states', hab.pre)
            rip = rgy.store.headEvent(registry.regk) or rgy.store.event(registry.regk)
            hab.interact(data=[dict(i=registry.regk, s='0', d=rip.said)], gvrsn=V2)
            assert registry.anchorMsg(rip.said)
            root = Salter()
            hab.mgr.putRegistryRoot(hab.pre, registry.regk, root)
            body = acdcmap(israid=hab.pre, regid=registry.regk, attribute=dict(d='', role='reader'))
            credential = tmp_path / 'body.cesr'
            credential.write_bytes(body.raw)
            initial_sn = hab.kever.sn
        finally:
            rgy.close()
    args = ['--name', name, '--base', base, '--alias', 'issuer', '--passcode', PASSCODE,
            '--version', '2.0', '--credential', str(credential), '--state', 'issued']
    destination = tmp_path / 'refused.cesr'
    assert 'RIP-only' in kli(tmp_path, 'vc', 'registry', 'update', *args,
        '--output', str(destination), succeeds=False)
    assert not destination.exists()
    hby = setupHby(name=name, base=base, bran=PASSCODE, noPrompt=True, version=V2)
    rgy = Regery(hby, name=name, base=base)
    try:
        registry, hab = rgy.registryByName('states'), hby.habByName('issuer')
        assert hab.kever.sn == initial_sn
        _, first = Registrar(rgy).issue(registry, body, salt=root.qb64)
        hab.interact(data=[dict(i=registry.regk, s=first.sad['n'], d=first.said)], gvrsn=V2)
        assert registry.anchorMsg(first.said)
        _, pending = Registrar(rgy).issue(registry, body, salt=root.qb64)
        assert registry._effectiveFrontier().said == pending.said
        prior_sn = hab.kever.sn
    finally:
        rgy.close()
        hby.close()
    assert 'outstanding staged successor' in kli(tmp_path, 'vc', 'registry', 'update', *args,
        '--output', str(destination), succeeds=False)
    assert not destination.exists()
    hby = setupHby(name=name, base=base, bran=PASSCODE, noPrompt=True, version=V2)
    rgy = Regery(hby, name=name, base=base)
    try:
        assert hby.habByName('issuer').kever.sn == prior_sn
        assert rgy.store.headEvent(body.regid).said == first.said
        assert rgy.registryByName('states')._effectiveFrontier().said == pending.said
    finally:
        rgy.close()
        hby.close()


def test_group_issuer_provisions_nonlead_then_updates_and_holder_presents(tmp_path, live_parties):
    import shutil
    import subprocess
    import time
    from keri.app import Habery, Notifier
    from keri.acdc import RegBaser, RegistryStore
    from keri.core import BlindState
    from keri.peer.exchanging import loadParsedNestedSubstreams
    from tests.cli.commands.test_ipex_v2_issuance_cli import group_issuer_issue, witnessed
    from tests.cli.commands.test_ipex_v2_presentation_cli import intake, inspect, present
    from tests.cli.commands.test_registry_root_cli import retained

    issuers, holder, body, selected = group_issuer_issue(tmp_path, live_parties)
    lead, peer = issuers
    credential = tmp_path / 'issuer-body.cesr'
    before = [snapshot(side, body, selected['grant']) for side in (lead, holder)]
    assert retained(peer, body)[0] is None
    destination = tmp_path / 'nonlead-update.cesr'
    update_args = ['vc', 'registry', 'update', *peer['args'], '--credential', str(credential),
                   '--state', 'issued', '--output', str(destination), '--timeout', '25']
    # Root possession is explicit capability; group membership alone cannot stage a successor.
    refused = kli(tmp_path, *update_args, succeeds=False)
    assert 'existing issuer-owned registry root' in refused and not destination.exists()
    hby = setupHby(name=lead['name'], base=lead['base'], bran=PASSCODE, noPrompt=True, version=V2)
    rgy = Regery(hby, name=lead['name'], base=lead['base'])
    notifier = Notifier(hby)
    try:
        first = rgy.store.headEvent(body.regid)
        proof = Blinder(data=BlindState(*loadParsedNestedSubstreams(hby, selected['grant'])[0].bsqs[0]))
        held = tmp_path / 'issuer-held-opening.cesr'
        held.write_bytes(proof.qb64b)
        unrelated = {keys: notice.attrs for keys, notice in notifier.noter.notes.getTopItemIter()
                     if notice.attrs['r'].startswith(('/xip/ipex/', '/exn/ipex/'))}
        assert {attrs['d'] for attrs in unrelated.values()} >= {selected['grant'], before[0][2]}
    finally:
        notifier.noter.close()
        rgy.close()
        hby.close()

    # The lead member copies the group root to the rootless member as one ESSR exn.
    copy = tmp_path / 'issuer-root-copy.cesr'
    sent = last_result(kli(tmp_path, 'vc', 'registry', 'root', 'send', *lead['args'],
        '--registry', body.regid, '--out', str(copy)))
    assert sent['recipient'] == peer['member'] and sent['gid'] == lead['pre']
    assert retained(peer, body)[0] is None
    received = last_result(kli(tmp_path, 'vc', 'registry', 'root', 'receive', *peer['args'],
        '--registry', body.regid, '--sender', lead['member'], '--event', first.said,
        '--opening', str(held), '--message', str(copy)))
    assert received['received'] and received['said'] == sent['exchange']
    root, encrypted, _ = retained(peer, body)
    assert root == before[0][0] and encrypted != root
    assert Blinder.unblind(first.sad['b'], salt=root, sn=1, acdc=body.said, states=('issued',)).qb64 == proof.qb64
    assert all(root.encode() not in p.read_bytes() for p in (copy, held))

    # With the root present, wrong-witness authorization still fails before staging.
    refused = kli(tmp_path, *update_args, '--authenticate', '--code', 'unsupported:code', succeeds=False)
    assert 'selected witness' in refused and not destination.exists()

    # The formerly rootless member authors BUP2; the other member must approve its exact controller anchor.
    log = tmp_path / 'nonlead-update.log'
    with log.open('w') as output:
        process = subprocess.Popen([shutil.which('kli'), *update_args], cwd=tmp_path,
            stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while '"phase": "group_bup_proposed"' not in log.read_text():
                assert process.poll() is None, log.read_text()
                assert time.monotonic() < deadline, log.read_text()
                time.sleep(.03)
            pending = next(json.loads(line) for line in log.read_text().splitlines()
                           if line.startswith('{') and json.loads(line).get('phase') == 'group_bup_proposed')
            assert destination.read_bytes() == b''
            baser = RegBaser(name=peer['name'], base=peer['base'], readonly=True, reopen=True)
            try:
                store = RegistryStore(baser)
                assert store.headEvent(body.regid).said == first.said
                assert store.event(pending['bup']) is not None  # Staging is not accepted history.
            finally:
                baser.close()
            joined = subprocess.run([shutil.which('kli'), 'multisig', 'join', '--name', lead['name'],
                '--base', lead['base'], '--passcode', PASSCODE, '--version', '2.0'],
                input='\n', text=True, capture_output=True, cwd=tmp_path, timeout=25)
            assert joined.returncode == 0 and 'Approve exact BUP anchor' in joined.stdout, joined.stdout + joined.stderr
            assert pending['anchor'] in joined.stdout
            hby = setupHby(name=lead['name'], base=lead['base'], bran=PASSCODE, noPrompt=True, version=V2)
            notifier = Notifier(hby)
            try:
                assert all(notifier.noter.notes.get(keys).attrs == attrs for keys, attrs in unrelated.items())
            finally:
                notifier.noter.close()
                hby.close()
            process.wait(timeout=25)
            assert process.returncode == 0 and 'ERR:' not in log.read_text(), log.read_text()
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
    updated = last_result(log.read_text())
    assert updated['accepted'] and updated['sequence'] == 2 and updated['priorHead'] == first.said
    assert updated['head'] == pending['bup']
    assert root.encode() not in destination.read_bytes() and body.raw not in destination.read_bytes()
    hby = setupHby(name=peer['name'], base=peer['base'], bran=PASSCODE, noPrompt=True, version=V2)
    rgy = Regery(hby, name=peer['name'], base=peer['base'])
    try:
        assert body.regid not in rgy.regs  # The temporary owner facade did not invent an alias.
        event = rgy.store.headEvent(body.regid)
        sn, said = regeventing.vetAnchor(event, db=hby.db, issuer=peer['pre'])
        anchor = hby.db.evts.get((peer['pre'], said))
        assert anchor.sn == sn and hby.db.fullyWitnessed(anchor)
        assert {sig.index for sig in hby.db.sigs.get((peer['pre'], said))} == {0, 1}
        assert hby.db.exns.get((selected['grant'],)) is None
    finally:
        rgy.close()
        hby.close()

    # The actual holder refreshes only a new presentation; an independent verifier never receives a root.
    name, base = f'continuation-verifier-{uuid4().hex}', lead['base']
    hby = Habery(name=name, base=base, bran=PASSCODE, version=V2)
    try:
        enable_kram(hby)
        witness = (tmp_path / 'witness.cesr').read_bytes()
        Parser(kvy=hby.kvy, rvy=hby.rvy, version=V2).parse(ims=bytearray(witness))
        wit = Parser(version=V2).parseOneBare(ims=bytearray(witness), processive=False).serder.pre
        hab = hby.makeHab(name='verifier', wits=[wit], toad=1)
        witnessed(hby, hab)
        public = tmp_path / 'continuation-verifier.cesr'
        public.write_bytes(bytes(hab.replay(gvrsn=V2)))
        verifier = dict(name=name, base=base, alias='verifier', pre=hab.pre, public=public,
            args=['--name', name, '--base', base, '--alias', 'verifier', '--passcode', PASSCODE, '--version', '2.0'])
    finally:
        hby.close()
    support = lead['public'].read_bytes() + destination.read_bytes()
    intake(holder, support)
    intake(verifier, support)
    presented, _, accepted = present(tmp_path, holder, verifier, selected['grant'],
                                    'continuation-present', '--refresh', '--derive')
    assert accepted['accepted'] and accepted['terminal'] and accepted['observations'][body.said]['state'] == 'issued'
    current = inspect(tmp_path, verifier, presented, current=True)
    assert current['current']['observations'][body.said]['said'] == updated['head']
    assert retained(verifier, body)[0] is None
    assert [snapshot(side, body, selected['grant'])[:3] for side in (lead, holder)] == [old[:3] for old in before]
    assert credential.read_bytes() == body.raw
