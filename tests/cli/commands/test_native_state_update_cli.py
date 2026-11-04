"""Installed native state updates retain root custody and admitted evidence."""
import json
from uuid import uuid4

import pytest

from keri import Vrsn_2_0 as V2
from keri.acdc import Regery, Registrar, acdcmap, grant, regeventing
from keri.app import openHby
from keri.cli.common import setupHby
from keri.core import Blinder, Kevery, Parser, Salter, messagize
from tests.cli.commands.test_native_issuance_cli import PASSCODE, issue
from tests.cli.commands.test_native_issuance_cli import live_parties as live_parties
from tests.cli.commands.test_native_negotiation_cli import kli


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
    result = json.loads(kli(tmp_path, 'vc', 'registry', 'update', *issuer['args'],
        '--credential', str(tmp_path / 'body.cesr'), '--state', 'issued',
        '--output', str(issued), '--timeout', '20').splitlines()[-1])
    assert result['accepted'] and result['regid'] == body.regid and result['sequence'] == 2
    assert result['priorHead'] == before[0][3] and result['head'] != result['priorHead']
    public = issued.read_bytes()
    frames = Parser(version=V2).parse(ims=bytearray(public), framed=False, processive=False)
    assert all(not frame.bsqs and not frame.bsss for frame in frames)
    assert before[0][0].encode() not in public and body.raw not in public
    with openHby(name='native-update-independent', version=V2) as observer:
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
    vacuous = json.loads(kli(tmp_path, 'vc', 'registry', 'update', *issuer['args'],
        '--credential', str(tmp_path / 'body.cesr'), '--state', 'vacuous',
        '--output', str(vacant), '--timeout', '20').splitlines()[-1])
    assert vacuous['accepted'] and vacuous['sequence'] == 3 and vacuous['priorHead'] == result['head']
    assert snapshot(issuer, body, selected['grant'])[:3] == before[0][:3]
    revoked = tmp_path / 'revoked-update.cesr'
    result = json.loads(kli(tmp_path, 'vc', 'registry', 'update', *issuer['args'],
        '--credential', str(tmp_path / 'body.cesr'), '--state', 'revoked',
        '--output', str(revoked), '--timeout', '20').splitlines()[-1])
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


def test_native_update_refuses_rip_only_and_staged_successors(tmp_path):
    name, base = f'update-refusal-{uuid4().hex}', 'native-update'
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
