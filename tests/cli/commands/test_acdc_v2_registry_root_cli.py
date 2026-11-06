"""Installed existing-root copies use one live approval and real witness mailboxes."""
import json
import shutil
import subprocess
import time

import pytest
from hio.base import doing

from keri import Vrsn_2_0 as V2
from keri.acdc import Regery, Registrar, acdcmap, regeventing
from keri.acdc.salting import RegistrySalt
from keri.app import Keeper, Receiptor
from keri.cli.common import setupHby
from keri.core import BlindState, Blinder, Encrypter, Parser, Salter, SealSource, Siger, messagize, reply
from keri.db import Baser
from keri.peer.exchanging import loadParsedNestedSubstreams, serializeParsedSubstream
from tests.cli.commands.test_ipex_v2_issuance_cli import PASSCODE, group_issue
from tests.cli.commands.test_ipex_v2_issuance_cli import live_parties as live_parties
from tests.cli.commands.test_ipex_v2_negotiation_cli import kli


pytestmark = pytest.mark.real_store_roots


def last_result(output):
    return json.loads([line for line in output.splitlines() if line.startswith('{')][-1])


def existing_registry(tmp_path, sides):
    """Author and witness the existing registry before either provisioning command."""
    issuer, receiver = sides
    hby = setupHby(name=issuer['name'], base=issuer['base'], bran=PASSCODE, noPrompt=True, version=V2)
    rgy = Regery(hby, name=issuer['name'], base=issuer['base'])
    try:
        hab = hby.habByName('issuer')
        hby.psr.parse(ims=bytearray(receiver['public'].read_bytes()), framed=False)
        registry = Registrar(rgy).makeRegistry('existing', hab.pre)

        def seal(event):
            hab.interact(data=[dict(i=registry.regk, s=event.sad['n'], d=event.said)], gvrsn=V2)
            receipts = Receiptor(hby=hby)
            def collect(tymth, tock=0.03125, **kwa):
                yield tock
                yield from receipts.receipt(hab.pre, sn=hab.kever.sn)
                owner.remove([receipts])
            owner = doing.DoDoer(doers=[receipts, doing.doify(collect)])
            doing.Doist(real=True, tock=0.03125, limit=10).do(doers=[owner])
            assert owner.done and registry.anchorMsg(event.said)

        seal(rgy.store.event(registry.regk))
        root = Salter()
        hab.mgr.putRegistryRoot(hab.pre, registry.regk, root)
        body = acdcmap(israid=hab.pre, iseaid=receiver['pre'], regid=registry.regk,
                       attribute=dict(d='', role='reader'))
        opening, event = Registrar(rgy).issue(registry, body, salt=root.qb64)
        seal(event)
        evidence = bytearray(hab.replay(gvrsn=V2))
        for raw in rgy.store.cloneTelIter(registry.regk):
            node = type(event)(raw=raw)
            sn, said = regeventing.vetAnchor(node, db=hby.db, issuer=hab.pre)
            evidence.extend(messagize(node, bonds=[SealSource(s=f'{sn:x}', d=said)], gvrsn=V2))
        public = tmp_path / 'public.cesr'
        public.write_bytes(evidence)
        held = tmp_path / 'held-opening.cesr'
        held.write_bytes(opening.qb64b)
        return body, event, opening, root.qb64, public, held
    finally:
        rgy.close()
        hby.close()


def retained(side, body):
    hby = setupHby(name=side['name'], base=side['base'], bran=PASSCODE, noPrompt=True, version=V2)
    rgy = Regery(hby, name=side['name'], base=side['base'])
    try:
        hab = hby.habByName(side['alias'])
        root = hab.mgr.getRegistryRoot(hab.pre, body.regid)
        return (root.qb64 if root else None,
                hby.ks.rroots.get((hab.pre, body.regid)).qb64 if root else None,
                tuple(rgy.store.cloneTelIter(body.regid)))
    finally:
        rgy.close()
        hby.close()


def receive_args(side, body, event, public, held):
    return ['vc', 'registry', 'receive', *side['args'], '--registry', body.regid,
            '--sender', body.israid, '--event', event.said, '--opening', str(held),
            '--evidence', str(public)]


def test_installed_copy_reopens_and_rejects_false_receipt_with_existing_root(tmp_path, live_parties):
    issuer, receiver = live_parties
    body, event, opening, root, public, held = existing_registry(tmp_path, live_parties)
    before = retained(issuer, body)
    assert retained(receiver, body)[0] is None
    args = receive_args(receiver, body, event, public, held)
    outside = tmp_path / 'outside-target.cesr'
    refused = kli(tmp_path, 'vc', 'registry', 'provision', *issuer['args'], '--registry', body.regid,
        '--recipient', receiver['pre'], '--target', issuer['pre'], '--output', str(outside), succeeds=False)
    assert 'not a current group signing member' in refused and not outside.exists()
    for name in ('first', 'identical'):
        destination = tmp_path / (name + '.cesr')
        prepared = last_result(kli(tmp_path, 'vc', 'registry', 'provision', *issuer['args'],
            '--registry', body.regid, '--recipient', receiver['pre'], '--output', str(destination)))
        result = last_result(kli(tmp_path, *args, '--message', str(destination)))
        assert result['received'] and result['reply'] == prepared['reply'] and not prepared['transmitted']
        assert root.encode() not in destination.read_bytes() and root.encode() not in public.read_bytes()
    saved = retained(receiver, body)
    assert saved[0] == root and saved[1] != root and retained(issuer, body) == before
    derived = Blinder.unblind(event.sad['b'], salt=saved[0], sn=1, acdc=body.said, states=('issued',))
    assert derived.qb64 == opening.qb64
    malformed = tmp_path / 'trailing-garbage.cesr'
    malformed.write_bytes(public.read_bytes() + b'garbage')
    output = kli(tmp_path, *args, '--evidence', str(malformed), '--message', str(destination), succeeds=False)
    assert 'complete public KEL/TEL frames' in output and '"phase": "approved"' not in output
    assert retained(receiver, body) == saved
    truncated = tmp_path / 'truncated.cesr'
    truncated.write_bytes(public.read_bytes()[:-1])
    output = kli(tmp_path, *args, '--evidence', str(truncated), '--message', str(destination), succeeds=False)
    assert 'complete public KEL/TEL frames' in output and '"phase": "approved"' not in output
    assert retained(receiver, body) == saved
    output = kli(tmp_path, *args, '--message', str(destination), '--timeout', '0.000001', succeeds=False)
    assert 'before --timeout' in output and '"received": true' not in output
    assert retained(receiver, body) == saved

    # BADA can retain this authenticated reply before v2 ACDC decryption/root checks fail.
    hby = setupHby(name=issuer['name'], base=issuer['base'], bran=PASSCODE, noPrompt=True, version=V2)
    try:
        hab = hby.habByName('issuer')
        wrong = Encrypter(verkey=hby.kevers[receiver['pre']].verfers[0].qb64).encrypt(prim=Salter())
        bad = reply(pre=hab.pre, route=RegistrySalt.Route, pvrsn=V2,
            data=dict(registry=body.regid, recipient=receiver['pre'], target=receiver['pre'], cipher=wrong.qb64))
        rejected = tmp_path / 'rejected.cesr'
        rejected.write_bytes(hab.endorse(bad, gvrsn=V2))
    finally:
        hby.close()
    output = kli(tmp_path, *args, '--message', str(rejected), succeeds=False)
    assert 'root does not reproduce' in output and '"received": true' not in output
    assert retained(receiver, body) == saved and retained(issuer, body) == before


def test_live_receive_timeout_needs_fresh_approval_then_real_mailbox_delivery(tmp_path, live_parties):
    issuer, receiver = live_parties
    body, event, _, root, public, held = existing_registry(tmp_path, live_parties)
    args = receive_args(receiver, body, event, public, held)
    output = kli(tmp_path, *args, '--listen', '--timeout', '0.4', succeeds=False)
    assert 'before --timeout' in output and '"received": true' not in output
    assert retained(receiver, body)[0] is None
    log = tmp_path / 'receive.log'
    with log.open('w+') as output:
        process = subprocess.Popen([shutil.which('kli'), *args, '--listen', '--timeout', '15'],
            cwd=tmp_path, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while '"phase": "approved"' not in log.read_text():
                assert process.poll() is None, log.read_text()
                assert time.monotonic() < deadline, log.read_text()
                time.sleep(.03)
            destination = tmp_path / 'delivered.cesr'
            prepared = last_result(kli(tmp_path, 'vc', 'registry', 'provision', *issuer['args'],
                '--registry', body.regid, '--recipient', receiver['pre'], '--output', str(destination),
                '--deliver', '--timeout', '15'))
            process.wait(timeout=20)
            assert process.returncode == 0 and 'ERR:' not in log.read_text(), log.read_text()
            received = last_result(log.read_text())
            assert received['received'] and received['reply'] == prepared['reply'] and prepared['transmitted']
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=5)
    assert retained(receiver, body)[0] == root


def group_copy(tmp_path, live_parties, data='{"role":"group reader"}'):
    # Continue the qualified real2of2 issuance; the nonlead has public proofs but no root.
    issuer, holders, body, selected = group_issue(tmp_path, live_parties, data=data)
    lead, target = holders
    before = retained(lead, body)
    assert before[0] is not None and retained(target, body)[0] is None
    hby = setupHby(name=target['name'], base=target['base'], bran=PASSCODE, noPrompt=True, version=V2)
    rgy = Regery(hby, name=target['name'], base=target['base'])
    try:
        coordinator = hby.habByName(target['alias']).kever.serder.said
        event = rgy.store.headEvent(body.regid)
        held_before = tuple(hby.db.enst.get((selected['grant'],)))
        proof = Blinder(data=BlindState(*loadParsedNestedSubstreams(hby, selected['grant'])[0].bsqs[0]))
        held = tmp_path / 'group-held-opening.cesr'
        held.write_bytes(proof.qb64b)
    finally:
        rgy.close()
        hby.close()
    scope = ['--registry', body.regid, '--recipient', lead['pre'], '--target', target['member'],
             '--coordinator', coordinator]
    partial, proposal = tmp_path / 'group-partial.cesr', tmp_path / 'group-proposal.cesr'
    refused = kli(tmp_path, 'vc', 'registry', 'provision', *target['args'], *scope,
        '--output', str(partial), '--proposal-output', str(proposal), succeeds=False)
    assert 'elected group coordinator' in refused and not partial.exists() and not proposal.exists()
    prepared = last_result(kli(tmp_path, 'vc', 'registry', 'provision', *lead['args'], *scope,
        '--output', str(partial), '--proposal-output', str(proposal), '--deliver', '--timeout', '15'))
    assert prepared['prepared'] and not prepared['contributed'] and prepared['transmitted']
    receive = ['vc', 'registry', 'receive', *target['args'], '--registry', body.regid,
               '--sender', lead['pre'], '--event', event.said, '--opening', str(held)]
    log = tmp_path / 'group-copy-partial.log'
    # KRAM retains incomplete group authentication before the live RegistrySalt route can run.
    with log.open('w') as output:
        process = subprocess.Popen([shutil.which('kli'), *receive, '--listen', '--timeout', '5'],
            cwd=tmp_path, stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 8
            store = Baser(name=target['name'], base=target['base'], readonly=True, reopen=True)
            try:
                key = (lead['pre'], prepared['reply'])
                while store.kramPMKM.get(key) is None:
                    assert process.poll() is None, log.read_text()
                    assert time.monotonic() < deadline, log.read_text()
                    time.sleep(.03)
                original = Parser(version=V2).parseOneBare(
                    ims=bytearray(partial.read_bytes()), processive=False).serder
                assert store.kramPMKM.get(key).raw == original.raw
                assert {siger.index for siger in store.kramPMKS.get(key)} == {0}
                assert store.kramPMSK.get(key) is not None
            finally:
                store.close()
            keeper = Keeper(name=target['name'], base=target['base'], readonly=True, reopen=True)
            try:
                assert not list(keeper.rroots.getTopItemIter())
            finally:
                keeper.close()
            process.wait(timeout=8)
            assert process.returncode != 0 and 'before --timeout' in log.read_text()
            assert '"received": true' not in log.read_text()
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=5)
    contribution = tmp_path / 'group-contribution.cesr'
    wrong = kli(tmp_path, 'vc', 'registry', 'provision', *target['args'], '--registry', body.regid,
        '--recipient', lead['pre'], '--target', lead['member'], '--coordinator', coordinator,
        '--proposal', str(proposal), '--output', str(contribution), succeeds=False)
    assert 'scope authentication' in wrong and not contribution.exists()
    contributed = last_result(kli(tmp_path, 'vc', 'registry', 'provision', *target['args'], *scope,
        '--proposal', str(proposal), '--output', str(contribution)))
    assert contributed['contributed'] and contributed['reply'] == prepared['reply']
    assert 'received' not in contributed and 'authenticated' not in contributed
    # An accepted proposal row cannot substitute for current scope or signature verification.
    fresh = tmp_path / 'group-fresh-contribution.cesr'
    wrong = kli(tmp_path, 'vc', 'registry', 'provision', *target['args'], '--registry', body.regid,
        '--recipient', lead['pre'], '--target', lead['member'], '--coordinator', coordinator,
        '--proposal', str(proposal), '--output', str(fresh), succeeds=False)
    assert 'scope authentication' in wrong and not fresh.exists()
    outer = Parser(version=V2).parseOneBare(ims=bytearray(proposal.read_bytes()), processive=False)
    pre, number, diger, sigers = outer.tsgs[0]
    corrupted = tmp_path / 'group-corrupted-proposal.cesr'
    corrupted.write_bytes(messagize(outer.serder,
        tsgs=[(pre, number, diger, [Siger(raw=bytes(64), index=sigers[0].index)])],
        nests=[serializeParsedSubstream(nest) for nest in outer.nests], gvrsn=V2))
    refused = kli(tmp_path, 'vc', 'registry', 'provision', *target['args'], *scope,
        '--proposal', str(corrupted), '--output', str(fresh), succeeds=False)
    assert 'scope authentication' in refused and not fresh.exists()
    repeated = last_result(kli(tmp_path, 'vc', 'registry', 'provision', *target['args'], *scope,
        '--proposal', str(proposal), '--output', str(fresh)))
    assert repeated['contributed'] and fresh.read_bytes() == contribution.read_bytes()
    original = Parser(version=V2).parseOneBare(ims=bytearray(partial.read_bytes()), processive=False)
    aggregate = Parser(version=V2).parseOneBare(ims=bytearray(contribution.read_bytes()), processive=False)
    assert aggregate.serder.raw == original.serder.raw
    assert {sig.index for pre, _, _, sigers in aggregate.tsgs if pre.qb64 == lead['pre']
            for sig in sigers} == {0, 1}
    assert retained(target, body)[0] is None  # Contributing authenticators grants no receive approval.
    result = last_result(kli(tmp_path, *receive, '--message', str(partial), '--message', str(contribution)))
    assert result['received'] and result['reply'] == prepared['reply']
    saved = retained(target, body)
    assert saved[0] == before[0] and saved[1] != before[0] and saved[2] == before[2]
    assert retained(target, body) == saved and retained(lead, body) == before
    hby = setupHby(name=target['name'], base=target['base'], bran=PASSCODE, noPrompt=True, version=V2)
    try:
        assert tuple(hby.db.enst.get((selected['grant'],))) == held_before
    finally:
        hby.close()
    assert all(before[0].encode() not in path.read_bytes() for path in (partial, proposal, contribution, held))
    return issuer, holders, body, selected


def test_group_copy_requires_exact_contribution_then_v2_retention(tmp_path, live_parties):
    group_copy(tmp_path, live_parties)
