"""Independent accepted group rotations precede a later installed issuance."""
import hashlib
import shutil
import subprocess
import time

import pytest

from keri import Vrsn_2_0 as V2
from keri.cli.common import setupHby
from keri.core import Diger, Kevery, Kramer, Parser
from keri.peer.exchanging import verify
from tests.cli.commands.test_native_both_group_issuance_cli import both_parties, issue_groups
from tests.cli.commands.test_native_issuance_cli import PASSCODE
from tests.cli.commands.test_native_issuance_cli import live_parties as live_parties
from tests.cli.commands.test_native_negotiation_cli import kli


pytestmark = pytest.mark.real_store_roots


def opened(side):
    return setupHby(name=side['name'], base=side['base'], bran=PASSCODE, noPrompt=True, version=V2)


def public(side, *, member=False):
    hby = opened(side)
    try:
        hab = hby.habByName(side['alias'])
        return bytes((hab.mhab if member else hab).replay(gvrsn=V2))
    finally:
        hby.close()


def propagate(actors, raw):
    """Bootstrap only real public KELs through ordinary signature/witness verification."""
    for side in actors:
        hby = opened(side)
        try:
            kvy = Kevery(db=hby.db, rvy=hby.rvy, lax=True, local=False, direct=False,
                         kramer=Kramer(db=hby.db, cf=hby.cf))
            Parser(kvy=kvy, rvy=hby.rvy, version=V2).parse(ims=bytearray(raw))
            kvy.processEscrows()
        finally:
            hby.close()


def history(side, body, grant):
    hby = opened(side)
    try:
        root = hby.habByName(side['alias']).mgr.getRegistryRoot(side['pre'], body.regid)
        message = hby.db.exns.get((grant,))
        admission = hby.db.erpy.get((grant,))
        if message is not None:
            assert admission is not None, 'pending Grant accepted without its selected Admit'
            verify(hby, message)
            verify(hby, hby.db.exns.get((admission.qb64,)))
        # Accepted proofs are durable history; expired pending scratch evidence may be removed.
        proofs = tuple(hby.db.enst.get((grant,))) if message is not None else None
        # Accepted KRAM transaction evidence fixes the exchange lifetime, whether or not the body is retained.
        lifetime = tuple((keys, cache.xdt, cache.xl) for keys, cache in hby.db.kramTMSC.getTopItemIter()
                         if keys[-1] == grant and cache.rdt)
        return (hashlib.sha256(root.qb64b).hexdigest() if root else None, message.raw if message else None,
                proofs, admission.qb64 if admission else None, lifetime)
    finally:
        hby.close()


def rotate_party(tmp_path, party, actors, label):
    # Member keys rotate and are witnessed independently before their group uses those committed next keys.
    for side in party:
        hby = opened(side)
        try:
            alias = hby.habByName(side['alias']).mhab.name
        finally:
            hby.close()
        kli(tmp_path, 'rotate', '--name', side['name'], '--base', side['base'], '--passcode', PASSCODE,
            '--alias', alias, '--version', '2.0', '--receipt-endpoint', '--isith', '1', '--nsith', '1')
        propagate(actors, public(side, member=True))
    hby = opened(party[0])
    try:
        group = hby.habByName(party[0]['alias'])
        prior, old_next = group.kever.serder.said, tuple(d.qb64 for d in group.kever.ndigers)
    finally:
        hby.close()
    logs = [tmp_path / (label + suffix) for suffix in ('-rotate.log', '-join.log')]
    processes = []
    with logs[0].open('w') as proposal, logs[1].open('w') as approval:
        try:
            processes.append(subprocess.Popen([shutil.which('kli'), 'multisig', 'rotate', *party[0]['args'],
                '--isith', '2', '--nsith', '2'], cwd=tmp_path, stdout=proposal, stderr=subprocess.STDOUT))
            join = subprocess.Popen([shutil.which('kli'), 'multisig', 'join', '--name', party[1]['name'],
                '--base', party[1]['base'], '--passcode', PASSCODE, '--version', '2.0'], cwd=tmp_path,
                stdin=subprocess.PIPE, stdout=approval, stderr=subprocess.STDOUT, text=True)
            processes.append(join)
            join.stdin.write('\n')
            join.stdin.close()
            limit = time.monotonic() + 25
            while any(p.poll() is None for p in processes):
                assert all(p.poll() in (None, 0) for p in processes), '\n'.join(p.read_text() for p in logs)
                assert time.monotonic() < limit, '\n'.join(p.read_text() for p in logs)
                time.sleep(.03)
            assert all(p.returncode == 0 for p in processes), '\n'.join(p.read_text() for p in logs)
            assert 'Group Multisig Rotation proposed' in logs[1].read_text()
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
    said = None
    for side in party:
        hby = opened(side)
        try:
            group = hby.habByName(side['alias'])
            event = group.kever.serder
            assert event.pvrsn == V2 and event.ilk == 'rot' and event.sad['p'] == prior
            assert event.said == (said or event.said)
            said = event.said
            assert group.kever.tholder.satisfy({0, 1}) and hby.db.fullyWitnessed(event)
            assert {sig.index for sig in hby.db.sigs.get((group.pre, said))} == {0, 1}
            assert {Diger(ser=key.qb64b).qb64 for key in event.verfers} == set(old_next)
        finally:
            hby.close()
    propagate(actors, public(party[0]))
    return said


def test_later_bilateral_issuance_uses_independently_rotated_groups(tmp_path, live_parties):
    issuers, holders, holder_public, icoordinator, hcoordinator = both_parties(tmp_path, live_parties)
    actors = [*issuers, *holders]
    body, selected = issue_groups(tmp_path, issuers, holders, holder_public, icoordinator, hcoordinator)
    original = [history(side, body, selected['grant']) for side in actors]
    # Each party accepts its own event separately; neither event selects the opposite party's custodian.
    icoordinator = rotate_party(tmp_path, issuers, actors, 'issuer')
    hcoordinator = rotate_party(tmp_path, holders, actors, 'holder')
    assert icoordinator != hcoordinator
    assert [history(side, body, selected['grant']) for side in actors] == original
    issuers[0]['public'].write_bytes(b''.join(public(side, member=True) for side in issuers) + public(issuers[0]))
    holder_public.write_bytes(b''.join(public(side, member=True) for side in holders) + public(holders[0]))
    # A new registry starts a new DH transaction; the original accepted roots and admissions are immutable.
    log = tmp_path / 'rotated-rip.log'
    with log.open('w') as output:
        process = subprocess.Popen([shutil.which('kli'), 'vc', 'registry', 'incept', *issuers[0]['args'],
            '--registry-name', 'rotated-fresh', '--usage', 'post-rotation issuance'], cwd=tmp_path,
            stdout=output, stderr=subprocess.STDOUT)
        try:
            kli(tmp_path, 'multisig', 'join', '--name', issuers[1]['name'], '--base', issuers[1]['base'],
                '--passcode', PASSCODE, '--version', '2.0', '--auto')
            process.wait(timeout=25)
            assert process.returncode == 0, log.read_text()
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
    later, new = issue_groups(tmp_path, issuers, holders, holder_public, icoordinator, hcoordinator,
                              registry_name='rotated-fresh', stem='rotated-')
    assert later.regid != body.regid and new['grant'] != selected['grant']
    assert [history(side, body, selected['grant']) for side in actors] == original
    hby = opened(issuers[0])
    try:
        root = hby.habByName(issuers[0]['alias']).mgr.getRegistryRoot(issuers[0]['pre'], later.regid)
        fingerprint = hashlib.sha256(root.qb64b).hexdigest()
        assert fingerprint != original[0][0]
    finally:
        hby.close()
