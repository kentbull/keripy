"""Legacy negotiation uses real KLI processes and existing v1 constructors."""
import json
import os
import subprocess
import sys
import uuid
from types import SimpleNamespace
import pytest
from keri.kering import ConfigurationError
from keri.cli.commands.ipex.grant import GrantDoer

from keri import Vrsn_1_0, Kinds
from keri.app import openHby, Notifier
from keri.app.notifying import Noter
from keri.peer import exchanging
from keri.vc import protocoling
from keri.core import Counter, Codens, Diger, Parser, Prefixer, Salter, SealEvent, Seqner
from keri.vc import credential
from keri.vdr import Regery, Verifier


PASSCODE = '0123456789abcdefghijk'  # public fixture only


def test_legacy_apply_offer_agree_across_cli_processes(tmp_path, seeder):
    """Complete installed v1 negotiation, verified admission, and authenticated return.

    Args:
        tmp_path (Path): Pytest-owned exact apply/offer/agree/grant transfer files.
        seeder: Existing legacy schema fixture; populates schema evidence, never
        accepted credential/KEL/TEL rows.

    Returns:
        None. Actual CLI processes reopen separate persistent stores, using ordinary
        v1 verifiers to issue and receive the credential. Assertions require correct
        prior/recipient/credential links. An authenticated grant without its schema
        must remain unadmitted without an output file; importing that real dependency
        permits admission. Wrong accepted-agreement selections raise ConfigurationError.
        No --v2 opt-in or synthetic native alias is used."""
    base = 'legacy-negotiation-' + uuid.uuid4().hex
    names = {role: role + '-' + uuid.uuid4().hex for role in ('issuer', 'holder')}
    prefixes = {}
    for role, name in names.items():
        with openHby(name=name, base=base, temp=False, bran=PASSCODE,
                     salt=Salter().qb64, version=Vrsn_1_0) as hby:
            hab = hby.makeHab(name=role, version=Vrsn_1_0, kind=Kinds.json)
            prefixes[role] = hab.pre
    schema = 'EMQWEcCnVRk1hatTNyK3sIykYSrrFvafX3bHQ9Gkk1kC'
    with openHby(name=names['issuer'], base=base, temp=False, bran=PASSCODE,
                 version=Vrsn_1_0) as hby:
        hab = hby.habByName('issuer')
        seeder.seedSchema(hby.db)
        rgy = Regery(hby=hby, name=hby.name, base=base, temp=False)
        try:
            reg = rgy.makeRegistry(prefix=hab.pre, name='legacy', noBackers=True,
                                   version=Vrsn_1_0, kind=Kinds.json)
            hab.interact(data=[SealEvent(reg.regk, '0', reg.regd)._asdict()], version=Vrsn_1_0, kind=Kinds.json)
            reg.anchorMsg(pre=reg.regk, regd=reg.regd, seqner=Seqner(sn=hab.kever.sn),
                          saider=Diger(qb64=hab.kever.serder.said))
            rgy.processEscrows()
            cred = credential(issuer=hab.pre, schema=schema, status=reg.regk,
                data=dict(i=prefixes['holder'], LEI='254900OPPU84GM83MG36'),
                version=Vrsn_1_0, kind=Kinds.json)
            event = reg.issue(said=cred.said)
            hab.interact(data=[SealEvent(event.pre, '0', event.said)._asdict()], version=Vrsn_1_0, kind=Kinds.json)
            reg.anchorMsg(pre=event.pre, regd=event.said, seqner=Seqner(sn=hab.kever.sn),
                          saider=Diger(qb64=hab.kever.serder.said))
            rgy.processEscrows()
            raw = (cred.raw + Counter(Codens.SealSourceTriples, count=1, version=Vrsn_1_0).qb64b
                   + Prefixer(qb64=event.pre).qb64b + Seqner(sn=0).qb64b + event.saidb)
            Parser(version=Vrsn_1_0).parseOne(ims=raw, vry=Verifier(hby=hby, reger=rgy.reger))
            assert rgy.reger.saved.get((cred.said,)) is not None
        finally:
            rgy.close()

    def invoke(role, verb, *options, okay=True):
        """Run one bounded installed legacy IPEX command over its persistent role store.

        Args:
            role (str): Issuer or holder selecting the existing identity and alias.
            verb (str): Actual KLI IPEX command to invoke.
            *options: Public command tokens and exact input/output file selections.
            okay (bool): Require success, or return the actual expected refusal.

        Returns:
            dict | str: First JSON result on success, or actual diagnostic text for
            an explicitly expected refusal.

        Raises:
            AssertionError: Exit status or KLI's textual ERR fallback reports failure.
            TimeoutExpired: Process exceeds twenty seconds. Missing/malformed JSON also
            fails the test rather than being interpreted as successful negotiation."""
        result = subprocess.run([sys.executable, '-m', 'keri.cli.kli', 'ipex', verb,
            '--name', names[role], '--base', base, '--alias', role, *options],
            env=dict(os.environ, KLI_KEYSTORE_PASSCODE=PASSCODE), capture_output=True,
            text=True, timeout=20)
        if not okay:
            assert result.returncode != 0 or 'ERR:' in result.stdout, result.stdout + result.stderr
            return result.stdout + result.stderr
        assert result.returncode == 0 and 'ERR:' not in result.stdout, result.stdout + result.stderr
        return next(json.loads(line) for line in result.stdout.splitlines() if line.startswith('{'))

    application, offered, agreement = (tmp_path / name for name in ('apply.cesr', 'offer.cesr', 'agree.cesr'))
    applied = invoke('holder', 'apply', '--recipient', prefixes['issuer'], '--schema', schema,
                     '--attributes', '{"LEI":"254900OPPU84GM83MG36"}', '--output', str(application))
    offer = invoke('issuer', 'offer', '--recipient', prefixes['holder'], '--said', cred.said,
                   '--prior', applied['exchange'], '--input', str(application), '--output', str(offered))
    agree = invoke('holder', 'agree', '--said', offer['exchange'], '--input', str(offered),
                   '--output', str(agreement))
    assert all(result['version'] == '1.0' and result['localAccepted'] for result in (applied, offer, agree))
    assert agree['recipient'] == prefixes['issuer']
    assert agreement.stat().st_size > 0

    granted = tmp_path / 'grant.cesr'
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    delivered = []

    class Intake(BaseHTTPRequestHandler):
        """Capture real HTTP bytes without replacing any credential verifier."""

        def do_POST(self):
            """Retain this request body and acknowledge transport; return None.

            The server only captures bytes. The ordinary receiver processors below
            must authenticate them separately; read/write errors fail the request.
            """
            delivered.append(self.rfile.read(int(self.headers['Content-Length'])))
            self.send_response(202)
            self.end_headers()

        def log_message(self, *args):
            """Suppress fixture access logs; args are unused, return None."""
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Intake)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        grant = invoke('issuer', 'grant', '--said', cred.said, '--recipient', prefixes['holder'],
            '--prior', agree['exchange'], '--input', str(agreement), '--output', str(granted),
            '--endpoint', f'http://127.0.0.1:{server.server_port}/ingest')
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    # Removing the completed HTTP child must leave the Grant owner open long
    # enough to query its authenticated completion and print the actual result.
    assert grant['localAccepted'] and delivered == [granted.read_bytes()]
    with openHby(name=names['holder'], base=base, temp=False, bran=PASSCODE,
                 version=Vrsn_1_0) as hby:
        rgy = Regery(hby=hby, name=hby.name, base=base, temp=False)
        noter = Noter(name=hby.name, base=base, temp=False)
        try:
            exc = exchanging.Exchanger(hby, handlers=[])
            protocoling.loadHandlers(hby, exc, Notifier(hby, noter=noter))
            Parser(version=Vrsn_1_0, kvy=hby.kvy, tvy=rgy.tvy,
                   vry=Verifier(hby=hby, reger=rgy.reger), exc=exc).parse(
                       ims=bytearray(granted.read_bytes()))
            assert exc.complete(grant['exchange'])
            event = hby.db.exns.get((grant['exchange'],))
            assert event.sad['p'] == agree['exchange']
            assert event.sad['e']['acdc']['d'] == cred.said
            exchanging.verify(hby, event)
            assert rgy.reger.saved.get((cred.said,)) is None
        finally:
            noter.close()
            rgy.close()

    admitted = tmp_path / 'admit.cesr'
    wrong = tmp_path / 'wrong-admit.cesr'
    assert 'another recipient' in invoke('issuer', 'admit', '--said', grant['exchange'],
        '--output', str(wrong), okay=False)
    assert not wrong.exists()
    missing = tmp_path / 'missing-schema-admit.cesr'
    # Grant authentication and TEL evidence alone do not satisfy credential
    # verification: this recipient has deliberately never imported its schema.
    assert 'verified credential dependencies' in invoke('holder', 'admit',
        '--said', grant['exchange'], '--input', str(granted), '--output', str(missing),
        '--timeout', '0.1', okay=False)
    assert not missing.exists()
    with openHby(name=names['holder'], base=base, temp=False, bran=PASSCODE,
                 version=Vrsn_1_0) as hby:
        rgy = Regery(hby=hby, name=hby.name, base=base, temp=False)
        try:
            exchanging.verify(hby, hby.db.exns.get((grant['exchange'],)))
            assert rgy.reger.saved.get((cred.said,)) is None
            assert rgy.reger.mse.get((cred.said,)) is not None
            assert hby.db.erpy.get((grant['exchange'],)) is None
            seeder.seedSchema(hby.db)
        finally:
            rgy.close()
    admit = invoke('holder', 'admit', '--said', grant['exchange'],
        '--input', str(granted), '--output', str(admitted))
    assert admit['localAccepted'] and admit['recipient'] == prefixes['issuer']

    with openHby(name=names['issuer'], base=base, temp=False, bran=PASSCODE,
                 version=Vrsn_1_0) as hby:
        noter = Noter(name=hby.name, base=base, temp=False)
        try:
            exc = exchanging.Exchanger(hby, handlers=[])
            protocoling.loadHandlers(hby, exc, Notifier(hby, noter=noter))
            Parser(version=Vrsn_1_0, kvy=hby.kvy, exc=exc).parse(
                ims=bytearray(admitted.read_bytes()))
            assert exc.complete(admit['exchange'])
            assert hby.db.exns.get((admit['exchange'],)).sad['p'] == grant['exchange']
        finally:
            noter.close()
        # Inspect the same authenticated thread without opening another CLI owner.
        owner = SimpleNamespace(hby=hby, hab=hby.habByName('issuer'))
        with pytest.raises(ConfigurationError, match='recipient agreement'):
            GrantDoer.acceptedAgreement(owner, agree['exchange'], prefixes['issuer'], cred)
        with pytest.raises(ConfigurationError, match='credential offer'):
            GrantDoer.acceptedAgreement(owner, agree['exchange'], prefixes['holder'],
                                       SimpleNamespace(said=prefixes['holder'], schema=schema))
        with pytest.raises(ConfigurationError, match='recipient agreement'):
            GrantDoer.acceptedAgreement(owner, offer['exchange'], prefixes['holder'], cred)
