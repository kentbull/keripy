"""Actual released peer binaries against the current Dolly HTTP/webhook path.

Run scripts/v2-e2e/legacy-peers/check.sh: peers are isolated Docker processes,
not current KERIpy with a version flag. Ordinary unit runs do not start Docker.
"""
import json
import os
from pathlib import Path
import urllib.request
from urllib.parse import urljoin

import falcon
import pytest
from hio.base import doing
from hio.core import http, tcp

from keri import Vrsn_1_0
from keri.app.habbing import openHby
from keri.app.dolly.serving import Context as Dolly
from keri.core import Schemer


pytestmark = pytest.mark.skipif(os.environ.get('KERI_LEGACY_PEER_MATRIX') != '1',
    reason='isolated released peers required: scripts/v2-e2e/legacy-peers/check.sh')


def peer_request(source, path, data=None):
    request = urllib.request.Request(urljoin(source, path),
        data=None if data is None else json.dumps(data).encode(),
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


@pytest.mark.parametrize('version', ['1.2.14', '1.3.6'])
def test_released_legacy_issuer_current_source_and_dolly_webhook(version):
    source = os.environ['LEGACY_PEER_' + version.replace('.', '_') + '_URL']
    callbackHost = os.environ['LEGACY_MATRIX_CALLBACK_HOST']
    profile = peer_request(source, 'profile')
    assert profile['version'] == profile['distribution'] == version
    assert profile['python'] == '3.12.15'
    assert '/site-packages/keri/' in profile['module']
    assert '/workspace/' not in profile['module']
    scripts = Path(__file__).resolve().parents[2] / 'scripts/v2-e2e/legacy-peers'
    normalize = lambda name: name.lower().replace('_', '-')
    pinned = dict(line.split('==') for line in (scripts / f'requirements-{version}.lock').read_text().splitlines())
    pinned['keri'] = version
    assert {normalize(k): v for k, v in profile['dependencies'].items()} == {
        normalize(k): v for k, v in pinned.items()}
    assert profile['sourceSha256'] == json.loads((scripts / 'profiles.json').read_text())[version]['sha256']
    hooks = []

    class Hook:
        def on_post(self, req, rep):
            hooks.append(req.media)
            rep.media = {'received': True}

    with openHby(name='released-peer-' + version, version=Vrsn_1_0) as verifier:
        hab = verifier.makeHab(name='dolly', version=Vrsn_1_0)
        hookApp = falcon.App()
        hookApp.add_route('/hook', Hook())
        hook = http.Server(servant=tcp.Server(ha=('127.0.0.1', 0)), app=hookApp)
        ingress = dolly = None
        try:
            assert hook.reopen()
            hook.servant.eha = hook.servant.ha
            # Reserve ingress before asking the released peer to create a Grant
            # addressed to this real disclosee and post future source replies.
            ingress = http.Server(servant=tcp.Server(ha=('0.0.0.0', 0)), app=falcon.App())
            assert ingress.reopen()
            ingress.servant.eha = ingress.servant.ha
            callback = f'http://{callbackHost}:{ingress.servant.ha[1]}/ingest'
            artifacts = peer_request(source, 'artifacts', {
                'recipient': hab.pre, 'source': source, 'callback': callback})
            assert artifacts['version'] == version
            assert artifacts['issuer'] == profile['issuer']
            schema = Schemer(sed=artifacts['schema'])
            verifier.db.schema.pin((schema.said,), schema)  # public schema only
            dolly = Dolly(verifier, hab, issuers=[artifacts['issuer']],
                schemas=[schema.said], fields={'status': 'a/status'}, required=['status'],
                observer=source, legacySources=[artifacts['issuer']],
                webhook=f'http://127.0.0.1:{hook.servant.ha[1]}/hook')
            ingress.app = dolly.app
            doers = [http.ServerDoer(server=hook), http.ServerDoer(server=ingress), dolly]
            pendingChecked, revoked = [], []

            def phases(tymth=None, tock=0.01, **kwa):
                yield tock
                peer_request(source, 'control', {'allowReplies': False,
                    'sendBootstrap': True, 'sendGrant': True})
                while len(peer_request(source, 'profile')['responses']) < 2:
                    yield 0.1
                started = tymth()
                while tymth() < started + 1.2:
                    yield tock
                assert dolly.legacy.reger.saved.get((artifacts['credential'],)) is not None
                submission = dolly.db.submissions.get((artifacts['grant'],))
                assert submission.state == 'pending' and not submission.delivered
                assert hooks == []  # historical issuance is not current standing
                pendingChecked.append(True)
                peer_request(source, 'control', {'allowReplies': True})
                # The unmodified released automatic route emits replay and a
                # registry TSN, but its vcState(vcpre=) typo omits credential TSN.
                while len(peer_request(source, 'profile')['responses']) < 4:
                    yield 0.1
                assert hooks == []
                assert dolly.db.submissions.get((artifacts['grant'],)).state == 'pending'
                peer_request(source, 'control', {
                    'allowReplies': True, 'completeCredentialNotice': True})
                while not hooks:
                    yield tock
                assert len(hooks) == 1
                assert dolly.db.observed.get(('legacy', artifacts['credential'])).head == artifacts['issuance']
                peer_request(source, 'control', {'allowReplies': True, 'sendGrant': True})
                while len(peer_request(source, 'profile')['responses']) < 6:
                    yield 0.1
                started = tymth()
                while tymth() < started + 0.3:
                    yield tock
                assert len(hooks) == 1  # exact released Grant replay is idempotent
                result = peer_request(source, 'revoke', {})
                while len(peer_request(source, 'profile')['responses']) < 10:
                    yield 0.1
                revoked.append(result)
                while True:
                    yield tock

            doers.append(doing.doify(phases))
            # One server lifetime: peer callback sockets are never invalidated
            # by restarting the receiver's event loop between proof phases.
            doing.Doist(real=True, tock=0.01, limit=8.5).do(doers=doers)
            assert pendingChecked == [True]
            assert len(revoked) == 1
            submission = dolly.db.submissions.get((artifacts['grant'],))
            state = peer_request(source, 'profile')
            assert {'tels', 'tsn'} <= set(state['queries'])
            assert state['responses'], {k: state[k] for k in ('queries', 'cues', 'outbox', 'inflight')}
            assert all(code == 202 for code in state['responses'])
            assert len(hooks) == 1, {'submission': vars(submission), 'source': state}
            payload = hooks[0]
            assert payload['schema'] == 'dolly.accepted-credential/v1'
            assert payload['protocol'] == 1 and payload['standing'] == 'issued'
            assert payload['credential'] == artifacts['credential']
            assert payload['grant'] == artifacts['grant']
            assert payload['business'] == {'status': 'authorized'}
            assert payload['disclosure'] == {'status': 'disclosed'}
            assert submission.delivered
            assert state['credentialTsnAdapterCalls'] == 1
            assert len(state['responses']) == 10
            assert dolly.db.observed.get(('legacy', artifacts['credential'])).head == revoked[0]['revocation']
            rejected = dolly.db.submissions.get((revoked[0]['grant'],))
            assert rejected.state == 'rejected' and not rejected.delivered
            assert rejected.reason == 'credential is not currently issued'
            assert len(hooks) == 1
        finally:
            if ingress is not None:
                ingress.close()
            hook.close()
            if dolly is not None:
                dolly.close()
