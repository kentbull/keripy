"""Independent KLI processes, witnessed anchors, observer evidence and webhooks.

The test seeds only local identities and public signed endpoint inputs. Every
credential/registry acceptance is performed by the production CLI or services.
Run through scripts/v2-e2e/check.sh so persistent KLI paths use a named volume.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib import error, request
import uuid

from keri import Vrsn_2_0
from keri.app import openHby
from keri.app.dolly.serving import DollyBaser
from keri.app.registrar.serving import signedQuery
from keri.core import Noncer, SerderACDC
from keri.db import openLMDB


PASSCODE = '0123456789abcdefghijk'  # public test fixture, never an operator secret
HOOK = '''
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
class Hook(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers['Content-Length']))
        data = json.loads(raw)
        with open(sys.argv[2], 'a') as stream:
            stream.write(json.dumps(data) + '\\n')
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{}')
    def log_message(self, *args): pass
HTTPServer(('127.0.0.1', int(sys.argv[1])), Hook).serve_forever()
'''


def port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def eventually(predicate, *, timeout=15):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            result = predicate()
            if result:
                return result
        except (OSError, ValueError, error.URLError) as exception:
            last = exception
        time.sleep(0.05)
    raise AssertionError(f'condition did not complete: {last}')


class Processes:
    def __init__(self, root, base, names):
        self.root, self.base, self.names = root, base, names
        self.env = dict(os.environ, KLI_KEYSTORE_PASSCODE=PASSCODE,
                        PYTHONUNBUFFERED='1', PYTHONDONTWRITEBYTECODE='1', DEBUG_KLI='1')
        self.running = []

    def command(self, role, *arguments):
        return [sys.executable, '-m', 'keri.cli.kli', *arguments,
                '--name', self.names[role], '--base', self.base]

    def invoke(self, role, *arguments, timeout=25):
        print(f"{role}: {' '.join(arguments[:3])}", flush=True)
        result = subprocess.run(self.command(role, *arguments), env=self.env,
            capture_output=True, text=True, timeout=timeout)
        assert result.returncode == 0, result.stdout + result.stderr
        assert 'ERR:' not in result.stdout, result.stdout + result.stderr
        assert 'Traceback' not in result.stderr, result.stdout + result.stderr
        return [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]

    def start(self, role, *arguments, command=None):
        log = (self.root / (role + '-' + uuid.uuid4().hex + '.log')).open('w+')
        process = subprocess.Popen(command or self.command(role, *arguments),
            env=self.env, stdout=log, stderr=subprocess.STDOUT)
        self.running.append((process, log))
        return process

    def exportKel(self, role, path):
        result = subprocess.run(self.command(role, 'export', '-a', role), env=self.env,
            capture_output=True, timeout=20)
        assert result.returncode == 0 and b'ERR:' not in result.stdout, result.stderr
        path.write_bytes(result.stdout)

    def stop(self, process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def close(self):
        for process, log in reversed(self.running):
            self.stop(process)
            log.close()


def http(url, raw=None):
    try:
        with request.urlopen(request.Request(url, data=raw,
            headers={'Content-Type': 'application/cesr'}), timeout=3) as response:
            return response.status, {key.lower(): value for key, value in response.headers.items()}, response.read()
    except error.HTTPError as response:
        return response.code, {key.lower(): value for key, value in response.headers.items()}, response.read()


def test_independent_cli_witness_holder_observer_dolly_restart_and_revocation(tmp_path):
    base = 'native-e2e-' + uuid.uuid4().hex
    witnesses = ('witness1', 'witness2', 'witness3')
    roles = (*witnesses, 'issuer', 'holder', 'registrar', 'observer', 'dolly')
    names = {role: role + '-' + uuid.uuid4().hex for role in roles}
    prefixes, kels = {}, {}
    ports = {role: port() for role in (*roles, 'hook', *(role + '-tcp' for role in witnesses))}
    urls = {role: f'http://127.0.0.1:{value}/' for role, value in ports.items()}
    processes = Processes(tmp_path, base, names)
    # Independent identities are ordinary local fixture setup. No receiver
    # credential, TEL, accepted index or wallet admission is written here.
    witnessKels, witnessEvidence = bytearray(), bytearray()
    for role in witnesses:
        with openHby(name=names[role], base=base, temp=False, bran=PASSCODE,
                     version=Vrsn_2_0) as witness:
            whab = witness.makeHab(name=role, transferable=False, version=Vrsn_2_0)
            prefixes[role] = whab.pre
            witnessKel = bytes(whab.replay(gvrsn=Vrsn_2_0))
            witnessKels.extend(witnessKel)
            witnessEvidence.extend(witnessKel + whab.makeLocScheme(url=urls[role],
                version=Vrsn_2_0, gvrsn=Vrsn_2_0))
    for role in roles[3:]:
        with openHby(name=names[role], base=base, temp=False, bran=PASSCODE,
                     version=Vrsn_2_0) as hby:
            kwargs = dict(wits=[prefixes[wit] for wit in witnesses], toad=2) if role in ('issuer', 'holder') else {}
            hab = hby.makeHab(name=role, version=Vrsn_2_0, **kwargs)
            prefixes[role] = hab.pre
            if role in ('issuer', 'holder'):
                hby.psr.parse(ims=bytearray(witnessEvidence))
            kels[role] = tmp_path / (role + '.kel')
            kels[role].write_bytes(hab.replay(gvrsn=Vrsn_2_0))
    bootstrap = tmp_path / 'public-bootstrap.cesr'
    bootstrap.write_bytes(witnessKels + b''.join(path.read_bytes() for path in kels.values()))
    receivedFile = tmp_path / 'webhooks.jsonl'

    def received():
        return [json.loads(line) for line in receivedFile.read_text().splitlines()] if receivedFile.exists() else []

    def delivered(grant):
        # Wait for the sender's persisted 2xx result before a quiescent restart.
        # Seeing a request in the hook file alone is not sender acknowledgement.
        with openLMDB(cls=DollyBaser, name=names['dolly'], base=base, temp=False) as db:
            record = db.submissions.get((grant,))
            return record is not None and record.delivered

    def signed(role, route, query=None):
        with openHby(name=names[role], base=base, temp=False, bran=PASSCODE,
                     version=Vrsn_2_0) as hby:
            return signedQuery(hby.habByName(role), route, query)

    def publish(path):
        status, _, body = http(urls['registrar'] + 'ingest',
            signed('issuer', 'tels/publish', {'stream': path.read_bytes().decode()}))
        assert status == 200, body
        result = json.loads(body)
        assert not result['pending'] and not result['rejected'], result

    try:
        for role in witnesses:
            processes.start(role, 'witness', 'start', '-a', role, '--no-prompt',
                            '-H', str(ports[role]), '-T', str(ports[role + '-tcp']))
            eventually(lambda: http(urls[role] + 'oobi')[0] == 200)
        # Use the existing synchronous receipt endpoint for inception itself.
        processes.invoke('issuer', 'witness', 'submit', '-a', 'issuer', '--receipt-endpoint')
        processes.invoke('holder', 'witness', 'submit', '-a', 'holder', '--receipt-endpoint')
        registry = processes.invoke('issuer', 'vc', 'registry', 'incept', '--native',
            '-a', 'issuer', '-r', 'r', '--timeout', '8')[0]['registry']
        attributes = {'d': '', 'u': Noncer().qb64,
            'status': {'d': '', 'u': Noncer().qb64, 'value': 'authorized'},
            'private': {'d': '', 'u': Noncer().qb64, 'value': 'full-stage-only'},
            'note': {'d': '', 'u': Noncer().qb64, 'value': None}}
        issued = processes.invoke('issuer', 'vc', 'create', '--native', '-a', 'issuer',
            '-r', 'r', '--data', json.dumps(attributes), '--timeout', '8')[0]
        said = issued['credential']
        rawCredential, public = tmp_path / 'credential.json', tmp_path / 'public.cesr'
        processes.invoke('issuer', 'vc', 'export', '--native', '-a', 'issuer', '-r', 'r',
            '--said', said, '--output', str(rawCredential))
        processes.invoke('issuer', 'vc', 'export', '--native', '-a', 'issuer', '-r', 'r',
            '--said', said, '--kels', '--tels', '--output', str(public))
        credential = SerderACDC(raw=rawCredential.read_bytes())
        for role in ('issuer', 'holder'):
            processes.exportKel(role, kels[role])
        bootstrap.write_bytes(witnessKels + b''.join(path.read_bytes() for path in kels.values()))
        registrar = processes.start('registrar', 'registrar', 'start',
            '--publisher', prefixes['issuer'], '--observer', prefixes['observer'],
            '--kel', str(bootstrap), '--port', str(ports['registrar']), '--no-prompt')
        eventually(lambda: http(urls['registrar'] + 'health')[0] == 200)
        publish(public)
        observerArgs = ('observer', 'start', '-a', 'observer', '--registrar', urls['registrar'],
            '--reader', prefixes['holder'], '--reader', prefixes['dolly'], '--kel', str(bootstrap),
            '--interval', '0.2', '--maximum-age', '2', '--timeout', '1',
            '--port', str(ports['observer']), '--no-prompt')
        observer = processes.start('observer', *observerArgs)
        def query():
            return signed('dolly', 'tels', {'i': registry})
        try:
            eventually(lambda: http(urls['observer'], query())[0] == 200)
        except AssertionError:
            raise AssertionError(http(urls['observer'], query())) from None
        policy = tmp_path / 'dolly.json'
        policy.write_text(json.dumps(dict(issuers=[prefixes['issuer']],
            schemas=[credential.schema['$id']], fields={'status': 'a/status/value',
            'private': 'a/private/value', 'note': 'a/note/value'}, required=['status'],
            observer=urls['observer'], webhook=urls['hook'] + 'hook', maximumAge=2, timeout=1)))
        dollyArgs = ('dolly', 'start', '--alias', 'dolly', '--config', str(policy),
            '--kel', str(bootstrap), '--port', str(ports['dolly']), '--no-prompt')
        processes.start('hook', command=[sys.executable, '-u', '-c', HOOK,
            str(ports['hook']), str(receivedFile)])
        dolly = processes.start('dolly', *dollyArgs)
        eventually(lambda: http(urls['dolly'] + 'health')[0] == 200)
        holderArgs = ('ipex', 'receive', '--native', '-a', 'holder',
            '--observer', urls['observer'], '--registry', registry, '--port', str(ports['holder']))
        holder = processes.start('holder', *holderArgs)
        eventually(lambda: http(urls['holder'] + 'ingest', b'')[0] == 202)
        granted = tmp_path / 'grant.cesr'
        grant = processes.invoke('issuer', 'ipex', 'grant', '--native', '-a', 'issuer',
            '-r', prefixes['holder'], '-s', said, '--endpoint', urls['holder'] + 'ingest',
            '--output', str(granted))[0]['exchange']
        processes.stop(holder)
        admitted = processes.invoke('holder', 'ipex', 'admit', '--native', '-a', 'holder',
            '-s', grant, '--observer', urls['observer'], '--registry', registry)[0]
        assert admitted['admitted']
        inventory = processes.invoke('holder', 'vc', 'list', '--native', '-a', 'holder')
        assert any(item['grant'] == grant for item in inventory)
        partial = processes.invoke('holder', 'ipex', 'grant', '--native', '-a', 'holder',
            '-r', prefixes['dolly'], '-s', said, '--from-grant', grant,
            '--disclose', 'a/status/', '--endpoint', urls['dolly'] + 'ingest')[0]['exchange']
        eventually(lambda: len(received()) == 1)
        eventually(lambda: delivered(partial))
        first = received()[0]
        assert first['grant'] == partial and first['credential'] == said
        assert first['business'] == {'status': 'authorized', 'private': None, 'note': None}
        assert first['disclosure']['private'] == first['disclosure']['note'] == 'undisclosed'
        assert 'full-stage-only' not in json.dumps(first)
        # All three restart using their own persistent stores; the holder had
        # already reopened for admission and now reopens for presentation.
        processes.stop(observer)
        processes.stop(dolly)
        observer = processes.start('observer', *observerArgs)
        dolly = processes.start('dolly', *dollyArgs)
        eventually(lambda: http(urls['dolly'] + 'health')[0] == 200)
        eventually(lambda: http(urls['observer'], query())[0] == 200)
        full = processes.invoke('holder', 'ipex', 'grant', '--native', '-a', 'holder',
            '-r', prefixes['dolly'], '-s', said, '--from-grant', grant,
            '--endpoint', urls['dolly'] + 'ingest')[0]['exchange']
        eventually(lambda: len(received()) == 2)
        eventually(lambda: delivered(full))
        second = received()[1]
        assert partial != full and second['grant'] == full and second['credential'] == said
        assert second['business'] == {'status': 'authorized', 'private': 'full-stage-only', 'note': None}
        assert second['disclosure']['note'] == 'disclosed_null'
        revoked = processes.invoke('issuer', 'vc', 'revoke', '--native', '-a', 'issuer',
            '-r', 'r', '--said', said, '--unblinded', '--timeout', '8')[0]
        latest = tmp_path / 'revoked-public.cesr'
        processes.invoke('issuer', 'vc', 'export', '--native', '-a', 'issuer', '-r', 'r',
            '--said', said, '--kels', '--tels', '--output', str(latest))
        publish(latest)
        # Observe the new head before any presentation or verifier query.
        def currentHead():
            status, headers, _ = http(urls['observer'], query())
            return status == 200 and headers.get('observer-registry-head') == revoked['update']
        eventually(currentHead)
        time.sleep(2.1)  # require Dolly to obtain a new observation before this presentation
        rejected = processes.invoke('holder', 'ipex', 'grant', '--native', '-a', 'holder',
            '-r', prefixes['dolly'], '-s', said, '--from-grant', grant,
            '--endpoint', urls['dolly'] + 'ingest')[0]['exchange']
        time.sleep(1.3)
        assert len(received()) == 2, received()
        assert rejected not in {item['grant'] for item in received()}
        processes.stop(registrar)
        time.sleep(2.2)
        assert http(urls['observer'], query())[0] == 503
        assert len(received()) == 2
    except BaseException:
        for process, log in processes.running:
            log.flush()
            log.seek(0)
            print(f'process {process.pid}, exit={process.poll()}:\n{log.read()}', flush=True)
        raise
    finally:
        processes.close()
