"""JSON assertions, webhook capture and process readiness; no KERI APIs."""
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import sys
import time
from urllib.request import urlopen


def json_file(path):
    """Return decoded JSON from path or its last JSON-object transcript line.

    path names a UTF-8 artifact. File, JSON and absent-object errors propagate;
    no protocol data or database is inspected or modified.
    """
    text = Path(path).read_text()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.startswith('{')][-1]


def field(value, path):
    """Return the nested item selected by dotted path in decoded value.

    Numeric components index lists; other components name dictionary keys.
    Missing keys, invalid indices and unsupported shapes raise normally.
    """
    for key in path.split('.'):
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


if __name__ == '__main__':
    operation, *args = sys.argv[1:]
    if operation == 'field':
        value = field(json_file(args[0]), args[1])
        print(json.dumps(value) if isinstance(value, (dict, list, bool)) else value)
    elif operation == 'ports':
        sockets, ports = [], {}
        for role in args:
            sock = socket.socket()
            sock.bind(('127.0.0.1', 0))
            sockets.append(sock)
            ports[role] = sock.getsockname()[1]
        print(json.dumps(ports))
        for sock in sockets:
            sock.close()
    elif operation == 'ready':
        deadline = time.monotonic() + float(args[1])
        while True:
            try:
                if urlopen(args[0], timeout=0.3).status == 200:
                    break
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise SystemExit('readiness deadline exceeded: ' + args[0])
            time.sleep(0.1)
    elif operation == 'tcp-ready':
        host, port, seconds = args
        deadline = time.monotonic() + float(seconds)
        while True:
            try:
                socket.create_connection((host, int(port)), 0.3).close()
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise SystemExit('TCP readiness deadline exceeded')
                time.sleep(0.1)
    elif operation == 'config':
        output, issuer, schema, observer, hook = args
        Path(output).write_text(json.dumps(dict(issuers=[issuer], schemas=[schema],
            fields=dict(status='a/status/value', private='a/private/value', note='a/note/value'),
            observer=observer, webhook=hook, maximumAge=3, timeout=2)))
    elif operation == 'attributes':
        output, *nonces = args
        Path(output).write_text(json.dumps(dict(d='', u=nonces[0],
            status=dict(d='', u=nonces[1], value='authorized'),
            private=dict(d='', u=nonces[2], value='full-stage-only'),
            note=dict(d='', u=nonces[3], value=None))))
    elif operation == 'plan':
        output, schema, mode = args
        Path(output).write_text(json.dumps([[[schema, '/', ['a/status/'] if mode == 'partial' else (['a/private/value'] if mode == 'withheld' else ['a/status/value', 'a/private/value', 'a/note/value'])]]]))
    elif operation == 'hook':
        port, output = int(args[0]), Path(args[1])

        class Hook(BaseHTTPRequestHandler):
            """Capture a public webhook payload and acknowledge receipt."""
            def do_GET(self):
                """Answer this HTTP GET with status 200 and no body.

                The request comes from BaseHTTPRequestHandler state. Return None;
                connection errors propagate. No credential state is accessed.
                """
                self.send_response(200)
                self.end_headers()

            def do_POST(self):
                """Append this request's JSON body to the configured capture file.

                Read Content-Length from request headers, return HTTP 200 after
                writing, and return None. Missing/invalid body or file/network
                errors propagate so a failed capture cannot acknowledge success.
                """
                value = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                with output.open('a') as stream:
                    stream.write(json.dumps(value, sort_keys=True) + '\n')
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"received":true}')

            def log_message(self, *args):
                """Suppress the superclass request log and return None.

                args are the unused format/message arguments. This override does
                not suppress capture errors or inspect credential state.
                """
                pass

        ThreadingHTTPServer(('127.0.0.1', port), Hook).serve_forever()
    elif operation == 'assert-hooks':
        path, count, credential, presenter = args
        values = [json.loads(line) for line in Path(path).read_text().splitlines()]
        assert len(values) == int(count), values
        for index, value in enumerate(values):
            assert value['credential'] == credential and value['presenter'] == presenter, value
            assert value['decision'] == 'accepted' and value['business']['status'] == 'authorized', value
            if index == 0:
                assert value['business'] == dict(status='authorized', private=None, note=None), value
                assert value['disclosure']['private'] == value['disclosure']['note'] == 'undisclosed', value
                assert 'full-stage-only' not in json.dumps(value), value
            else:
                assert value['business'] == dict(status='authorized', private='full-stage-only', note=None), value
                assert value['disclosure']['note'] == 'disclosed_null', value
    elif operation == 'assert-json':
        path, dotted, expected = args
        assert field(json_file(path), dotted) == json.loads(expected), json_file(path)
    elif operation == 'assert-no-secret':
        custody, *paths = args
        secret = json_file(custody)['salt']
        for path in paths:
            assert secret not in Path(path).read_text(), 'registry salt appeared in public output'
    elif operation == 'hash':
        print(hashlib.sha256(Path(args[0]).read_bytes()).hexdigest())
    elif operation == 'first-hook':
        Path(args[1]).write_text(Path(args[0]).read_text().splitlines()[0] + '\n')
    elif operation == 'manifest':
        root, scenario, transport, *roles = args
        folder = Path(root)
        value = dict(scenario=scenario, transport=transport, protocol=2,
            topology=dict(witnesses=3, quorum=2), roles={}, artifacts=json_file('/artifacts/manifest.json'))
        for role in roles:
            value['roles'][role] = dict(aid=(folder / (role + '.aid')).read_text().strip())
        for path in folder.glob('*.ref'):
            value[path.stem] = path.read_text().strip()
        value['versions'] = dict(kli=(folder / 'kli-version.txt').read_text().strip(),
            dolly=(folder / 'dolly-version.txt').read_text().strip())
        value['authorizationProfile'] = (folder / 'authorization.txt').read_text().strip()
        value['actors'] = dict(credentialIssuer=value['roles']['issuer']['aid'],
            credentialRecipient=value['roles']['holder']['aid'], holder=value['roles']['holder']['aid'],
            presenter=value['roles'].get('presenter', value['roles']['holder'])['aid'],
            verifier=value['roles']['dolly']['aid'],
            registryStateDiscloser=value['roles'][(folder / 'discloser-role.txt').read_text().strip()]['aid'])
        value['expectedFields'] = dict(partial=['status'], fuller=['status', 'private', 'note'])
        value['publicEvidence'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in folder.glob('*.cesr')}
        value['hooks'] = [json.loads(line) for line in (folder / 'hooks.jsonl').read_text().splitlines()]
        value['result'] = 'passed'
        (folder / 'result.json').write_text(json.dumps(value, indent=2) + '\n')
    else:
        raise SystemExit('unknown JSON/supervision helper operation')
