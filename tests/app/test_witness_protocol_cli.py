"""Installed witness protocol selection follows the persisted identity version."""
import time
from keri import Vrsn_1_0, Vrsn_2_0, Kinds
from keri.app import openHby
from keri.core import Parser, SerderKERI


def test_installed_witness_receipts_preserve_existing_protocol():
    """Exercise the installed witness HTTP parser for real v1 and v2 inceptions.

    No arguments/return. Each case reopens an existing persistent witness through
    KLI, submits an actual signed inception, and verifies its returned receipt
    with the issuer core processor. Old v1 setup returns 202 without a receipt;
    both supported versions must return 200 and one verified witness signature.
    """
    import os
    import socket
    import subprocess
    import sys
    import uuid
    from urllib.request import Request, urlopen
    for version in (Vrsn_1_0, Vrsn_2_0):
        name = 'witness-version-' + uuid.uuid4().hex
        base = 'witness-protocol-cli'
        with openHby(name=name, base=base, temp=False, version=version,
                     bran='0123456789abcdefghijk') as witness:
            whab = witness.makeHab(name='witness', transferable=False,
                                   version=version, kind=Kinds.json)
            wit = whab.pre
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        sock.close()
        command = [sys.executable, '-m', 'keri.cli.kli', 'witness', 'start',
            '--name', name, '--base', base, '-a', 'witness', '--no-prompt',
            '--http', str(port), '--tcp', '0']
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env=dict(os.environ, KLI_KEYSTORE_PASSCODE='0123456789abcdefghijk'))
        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    if urlopen(f'http://127.0.0.1:{port}/oobi', timeout=0.2).status == 200:
                        break
                except OSError:
                    pass
                assert process.poll() is None and time.monotonic() < deadline
                time.sleep(0.05)
            with openHby(name='receipt-issuer-' + uuid.uuid4().hex, version=version) as issuer:
                hab = issuer.makeHab(name='issuer', wits=[wit], toad=1,
                                     version=version, kind=Kinds.json)
                raw = hab.msgOwnEvent(sn=0, framed=True, gvrsn=version)
                event = SerderKERI(raw=raw)
                request = Request(f'http://127.0.0.1:{port}/receipts', data=event.raw,
                    headers={'Content-Type': 'application/cesr',
                             'CESR-ATTACHMENT': bytes(raw[event.size:]).decode('ascii')})
                with urlopen(request, timeout=3) as response:
                    assert response.status == 200
                    receipt = response.read()
                Parser(version=version).parseOne(ims=bytearray(receipt), kvy=issuer.kvy)
                assert len(issuer.db.wigs.get((hab.pre, event.said))) == 1
                assert SerderKERI(raw=receipt).pvrsn == version
        finally:
            process.terminate()
            output = process.communicate(timeout=5)[0]
            assert process.returncode in (0, -15, -2), output.decode()
