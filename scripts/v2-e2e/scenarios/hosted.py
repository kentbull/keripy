"""Hosted-provider HTTP provisioning and private test authorization adapter.

No accepted protocol tables are written. Witness introductions go through KLI
verification; registration uses the actual KLI witness authenticate command.
"""
import json
from pathlib import Path
import sys
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

import pyotp
from keri import Vrsn_2_0
from keri.core import Parser
from keri.help import helping


def provision(root, role, aid):
    """Provision one witness per independent process for the existing actor AID.

    Parameters:
        root: scenario directory containing public listener ports.
        role: actor label used for public output filenames.
        aid: already incepted actor AID, before adding hosted witnesses.
    Writes public OOBIs/KEL frames and the provider mapping; core verification
    occurs separately when KLI imports these bytes. No private seed is returned.
    """
    ports = json.loads((root / 'ports.json').read_text())
    records, introductions, kels = [], bytearray(), bytearray()
    for name in ('witness1', 'witness2', 'witness3'):
        req = Request(f'http://127.0.0.1:{ports[name + "boot"]}/witnesses',
                      data=json.dumps({'aid': aid}).encode(),
                      headers={'Content-Type': 'application/json'})
        with urlopen(req, timeout=10) as response:
            record = json.load(response)
        assert record['cid'] == aid and len(record['oobis']) == 1
        with urlopen(record['oobis'][0], timeout=10) as response:
            raw = response.read()
        introductions.extend(raw)
        # Keep exact signed frames, excluding endpoint replies from the service
        # KEL bootstrap. Parsing here selects bytes; it does not authenticate.
        ims = bytearray(raw)
        while ims:
            before = bytes(ims)
            dom = Parser(version=Vrsn_2_0).parseOne(ims=ims, processive=False)
            if dom is None or dom.serder is None or len(ims) >= len(before):
                raise ValueError('incomplete witness introduction')
            if dom.serder.ilk in ('icp', 'rot', 'ixn', 'rct'):
                kels.extend(before[:len(before) - len(ims)])
        records.append({**record, 'process': name})
    (root / f'{role}-hosted.json').write_text(json.dumps(records, indent=2))
    (root / f'{role}-witnesses.cesr').write_bytes(introductions)
    with (root / 'witnesses.cesr').open('ab') as output:
        output.write(introductions)
    with (root / 'witness-kels.cesr').open('ab') as output:
        output.write(kels)


def authorizations(root, role):
    """Generate short-lived headers from owner-only KLI registration outputs.

    Parameters:
        root: scenario directory; role: actor owning the private TOTP URL files.
    Writes only a private per-command header map. This test adapter is not a
    wallet custody subsystem or an interoperable secret provisioning protocol.
    """
    records = json.loads((root / f'{role}-hosted.json').read_text())
    values = {}
    for record in records:
        path = root / 'private' / f'{role}-{record["eid"]}.txt'
        url = next(line for line in path.read_text().splitlines() if line.startswith('otpauth://'))
        seed = parse_qs(urlsplit(url).query)['secret'][0]
        values[record['eid']] = f'{pyotp.TOTP(seed).now()}#{helping.nowIso8601()}'
    (root / 'private' / f'{role}-auth.json').write_text(json.dumps(values))


if __name__ == '__main__':
    operation, folder, role, *args = sys.argv[1:]
    root = Path(folder)
    if operation == 'provision':
        provision(root, role, args[0])
    elif operation == 'auth':
        authorizations(root, role)
    else:
        raise SystemExit('unknown hosted adapter operation')
