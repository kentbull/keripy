"""Install an authenticated released peer, never the current checkout."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import urllib.request

version = sys.argv[1]
root = Path(__file__).parent
profile = json.loads((root / 'profiles.json').read_text())[version]
archive = Path('/tmp') / f'keri-{version}.tar.gz'
raw = urllib.request.urlopen(profile['url']).read()
if hashlib.sha256(raw).hexdigest() != profile['sha256']:
    raise SystemExit('released source distribution SHA-256 mismatch')
archive.write_bytes(raw)
subprocess.run([sys.executable, '-m', 'pip', 'install', '--no-build-isolation',
                '-c', str(root / f'requirements-{version}.lock'), str(archive)], check=True)
