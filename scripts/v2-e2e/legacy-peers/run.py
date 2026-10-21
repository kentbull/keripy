"""Wait for the two actual released peers, then run the socket matrix."""
import os
import subprocess
import sys
import time
import urllib.request

for version in ('1.2.14', '1.3.6'):
    url = os.environ['LEGACY_PEER_' + version.replace('.', '_') + '_URL'] + 'profile'
    deadline = time.monotonic() + 20
    while True:
        try:
            with urllib.request.urlopen(url, timeout=1):
                break
        except OSError:
            if time.monotonic() >= deadline:
                raise RuntimeError(f'released peer {version} never became healthy')
            time.sleep(0.1)
raise SystemExit(subprocess.call([sys.executable, '-m', 'pytest', '-p', 'no:cacheprovider',
                                  '-q', 'tests/app/test_legacy_peer_profiles.py']))
