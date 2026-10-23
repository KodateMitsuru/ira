#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""CTest runtime fixtures. Compilation belongs to CMake targets."""
from pathlib import Path
import os
import subprocess
import sys

mode, executable, directory, *extra = sys.argv[1:]
work = Path(directory).resolve()
work.mkdir(parents=True, exist_ok=True)
if mode in ('namespace', 'credentials', 'integration'):
    flags = ['--user', '--map-root-user', '--mount'] if mode == 'namespace' else ['--user', '--map-auto', '--map-root-user']
    if subprocess.run(['unshare', *flags, 'true'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        print('SKIP: required mapped user/mount namespaces are unavailable')
        raise SystemExit(77)
    env = dict(os.environ, IRA_BACKEND_TEST_DIR=str(work), IRA_TEST_REAL_DROP='1')
    args = [executable] if mode == 'credentials' else [executable, str(work)]
    if mode == 'integration':
        work.chmod(0o700)
        env['LD_LIBRARY_PATH'] = extra[0]
    raise SystemExit(subprocess.run(['unshare', *flags, *args], env=env).returncode)
if mode != 'crypto':
    raise SystemExit('unsupported fixture: ' + mode)

def openssl(*args, output=None):
    result = subprocess.run(['openssl', *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if output: Path(output).write_bytes(result.stdout)
    return result.stdout
key = str(work / 'key.pem')
openssl('genrsa', '-out', key, '2048')
modulus = openssl('rsa', '-in', key, '-noout', '-modulus').decode().strip().split('=', 1)[1]
n = int(modulus, 16)
nb = (n.bit_length() + 7) // 8
token = b'0123456789abcdefghij'
(work / 'token.bin').write_bytes(token)
openssl('dgst', '-sha1', '-sign', key, '-out', str(work / 'sig-sha1.bin'), str(work / 'token.bin'))
(work / 'sig-raw-in.bin').write_bytes(bytes.fromhex('3021300906052b0e03021a05000414') + token)
openssl('rsautl', '-sign', '-inkey', key, '-in', str(work / 'sig-raw-in.bin'), '-out', str(work / 'sig-raw.bin'))
inv = 1
for _ in range(6): inv = (inv * (2 - (n & 0xffffffff) * inv)) & 0xffffffff
blob = (nb // 4).to_bytes(4, 'little') + ((-inv) & 0xffffffff).to_bytes(4, 'little')
blob += n.to_bytes(nb, 'little') + pow(2, 2 * nb * 8, n).to_bytes(nb, 'little') + (65537).to_bytes(4, 'little')
(work / 'blob.bin').write_bytes(blob)
raise SystemExit(subprocess.run([executable, str(work)]).returncode)
