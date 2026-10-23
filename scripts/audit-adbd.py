#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bounded, non-disruptive ADB behavior capture. Does not change root/auth/USB settings.

Run once per explicitly selected endpoint; identity records prevent labeling system adbd as IRA.
Creates a temporary test directory on sdcard and removes only that directory in finally.
Host evidence lives under --out, never /tmp. This is a capture, not a claim of full equivalence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import socket
import struct
import subprocess
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', default='/opt/android-sdk/platform-tools/adb')
    parser.add_argument('--serial', required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--server-port', type=int, default=5037)
    args = parser.parse_args()
    work = Path(args.out).resolve()
    work.mkdir(parents=True, exist_ok=True)
    adb = [args.adb, '-P', str(args.server_port), '-s', args.serial]
    records = {}

    def run(name, command, timeout=15, expect_out=None, expect_rc=0):
        try:
            p = subprocess.run(adb + command, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            records[name] = {'command': command, 'rc': p.returncode,
                             'stdout': p.stdout[:12000].decode('utf-8', 'backslashreplace'),
                             'stderr': p.stderr[:4000].decode('utf-8', 'backslashreplace')}
            if expect_out is not None:
                records[name]['expected_match'] = (p.stdout == expect_out and p.returncode == expect_rc)
            return p
        except subprocess.TimeoutExpired:
            records[name] = {'command': command, 'timeout': timeout}
            return None

    def raw(name, service):
        def exact(s, n):
            data = b''
            while len(data) < n:
                part = s.recv(n - len(data))
                if not part:
                    raise EOFError('short ADB server reply')
                data += part
            return data

        def request(s, text):
            data = text.encode()
            s.sendall(f'{len(data):04x}'.encode() + data)
            status = exact(s, 4)
            if status != b'OKAY':
                n = int(exact(s, 4), 16)
                raise RuntimeError(exact(s, n).decode(errors='replace'))

        result = {}
        try:
            with socket.create_connection(('127.0.0.1', args.server_port), timeout=3) as s:
                request(s, 'host:transport:' + args.serial)
                request(s, service)
                result['accepted'] = True
                s.settimeout(2)
                data = b''
                try:
                    while len(data) < 4096:
                        part = s.recv(4096 - len(data))
                        if not part:
                            result['eof'] = True
                            break
                        data += part
                except socket.timeout:
                    result['read_timeout'] = True
                result['payload_hex'] = data.hex()
                result['payload_text'] = data.decode(errors='backslashreplace')
        except (OSError, RuntimeError, EOFError, ValueError) as e:
            result['error'] = str(e)
        records[name] = result

    run('devices', ['devices', '-l'])
    run('features', ['features'])
    run('state', ['get-state'])
    run('identity', ['shell', '-T',
        'id; id -Z; pwd; readlink /proc/$$/exe; '
        'readlink /proc/self/ns/mnt; p=$(sed -n "s/^PPid:[[:space:]]*//p" /proc/$$/status); '
        'printf "parent="; tr "\\0" " " < /proc/$p/cmdline; echo; '
        'printf "SHELL=%s HOME=%s USER=%s TERM=%s IRA_VTTY=%s\\n" '
        '"$SHELL" "$HOME" "$USER" "$TERM" "$IRA_VTTY"; '
        'getprop ro.build.version.sdk; getprop ro.build.type; getprop ro.debuggable'])
    run('shell_v2', ['shell', '-T', 'printf stdout; printf stderr >&2; exit 37'],
        expect_out=b'stdout', expect_rc=37)
    if 'shell_v2' in records and 'stderr' in records['shell_v2']:
        records['shell_v2']['stderr_match'] = records['shell_v2']['stderr'] == 'stderr'
    run('exec_binary', ['exec-out', "printf '\\000\\001\\177\\377A'"],
        expect_out=bytes([0, 1, 127, 255, 65]))
    run('raw_stdin_eof', ['shell', '-T', 'cat; printf eof'], expect_out=b'eof')
    run('signal_exit', ['shell', '-T', 'kill -TERM $$'], expect_out=b'', expect_rc=143)
    # This records terminal behavior, not a requirement to use a kernel PTY implementation.
    run('terminal_contract', ['shell', '-tt',
        'test -t 0; echo stdin_tty=$?; tty; stty size; '
        'printf "TERM=%s\\n" "$TERM"'])
    run('package_query', ['shell', '-T', 'cmd package path android'])
    run('forward_list', ['forward', '--list'])
    run('reverse_list', ['reverse', '--list'])
    run('jdwp', ['jdwp'], timeout=5)
    raw('track_jdwp', 'track-jdwp')
    raw('track_app', 'track-app')
    raw('abb_exec_query', 'abb_exec:package\0path\0android\0')
    raw('unknown_service', 'ira-audit-no-such-service:')

    # These are the only writes to the device, confined to a unique sdcard directory.
    remote = '/sdcard/ira-audit-' + uuid.uuid4().hex[:12]
    payload = work / 'payload.bin'
    payload.write_bytes(bytes(range(256)) * 4096 + b'\0ADB\xff\n')
    os.chmod(payload, 0o640)
    expected = hashlib.sha256(payload.read_bytes()).hexdigest()
    made = run('scratch_mkdir', ['shell', '-T', 'mkdir ' + shlex.quote(remote)])
    if made is not None and made.returncode == 0:
        try:
            dst = remote + '/payload.bin'
            run('push', ['push', str(payload), dst], timeout=30)
            checksum = run('shell_sees_push', ['shell', '-T', 'sha256sum ' + shlex.quote(dst)])
            records['shell_sees_push']['hash_match'] = bool(
                checksum and checksum.stdout.decode().split() and
                checksum.stdout.decode().split()[0] == expected)
            run('sync_stat', ['shell', '-T', 'stat -c "%u:%g %a %s" ' + shlex.quote(dst)])
            fetched = work / 'pulled.bin'
            run('pull', ['pull', dst, str(fetched)], timeout=30)
            records['pull']['hash_match'] = fetched.exists() and hashlib.sha256(fetched.read_bytes()).hexdigest() == expected
            run('shell_write', ['shell', '-T', 'printf shell-data > ' + shlex.quote(remote + '/shell.txt')])
            pulled_shell = work / 'from-shell.txt'
            run('pull_shell_write', ['pull', remote + '/shell.txt', str(pulled_shell)])
            records['pull_shell_write']['content_match'] = pulled_shell.exists() and pulled_shell.read_bytes() == b'shell-data'
            run('push_dry_run', ['push', '-n', str(payload), remote + '/dry-run.bin'])
            run('dry_run_absent', ['shell', '-T', 'test ! -e ' + shlex.quote(remote + '/dry-run.bin')], expect_out=b'')
        finally:
            run('scratch_cleanup', ['shell', '-T', 'rm -rf ' + shlex.quote(remote)])

    report = {'label': args.label, 'serial': args.serial, 'captured_unix': int(time.time()),
              'note': 'Identify parent in identity before comparing endpoints; no root/auth/USB settings changed.',
              'records': records}
    (work / 'capture.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'capture': str(work / 'capture.json'), 'checks': len(records),
                      'timeouts': [n for n, r in records.items() if 'timeout' in r],
                      'contract_mismatches': [n for n, r in records.items()
                          if r.get('expected_match') is False or r.get('hash_match') is False or
                          r.get('content_match') is False or r.get('stderr_match') is False]}, indent=2))


if __name__ == '__main__':
    main()
