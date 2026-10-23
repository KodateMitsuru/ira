#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run the real module installer against repo-confined images.

The images are shaped like the packaged ones: a fixed-length token surrounded by unrelated bytes.
The installer's SELinux detection is exercised for real: a process whose argv[0] says usb gadget is
started, and the wrapper's cat reports a domain for it, so the generated policy is the one that
would be written on that device - with no hardcoded domain anywhere.
"""
from pathlib import Path
import os
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'build' / 'installer-policy-test'
TOKEN = b'IRA-SOCKET-NAME-0000000000000000'
CONTROL_TOKEN = b'IRA-CONTROL-NAME-00000000000000'
GADGET = 'vendor_test_gadget'

WRAPPER = r'''
set -u
ui_print() { :; }
set_perm_recursive() { :; }
abort() { printf '%s\n' "$*" >&2; exit 71; }
cat() {
    case "${1:-}" in
    /proc/self/attr/current) printf 'u:r:%s:s0' "${TEST_ROOT_DOMAIN:-}";;
    */attr/current) printf 'u:r:%s:s0' "${TEST_GADGET_DOMAIN:-}";;
    *) command cat "$@";;
    esac
}
od() {
    case "$*" in
    *"-N8"*"/dev/urandom"*)
        [ "${TEST_RANDOM_FAIL:-0}" = 1 ] && return 1
        printf ' 01 23 45 67 89 ab cd ef\n' ;;
    *) command od "$@" ;;
    esac
}
ksud() {
    [ "$1 $2" = 'sepolicy check' ] || return 91
    printf '%s\n' "$3" >> "$MODPATH/policy-checks"
    [ "${TEST_POLICY_FAIL:-0}" != 1 ] || return 92
    case "$3" in *:*|*';'*) return 93 ;; esac
}
trap '[ -z "${HAL_PID:-}" ] || kill "$HAL_PID" 2>/dev/null || :' EXIT
if [ "${TEST_NO_HAL:-0}" != 1 ]; then
    ( exec -a /tmp/ira-usb-gadget-hal sleep 20 ) &
    HAL_PID=$!
fi
. "$INSTALLER"
[ -n "${HAL_PID:-}" ] && kill "$HAL_PID" 2>/dev/null
'''


def make_image(path: Path, offset: int, copies: int = 1) -> None:
    filler = bytes(((i * 37 + 11) % 251) + 1 for i in range(offset))
    tail = bytes(((i * 53 + 7) % 251) + 1 for i in range(4096))
    image = filler + TOKEN * copies + tail
    assert TOKEN not in filler and TOKEN not in tail
    path.write_bytes(image)


def fixture(directory: Path) -> None:
    (directory / 'zygisk').mkdir(parents=True, exist_ok=True)
    (directory / 'lib').mkdir(exist_ok=True)
    (directory / 'service.sh').write_text('#!/system/bin/sh\n')
    (directory / 'sepolicy.rule').write_text('# placeholder\n')
    framework = directory / 'zygisk' / 'arm64-v8a.so'
    make_image(framework, 1234)
    with framework.open('ab') as image:
        image.write(CONTROL_TOKEN + b'\0' * (32 - len(CONTROL_TOKEN)))
    make_image(directory / 'lib' / 'ira-zn.so', 907)


def run(directory: Path, root_domain: str = 'ksu', gadget_domain: str = GADGET,
        no_hal: bool = False, random_fail: bool = False, policy_fail: bool = False):
    env = dict(os.environ, MODPATH=str(directory), TEST_ROOT_DOMAIN=root_domain,
               TEST_GADGET_DOMAIN='' if no_hal else gadget_domain,
               TEST_NO_HAL=str(int(no_hal)), TEST_RANDOM_FAIL=str(int(random_fail)),
               TEST_POLICY_FAIL=str(int(policy_fail)),
               INSTALLER=str(ROOT / 'module/customize.sh'))
    return subprocess.run(['bash', '-c', WRAPPER], env=env, cwd=ROOT,
                          stdin=subprocess.DEVNULL, capture_output=True, timeout=120)


def fresh(name: str) -> Path:
    directory = WORK / name
    if directory.exists():
        subprocess.run(['rm', '-rf', str(directory)], check=True)
    fixture(directory)
    return directory


checks = 0

# The shipped rule file must not name any domain: everything is generated from the device.
shipped = (ROOT / 'module' / 'sepolicy.rule').read_text()
assert 'allow ' not in shipped, shipped
assert 'vendor_hal_usb_qti' not in shipped and ':su' not in shipped
checks += 2

for domain in ('ksu', 'magisk'):
    directory = fresh(domain)
    result = run(directory, root_domain=domain)
    assert result.returncode == 0, result.stderr.decode()

    names = {}
    for line in (directory / 'names').read_text().splitlines():
        role, name = line.split('=', 1)
        assert re.fullmatch(r'[0-9a-f]{16}\.' + role, name), name
        names[role] = name
        checks += 1
    assert set(names) == {'ctl', 'auth', 'su'} and len(set(names.values())) == 3
    checks += 2
    assert not (directory / 'state').exists(), 'state/ must stay runtime-only'
    checks += 1

    policy = (directory / 'sepolicy.rule').read_text()
    expected = (
        f'# generated at install time: {GADGET} -> {domain}\n'
        f'allow {GADGET} {domain} unix_stream_socket {{ connectto read write }}\n'
        f'allow {GADGET} {GADGET} process execmem\n'
        f'allow system_server {domain} unix_stream_socket {{ connectto read write }}\n'
        f'allow adbd {domain} unix_stream_socket {{ read write }}\n'
        'allow adbd shell process2 nosuid_transition\n'
    )
    assert policy == expected, policy
    checked = (directory / 'policy-checks').read_text().splitlines()
    assert checked == [line for line in policy.splitlines() if line.startswith('allow ')]
    checks += 1
    for forbidden in (f'allow {domain} ', 'fd use', 'tcp_socket', 'vendor_hal_usb_qti', ':su:'):
        assert forbidden not in policy, forbidden
        checks += 1

    for image, role, offset in ((directory / 'lib' / 'ira-zn.so', 'ctl', 907),
                                (directory / 'zygisk' / 'arm64-v8a.so', 'auth', 1234)):
        data = image.read_bytes()
        name = names[role].encode()
        assert data[offset:offset + len(name)] == name, role
        assert data[offset + len(name):offset + 32] == b'\0' * (32 - len(name)), role
        assert TOKEN not in data, role
        checks += 3

    framework = (directory / 'zygisk' / 'arm64-v8a.so').read_bytes()
    ctl = names['ctl'].encode()
    assert framework[-32:] == ctl + b'\0' * (32 - len(ctl))
    assert CONTROL_TOKEN not in framework
    checks += 2

    assert not (directory / 'sockoff').exists() and not (directory / 'sockoff-zn').exists()
    checks += 1

# No gadget service running: refuse the install instead of guessing a domain from another device.
directory = fresh('no-hal')
result = run(directory, no_hal=True)
assert result.returncode == 71 and b'USB gadget HAL is not running' in result.stderr, result.stderr
checks += 2

# No readable SELinux domain for the installer: refuse instead of falling back to "su".
directory = fresh('no-root')
result = run(directory, root_domain='')
assert result.returncode == 71 and b'cannot read this installer' in result.stderr, result.stderr
checks += 2

# A token that is not there, or is there twice, must stop the install rather than write half an image.
for copies, expected_error in ((0, b'no socket-name token'), (2, b'more than one socket-name token')):
    directory = fresh(f'token-{copies}')
    make_image(directory / 'lib' / 'ira-zn.so', 907, copies)
    result = run(directory)
    assert result.returncode == 71 and expected_error in result.stderr, result.stderr
    checks += 2

# Missing or duplicated framework control tokens must also abort; accepting either breaks revoke.
for copies, expected_error in ((0, b'no socket-name token'), (2, b'more than one socket-name token')):
    directory = fresh(f'control-token-{copies}')
    framework = directory / 'zygisk' / 'arm64-v8a.so'
    image = framework.read_bytes()
    framework.write_bytes(image.replace(CONTROL_TOKEN, CONTROL_TOKEN * copies))
    result = run(directory)
    assert result.returncode == 71 and expected_error in result.stderr, result.stderr
    checks += 2

# A rule rejected by the real checker interface must stop installation before endpoint injection.
directory = fresh('policy-rejected')
before = (directory / 'zygisk' / 'arm64-v8a.so').read_bytes()
result = run(directory, policy_fail=True)
assert result.returncode == 71 and b'unsupported generated policy' in result.stderr
assert (directory / 'zygisk' / 'arm64-v8a.so').read_bytes() == before
checks += 2

# A random source that fails must abort before any image is touched.
directory = fresh('random-failed')
before = (directory / 'lib' / 'ira-zn.so').read_bytes()
result = run(directory, random_fail=True)
assert result.returncode == 71 and b'secure random source failed' in result.stderr
assert (directory / 'lib' / 'ira-zn.so').read_bytes() == before
checks += 2

print(f'PASS: {checks} actual-installer endpoint/policy checks')
