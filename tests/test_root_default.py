#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exercise actual startup selection with a mock ksud CLI and a recording daemon."""
from pathlib import Path
import os
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
work = Path(sys.argv[1]).resolve()
work.mkdir(parents=True, exist_ok=True)
shutil.copy2(root / 'module/start-daemon.sh', work / 'start-daemon.sh')
# Give the production script a shell function resolver for ksud through PATH;
# never execute or depend on a device's actual /data/adb/ksud during host tests.
assert not Path('/data/adb/ksud').exists()
ksud = work / 'ksud'
ksud.write_text('''#!/bin/sh
[ "$*" = 'feature get adb_root' ] || exit 91
case "$IRA_TEST_KSU" in
 enabled) printf 'Feature: adb_root (3)\\nValue: 1\\nStatus: enabled\\n';;
 disabled) printf 'Feature: adb_root (3)\\nValue: 0\\nStatus: disabled\\n';;
 nonzero) printf 'Value: 2\\n';;
 unsupported) printf "Feature 'adb_root' is not supported by kernel\\n";;
 malformed) printf 'Value: yes\\n';;
 duplicate) printf 'Value: 1\\nValue: 0\\n';;
 failed) exit 1;;
 stalled) exec sleep 10;;
 ignores_term) trap "" TERM; exec sleep 10;;
esac
''')
ksud.chmod(0o755)
daemon = work / 'ira-daemon'
daemon.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
daemon.chmod(0o755)
for state, expected in [('enabled','root'), ('disabled','shell'), ('nonzero','root'),
                        ('unsupported','shell'), ('malformed','shell'), ('duplicate','shell'),
                        ('failed','shell'), ('stalled','shell'), ('ignores_term','shell')]:
    env = dict(os.environ, PATH=str(work) + os.pathsep + os.environ['PATH'], IRA_TEST_KSU=state)
    result = subprocess.run(['sh', str(work / 'start-daemon.sh')], env=env,
                            capture_output=True, text=True, timeout=4)
    assert result.returncode == 0, (state, result.stderr)
    assert result.stdout.splitlines()[-2:] == ['--ira-root-default', expected], (state, result.stdout)
ksud.unlink()
result = subprocess.run(['sh', str(work / 'start-daemon.sh')],
    env=dict(os.environ, PATH=str(work) + os.pathsep + os.environ['PATH']),
    capture_output=True, text=True, timeout=4)
assert result.returncode == 0 and result.stdout.splitlines()[-2:] == ['--ira-root-default', 'shell']
# The production daemon validates explicit startup arguments before platform initialization.
for args in [('--ira-root-default','invalid'), ('--ira-root-default',), ('--unexpected',)]:
    result = subprocess.run([sys.argv[2], *args], capture_output=True, text=True, timeout=2)
    assert result.returncode == 2 and 'usage:' in result.stderr, (args, result)
print('PASS: KSU enabled/disabled/nonzero/unsupported/malformed/failure/timeout defaults and daemon argument validation')
