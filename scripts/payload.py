#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deterministic generated-header writer and checks used exclusively by CMake targets."""
from pathlib import Path
import sys

mode, path, role = sys.argv[1:]
data = Path(path).read_bytes()
if mode == 'embed':
    target = Path(role)
    lines = [', '.join(f'0x{byte:02x}' for byte in data[i:i + 16]) for i in range(0, len(data), 16)]
    text = 'unsigned char ira_dex[] = {\n' + ',\n'.join(lines) + '\n};\n'
    text += f'unsigned int ira_dex_len = {len(data)};\n'
    target.write_text(text)
    assert sum(line.count('0x') for line in lines) == len(data)
    assert f'ira_dex_len = {len(data)};' in target.read_text()
    print(f'PASS: embedded {len(data)} dex bytes')
elif mode == 'check':
    if role == 'shell':
        assert data[:4] == b'\x7fELF' and b'ira.su' not in data and b'IRA_SU_SOCKET' in data
    else:
        assert data.count(b'IRA-SOCKET-NAME-0000000000000000') == 1
        if role == 'framework':
            assert data.count(b'IRA-CONTROL-NAME-00000000000000') == 1
    print(f'PASS: {role} payload invariants')
else:
    raise SystemExit(f'unknown mode: {mode}')
