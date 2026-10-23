#!/usr/bin/env python3
# IRA-specific changes: AGPL-3.0-or-later; upstream MirOS terms retained below.
# Native CMake build-time generator for mksh .opt tables.
# genopt rules derived from mksh Build.sh, Copyright (c) mirabilos et al.;
# MirOS licence, reproduced in src/mksh/NOTICE. No compiler/configure invocation.
from pathlib import Path
import sys

source, target = map(Path, sys.argv[1:])
lines = iter(source.read_text().splitlines())
header = ['/* +++ GENERATED FILE +++ DO NOT EDIT +++ */']
body, undefines, options = [], [], []
state = 0
symbol = None

def condition(text):
    if not text: return []
    if ' ' in text: return ['#if ' + text.removeprefix(' ')]
    if text.startswith('!'): return ['#ifndef ' + text[1:]]
    return ['#ifdef ' + text]

for line in lines:
    if state == 2 and line.startswith('|'):
        symbol = line[1:]
        body += ['#undef F0', '#undef FN', *undefines]
        state = 3
    elif state == 1 and line == '@@':
        body += ['#endif', '#ifndef F0', '#define F0 FN', '#endif']
        state = 2
    elif line.startswith('@@'):
        raise ValueError('invalid section: ' + line)
    elif state == 0 and (not line or line.startswith(('/*-', ' *'))):
        header.append(line)
    elif state in (0, 1) and line.startswith('@'):
        name = line[1:]
        body.append(('#if' if state == 0 else '#elif') + ' defined(' + name + ')')
        undefines.append('#undef ' + name)
        state = 1
    elif state in (0, 3):
        raise ValueError('unexpected input: ' + line)
    elif state == 1:
        body.append(line)
    elif state == 2 and line.startswith(('<', '>')) and '|' in line:
        option = line[1]
        opts, cond = line[1:].split('|', 1)
        if option != '|':
            key = option.lower() + str(int(option == option.lower())) + '|' + opts + '|' + cond
            options.append((key, opts, cond))
        if line.startswith('>'):
            directives = condition(cond)
            body += directives + [next(lines) + ', ' + ('0' if option == '|' else repr(option)) + ')']
            if directives: body.append('#endif')

assert state == 3 and symbol, 'missing table end marker'
output = header + ['#ifndef ' + symbol] + body + ['#else']
for _, opts, cond in sorted(options):
    directives = condition(cond)
    output += directives + ['"' + opts + '"']
    if directives: output.append('#endif')
output += ['#undef ' + symbol, '#endif']
text = '\n'.join(output) + '\n'
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(text)
assert target.read_text() == text and output.count('#else') >= 1
print('PASS: generated ' + target.name + ' from ' + source.name)
