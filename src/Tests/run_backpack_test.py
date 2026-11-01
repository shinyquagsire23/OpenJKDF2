#!/usr/bin/env python3
"""Test rejected-count item flags using full production types and the receiver item case.

No creator, getter, outbound clamp or physical-capacity policy change is tested.
Both QOL and non-QOL declarations compile; unsafe legacy creation is never run.
The byte reader is controlled; full-message transactionality is not claimed.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from source_test_utils import extract_block, unique_match, find_compiler
ROOT = Path(__file__).resolve().parents[2]
INPUTS = ('src/Dss/sithDSSThing.c', 'src/types.h', 'src/types_enums.h',
          'src/types_win_enums.h', 'src/engine_config.h', 'src/Primitives/rdRect.h')

def execute(argv, directory, environment):
    return subprocess.run(argv, cwd=directory, env=environment, capture_output=True,
                          text=True, encoding='utf-8', errors='replace', timeout=60)

def require(result, label):
    if result.returncode:
        raise RuntimeError(f'{label} exited {result.returncode}\n{result.stdout}{result.stderr}')
    if result.stderr:
        print(result.stderr, end='', file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cc', default=os.environ.get('CC'))
    parser.add_argument('--ubsan', action='store_true')
    parser.add_argument('--negative-controls', action='store_true')
    args = parser.parse_args()
    compiler = find_compiler(args.cc)
    inputs = {name: (ROOT / name).read_bytes() for name in INPUTS}
    function = extract_block(inputs[INPUTS[0]].decode('utf-8'),
                             r'^int\s+sithDSSThing_ProcessStateUpdate\s*\(', 'state receiver')
    start = unique_match(r'^[ \t]*case SITH_THING_ITEM:', function, 'item case')
    end = unique_match(r'^[ \t]*default:', function, 'default case')
    if end.start() <= start.start(): raise RuntimeError('Review item case boundaries')
    production = function[start.start():end.start()]
    environment = dict(os.environ, UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    with tempfile.TemporaryDirectory(prefix='openjk-backpack-flags-') as temporary:
        temp = Path(temporary)
        (temp / 'backpack_test.c').write_bytes(Path(__file__).with_name('backpack_test.c').read_bytes())
        flags = ['-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-DLINUX', '-DPLATFORM_POSIX', '-DSTDSOUND_NULL',
                 '-I', str(ROOT / 'src')]
        if args.ubsan: flags += ['-fsanitize=undefined', '-fno-sanitize-recover=all']
        version = execute([compiler, '--version'], temp, environment); require(version, 'compiler')
        print(version.stdout.splitlines()[0])
        for layout, define in [('non-qol', '-UQOL_IMPROVEMENTS'), ('qol', '-DQOL_IMPROVEMENTS')]:
            binary = temp / layout
            command = [compiler, *flags, define, 'backpack_test.c', '-o', str(binary)]
            (temp / 'backpack_dss_unpack.inc').write_text(production, encoding='utf-8')
            require(execute(command, temp, environment), f'compile {layout}')
            result = execute([str(binary)], temp, environment); require(result, layout)
            print(layout + ': ' + result.stdout, end='')
            if args.negative_controls:
                anchor = 'const uint32_t itemFlags = NETMSG_POPS32();'
                if production.count(anchor) != 1: raise RuntimeError('Review early-flags control anchor')
                mutated = production.replace(anchor, anchor + '\n            pThing->itemParams.flags = itemFlags;')
                (temp / 'backpack_dss_unpack.inc').write_text(mutated, encoding='utf-8')
                require(execute(command, temp, environment), f'compile {layout} early-flags control')
                control = execute([str(binary)], temp, environment)
                if control.returncode != 1 or 'rejected-count-preserves-item-flags' not in control.stderr:
                    raise RuntimeError('Early-flags control did not fail its intended assertion\n' + control.stderr)
                print('PASS ' + layout + ' early-flags negative control rejected')
    for name, data in inputs.items():
        if (ROOT / name).read_bytes() != data: raise RuntimeError('Input changed: ' + name)
        print(f'SHA256 {hashlib.sha256(data).hexdigest()} {name}')
    print('PASS production inputs unchanged; no backpack creator executed')
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        print('FAIL:', error, file=sys.stderr)
        sys.exit(1)
