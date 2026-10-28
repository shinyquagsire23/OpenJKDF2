#!/usr/bin/env python3
"""Test actual host item acknowledgment and respawn functions without game assets.

Requires a native GCC or Clang compiler. Production bodies are extracted into a
temporary directory. Local lifecycle assertions cover the MotS sentinel and
normal actor/JK controls. This is not a network integration test.
"""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from source_test_utils import extract_block, find_compiler

ROOT = Path(__file__).resolve().parents[2]
PATHS = ('src/Dss/sithDSSThing.c', 'src/World/sithItem.c')


def run(cc, sanitize):
    version = subprocess.run([cc, '--version'], capture_output=True, text=True,
                             timeout=30, check=True)
    print(version.stdout.splitlines()[0])
    inputs = {name: (ROOT / name).read_bytes() for name in PATHS}
    sources = {name: data.decode('utf-8').replace('\r\n', '\n')
               for name, data in inputs.items()}
    take = extract_block(sources[PATHS[0]], r'^void sithDSSThing_Take\(', 'item take')
    lifecycle = extract_block(sources[PATHS[1]], r'^void sithItem_SetItemTaken\(', 'item lifecycle')
    flags = ['-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror']
    env = os.environ.copy()
    if sanitize:
        flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
        # No allocations in this fixture; LSan is unavailable in restricted runners.
        env['ASAN_OPTIONS'] = 'detect_leaks=0:halt_on_error=1'
        env['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
    with tempfile.TemporaryDirectory(prefix='openmots-takeitem-') as directory:
        work = Path(directory)
        shutil.copyfile(Path(__file__).with_name('takeitem_test.c'), work / 'takeitem_test.c')
        (work / 'actual_setitemtaken.inc').write_text(lifecycle + '\n', encoding='utf-8')
        (work / 'actual_takeitem.inc').write_text(take + '\n', encoding='utf-8')
        binary = work / ('current' + ('.exe' if os.name == 'nt' else ''))
        compiled = subprocess.run([cc, *flags, 'takeitem_test.c', '-o', str(binary)],
                                  cwd=work, env=env, capture_output=True, text=True, timeout=120)
        if compiled.returncode:
            raise RuntimeError('Compile:\n' + compiled.stdout + compiled.stderr)
        if compiled.stderr:
            print(compiled.stderr, file=sys.stderr, end='')
        result = subprocess.run([str(binary)], cwd=work, env=env,
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError('Production lifecycle:\n' + result.stdout + result.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr, end='')
        print(result.stdout, end='')
    for name, original in inputs.items():
        if (ROOT / name).read_bytes() != original:
            raise RuntimeError('Production source changed during test: ' + name)
        print('SHA256', hashlib.sha256(original).hexdigest(), name)
    print('PASS ASan+UBSan enabled; leak detection disabled (allocation-free fixture)'
          if sanitize else 'PASS unsanitized run')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cc', default=os.environ.get('CC'))
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    try:
        run(find_compiler(args.cc), args.sanitize)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print('FAIL:', error, file=sys.stderr)
        sys.exit(1)
