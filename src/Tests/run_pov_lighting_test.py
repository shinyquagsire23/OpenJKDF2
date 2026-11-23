#!/usr/bin/env python3
"""Execute actual DrawPov with synthetic state and reject the former RGB leak."""
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


def run(cc, sanitize):
    source_path = ROOT / 'src/World/jkPlayer.c'
    original = source_path.read_bytes()
    function = extract_block(original.decode().replace('\r\n', '\n'), r'^void jkPlayer_DrawPov\(', 'POV draw')
    anchor = '        rdSetVertexColorMode(0);'
    if function.count(anchor) != 1:
        raise RuntimeError('POV mono-boundary anchor changed')
    flags = ['-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-unused-variable']
    env = os.environ.copy()
    if sanitize:
        flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
        env.setdefault('ASAN_OPTIONS', 'detect_leaks=1:halt_on_error=1')
        env['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
    with tempfile.TemporaryDirectory(prefix='openmots-pov-lighting-') as directory:
        work = Path(directory)
        shutil.copyfile(Path(__file__).with_name('pov_lighting_test.c'), work / 'pov_lighting_test.c')
        for name, defines, body, control in (
            ('current-accelerated', ['-DSDL2_RENDER', '-DQOL_IMPROVEMENTS'], function, False),
            ('current-legacy', [], function, False),
            ('old-rgb-leak', ['-DSDL2_RENDER', '-DQOL_IMPROVEMENTS'], function.replace(anchor, ''), True),
        ):
            (work / 'actual_draw_pov.inc').write_text(body + '\n', encoding='utf-8')
            binary = work / (name + ('.exe' if os.name == 'nt' else ''))
            compiled = subprocess.run([cc, *flags, *defines, 'pov_lighting_test.c', '-lm', '-o', str(binary)],
                                      cwd=work, env=env, capture_output=True, text=True, timeout=120)
            if compiled.returncode:
                raise RuntimeError(name + ' compile:\n' + compiled.stdout + compiled.stderr)
            result = subprocess.run([str(binary)], cwd=work, env=env, capture_output=True, text=True, timeout=30)
            if control:
                if result.returncode != 1 or 'FAIL pov-mono' not in result.stderr:
                    raise RuntimeError('Old RGB-leak control did not fail:\n' + result.stdout + result.stderr)
                print('PASS rejected old RGB mode leak by actual draw/cache observations')
            elif result.returncode:
                raise RuntimeError(name + ':\n' + result.stdout + result.stderr)
            else:
                print(name + ': ' + result.stdout, end='')
    if source_path.read_bytes() != original:
        raise RuntimeError('Production DrawPov source changed during test')
    print('SHA256', hashlib.sha256(original).hexdigest(), 'src/World/jkPlayer.c')
    print('PASS ASan+UBSan enabled' if sanitize else 'PASS unsanitized run')


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
