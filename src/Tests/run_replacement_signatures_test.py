#!/usr/bin/env python3
"""Compile actual replacement registration/selection blocks with synthetic caches."""
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


def between(text, start, end):
    if text.count(start) != 1 or text.count(end) != 1:
        raise RuntimeError("Production extraction boundary changed: " + start)
    return text.split(start, 1)[1].split(end, 1)[0]


def run(cc, sanitize):
    source = ROOT / 'src/Platform/GL/jkgm.cpp'
    original = source.read_bytes()
    text = original.decode()
    populate = extract_block(text, r'^void jkgm_populate_cache\(', 'metadata population')
    registration = extract_block(populate, r'^[ \t]*for \(auto hash_it : it\["replaces_signatures"\]\)', 'signature registration')
    registration = registration[registration.index('{') + 1:registration.rfind('}')]
    shortcut = extract_block(text, r'^void jkgm_populate_shortcuts\(', 'shortcut selection')
    # Include the complete contiguous decision/early-return region. The optional
    # upload callback is stubbed; no texture IO or GL calls run in this fixture.
    selection = between(shortcut,
        '    //printf("%s %s %s\\n", full_fpath_str.c_str(), cache_key.c_str(), hash.c_str());',
        '    rdTexture *pRdTexture = &material->textures[cel];')
    # Its early return is void in production; wrap in a void lambda unchanged.
    selection = 'auto select = [&]() {\n' + selection + '\n}; select();\n'
    support = '#define jkGuiBuildMulti_bRendering 0\n#define jkPlayer_bEnableTexturePrecache 0\n#define std3D_AddToTextureCache(...) ((void)0)\n'
    flags = ['-std=c++17', '-Wall', '-Wextra', '-Werror', '-g', '-O1']
    env = os.environ.copy()
    if sanitize:
        flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
        env.setdefault('ASAN_OPTIONS', 'detect_leaks=1:halt_on_error=1')
    with tempfile.TemporaryDirectory(prefix='openjkdf2-signatures-') as d:
        work = Path(d)
        (work / 'actual_register.inc').write_text(registration)
        (work / 'actual_select.inc').write_text(support + selection)
        shutil.copyfile(Path(__file__).with_name('replacement_signatures_test.cpp'), work / 'test.cpp')
        command = [cc, *flags, '-I', str(ROOT / 'src'), 'test.cpp', '-o', str(work / 'test')]
        print('Compile:', ' '.join(command), flush=True)
        subprocess.run(command, cwd=work, env=env, check=True)
        subprocess.run([str(work / 'test')], env=env, check=True)
    if source.read_bytes() != original:
        raise RuntimeError('Production source changed during test')
    print('SHA256', hashlib.sha256(original).hexdigest(), source.relative_to(ROOT))
    print('PASS ASan+UBSan enabled' if sanitize else 'PASS unsanitized run')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cxx', default=os.environ.get('CXX', 'g++'))
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    try:
        run(find_compiler(args.cxx), args.sanitize)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print('FAIL:', error, file=sys.stderr)
        sys.exit(1)
