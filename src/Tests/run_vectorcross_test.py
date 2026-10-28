#!/usr/bin/env python3
"""Test the production COG VectorCross wrapper and stack helpers without assets.

Requires native GCC or Clang. Complete production functions are extracted into
a temporary directory and compiled with the sibling C harness. The current
implementation must pass; restoring only the old operand order must fail the
axis-direction assertion. This is not a parser, ABI, or game integration test.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

PATHS = (
    'src/Cog/sithCogFunction.c', 'src/Cog/sithCogExec.c',
    'src/Primitives/rdVector.c', 'src/types_enums.h',
)


def extract_block(text, marker, description):
    matches = list(re.finditer(marker, text, re.MULTILINE))
    if len(matches) != 1:
        raise RuntimeError(f'Expected one {description}; found {len(matches)}. Review extractor.')
    start = matches[0].start()
    opening = text.index('{', start)
    tokens = re.finditer(
        r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]',
        text[opening:], re.DOTALL,
    )
    depth = 0
    for token in tokens:
        if token.group() == '{':
            depth += 1
        elif token.group() == '}':
            depth -= 1
            if depth == 0:
                return text[start:opening + token.end()]
    raise RuntimeError(f'Unbalanced production body: {description}')


def execute(command, work, env, timeout=30):
    return subprocess.run(command, cwd=work, env=env, capture_output=True,
                          text=True, errors='replace', timeout=timeout, check=False)


def require_success(result, description):
    if result.returncode:
        raise RuntimeError(f'{description} exited {result.returncode}\n{result.stdout}{result.stderr}')
    if result.stderr:
        print(result.stderr, file=sys.stderr, end='')


def run(root, cc, ubsan):
    inputs = {name: (root / name).read_bytes() for name in PATHS}
    src = {name: data.decode('utf-8').replace('\r\n', '\n') for name, data in inputs.items()}
    functions = []
    for file_index, name, result_type in (
        (1, 'sithCogExec_PopSymbol', 'int32_t'),
        (1, 'sithCogExec_PopVector', 'int32_t'),
        (1, 'sithCogExec_PushStack', 'void'),
        (1, 'sithCogExec_PushVector', 'void'),
        (2, 'rdVector_Cross3', 'void'),
    ):
        functions.append(extract_block(src[PATHS[file_index]],
            rf'^{result_type}\s+{name}\s*\(', name))
    wrapper = extract_block(src[PATHS[0]], r'^void\s+sithCogFunction_VectorCross\s*\(', 'VectorCross')
    enums = extract_block(src[PATHS[3]], r'^typedef enum eSithCogValueType\b', 'COG value enum')
    flags = ['-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Wno-unused-variable']
    env = os.environ.copy()
    if ubsan:
        flags += ['-fsanitize=undefined', '-fno-sanitize-recover=all']
        env['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
    try:
        with tempfile.TemporaryDirectory(prefix='openjkdf2-vectorcross-') as temp:
            work = Path(temp)
            shutil.copyfile(Path(__file__).with_name('vectorcross_test.c'), work / 'vectorcross_test.c')
            (work / 'production.inc').write_text(enums + ' SithCogValueType;\n\n' + '\n\n'.join(functions) + '\n', encoding='utf-8')
            version = execute([cc, '--version'], work, env)
            require_success(version, 'Compiler version query')
            print(version.stdout.splitlines()[0])
            for old_order in (False, True):
                body = wrapper
                name = 'old-order' if old_order else 'production'
                if old_order:
                    anchor = 'rdVector_Cross3(&out, &inB, &inA);'
                    if body.count(anchor) != 1:
                        raise RuntimeError('Corrected call shape changed; review old-order mutation.')
                    body = body.replace(anchor, 'rdVector_Cross3(&out, &inA, &inB);')
                (work / 'wrapper.inc').write_text(body + '\n', encoding='utf-8')
                binary = work / (name + ('.exe' if os.name == 'nt' else ''))
                result = execute([cc, *flags, 'vectorcross_test.c', '-lm', '-o', str(binary)], work, env, 120)
                require_success(result, f'Compile {name}')
                result = execute([str(binary)], work, env)
                if old_order:
                    if result.returncode != 1 or 'FAIL x-cross-y [literal/literal]: result.z' not in result.stderr:
                        raise RuntimeError('Old order did not fail the expected direction assertion:\n' + result.stdout + result.stderr)
                    print('PASS old operand-order mutant rejected by x-cross-y direction assertion')
                else:
                    require_success(result, 'Production VectorCross regression')
                    print(result.stdout, end='')
    finally:
        for name, original in inputs.items():
            if (root / name).read_bytes() != original:
                raise RuntimeError('Production source changed during test: ' + name)
            print('SHA256', hashlib.sha256(original).hexdigest(), name)
    print('PASS UBSan enabled' if ubsan else 'PASS unsanitized run')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--cc', default=os.environ.get('CC'))
    parser.add_argument('--ubsan', action='store_true')
    args = parser.parse_args()
    try:
        candidates = [args.cc] if args.cc else ['gcc', 'clang', 'cc']
        cc = next((shutil.which(c) for c in candidates if shutil.which(c)), None)
        if not cc:
            raise RuntimeError('Native GCC/Clang not found; select it with --cc.')
        run(args.source_root.resolve(), cc, args.ubsan)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print('FAIL:', error, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
