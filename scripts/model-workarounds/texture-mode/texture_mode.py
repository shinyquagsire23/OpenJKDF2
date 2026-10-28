"""Inspect or copy a text 3DO with explicit mesh AND face texture modes.

Historical JK format: 0 = affine, 1 = perspective corrected. This helper changes
only those numeric tokens, preserves the rest of the bytes, and never overwrites
an existing file. It is not a full 3DO validator or a runtime compatibility test.
"""
from pathlib import Path
from collections import Counter
import argparse
import hashlib
import json
import re

HEADER = re.compile(r'^(\s*TEXTUREMODE\s+)([0-4])(?=\s|$)', re.I)
FACES = re.compile(r'^\s*FACES\s+(\d+)\s*$', re.I)
FACE = re.compile(r'^(\s*(\d+)\s*:\s+\S+\s+\S+\s+\d+\s+\d+\s+)([0-4])(?=\s)')


def convert(data, mode=None):
    if mode not in (None, 0, 1):
        raise ValueError('Only explicit affine (0) or perspective (1) output is supported')
    text = data.decode('ascii')
    lines = text.splitlines(keepends=True)
    sections = [line.split('#', 1)[0].strip().upper() for line in lines]
    if sections.count('3DO 2.1') != 1 or sections.count('SECTION: GEOMETRYDEF') != 1 or sections.count('SECTION: HIERARCHYDEF') != 1:
        raise ValueError('Expected one 3DO 2.1 geometry and hierarchy section')
    start = sections.index('SECTION: GEOMETRYDEF') + 1
    end = sections.index('SECTION: HIERARCHYDEF')
    if start >= end:
        raise ValueError('Hierarchy must follow geometry')
    remaining, face_index = 0, 0
    mesh_modes, face_modes, changes = Counter(), Counter(), []
    mesh_count = 0
    for i in range(start, end):
        line = lines[i]
        content = line.split('#', 1)[0].strip()
        if not content:
            continue
        if remaining:
            match = FACE.match(line)
            if not match or int(match[2]) != face_index:
                raise ValueError(f'Unexpected face row at line {i+1}')
            field = 3
            face_modes[int(match[field])] += 1
            remaining -= 1
            face_index += 1
        else:
            if re.fullmatch(r'MESH\s+\d+', content, re.I):
                mesh_count += 1
            count = FACES.fullmatch(content)
            if count:
                remaining, face_index = int(count[1]), 0
                continue
            match = HEADER.match(line)
            if not match:
                continue
            field = 2
            mesh_modes[int(match[field])] += 1
        if mode is not None and int(match[field]) != mode:
            a, b = match.span(field)
            lines[i] = line[:a] + str(mode) + line[b:]
            changes.append({'line': i+1, 'column': a+1, 'old': int(match[field]), 'new': mode})
    if remaining or not mesh_count or sum(mesh_modes.values()) != mesh_count:
        raise ValueError('Truncated faces or missing mesh texture-mode declarations')
    output = ''.join(lines).encode('ascii')
    differences = [i for i, (a, b) in enumerate(zip(data, output)) if a != b]
    if len(data) != len(output) or len(differences) != len(changes):
        raise AssertionError('Only one-byte texture-mode tokens may change')
    report = {'scope': 'Texture-mode fields only; not a complete geometry, KEY, material or runtime validation',
              'input_sha256': hashlib.sha256(data).hexdigest(), 'output_sha256': hashlib.sha256(output).hexdigest(),
              'mesh_modes': dict(mesh_modes), 'face_modes': dict(face_modes), 'mesh_count_all_geosets': mesh_count,
              'requested_mode': mode, 'changed_token_count': len(changes), 'changes': changes,
              'other_bytes_preserved': True}
    return output, report


def write_copy(source, output, mode):
    source, output = Path(source), Path(output)
    if source.resolve() == output.resolve():
        raise ValueError('Input and output must be different files')
    data = source.read_bytes()
    converted, report = convert(data, mode)
    # Exclusive creation also refuses an existing file, hard link or symlink.
    with output.open('xb') as stream:
        stream.write(converted)
    if output.read_bytes() != converted or source.read_bytes() != data:
        raise RuntimeError('Readback or input preservation failed')
    report['output'] = str(output)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--mode', type=int, choices=(0, 1))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.output is not None and args.mode is None:
        parser.error('--output requires --mode')
    if args.output is None:
        _, report = convert(args.input.read_bytes(), args.mode)
        report['written'] = False
    else:
        report = write_copy(args.input, args.output, args.mode)
        report['written'] = True
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
