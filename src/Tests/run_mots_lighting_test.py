#!/usr/bin/env python3
"""Asset-free execution of production MotS lighting paths and old-behavior controls.

Runs complete alpha-pass, world RGB primitive/clippers and scoped ARCH draw
functions. Solid-color normalization/encoding are unmodified contiguous blocks
from rdCache_SendFaceListToHardware, with a synthetic cache/colormap wrapper.
Also executes the placed-thing loader, template copy/reset and argument tokenizer
with original text fixtures, in builds with and without JKM_LIGHTING.
This is CPU data-path validation, not a renderer screenshot or retail parity test.
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

sys.dont_write_bytecode = True
from source_test_utils import extract_block, find_compiler

ROOT = Path(__file__).resolve().parents[2]
PATHS = ('src/Engine/sithRender.c', 'src/Raster/rdCache.c',
         'src/Primitives/rdPrimit3.c', 'src/Engine/rdClip.c',
         'src/types.h', 'src/types_enums.h', 'src/Engine/rdLight.c',
         'src/Primitives/rdModel3.c', 'src/World/sithThing.c',
         'src/General/stdConffile.c')


def between(text, start, end):
    if text.count(start) != 1 or text.count(end) != 1:
        raise RuntimeError('Production block boundaries changed: ' + start)
    return text.split(start, 1)[1].split(end, 1)[0]


def prepare(work):
    inputs = {name: (ROOT / name).read_bytes() for name in PATHS}
    src = {name: data.decode('utf-8').replace('\r\n', '\n') for name, data in inputs.items()}
    def write(name, text):
        (work / name).write_text(text + '\n', encoding='utf-8', newline='\n')
    render = src[PATHS[0]]
    alpha = extract_block(render, r'^void sithRender_RenderAlphaAdjoins\(', 'alpha pass')
    write('actual_alpha.inc', alpha)
    arch = extract_block(render, r'^static int sithRender_DrawLevelGeometryThing\(', 'ARCH draw scope')
    write('actual_arch.inc', arch)
    # Independent controls preserve the production body and remove only each
    # repaired decision. They must be rejected by behavioral expectations.
    old_alpha = alpha.replace('rdSetVertexColorMode(rdroid_curAcceleration && (sithRender_renderflags & 0x80));',
                              'rdSetVertexColorMode(0);')
    if old_alpha == alpha:
        raise RuntimeError('Alpha mode control changed')
    write('old_alpha.inc', old_alpha)
    primitive = extract_block(src[PATHS[2]], r'^void rdPrimit3_ClipFaceRGBLevel\b', 'world RGB primitive')
    write('actual_primitive.inc', primitive)
    write('actual_model_primitive.inc', '\n'.join(extract_block(src[PATHS[2]],
          r'^void\s+' + name + r'\b', name) for name in ('rdPrimit3_NoClipFaceRGB', 'rdPrimit3_ClipFaceRGB')))
    light = extract_block(src[PATHS[6]], r'^flex_t rdLight_CalcVertexIntensities\(', 'model vertex lighting')
    write('actual_light.inc', light)
    old_light = light.replace('aVertexColors ? *aVertexColors++ : 0.0', 'aVertexColors ? *aVertexColors : 0.0')
    if old_light == light:
        raise RuntimeError('Vertex base control changed')
    write('old_light.inc', old_light)
    model_call = re.search(r'    pMesh->extraLight = rdLight_CalcVertexIntensities\([\s\S]*?\);', src[PATHS[7]])
    if model_call is None:
        raise RuntimeError('Model lighting call changed')
    write('actual_model_light_call.inc', model_call.group())
    old_call = model_call.group().replace('rdGetVertexColorMode() == 1 ? NULL : pCurMesh->vertices_i', 'pCurMesh->vertices_i')
    if old_call == model_call.group():
        raise RuntimeError('RGB double-base control changed')
    write('old_model_light_call.inc', old_call)
    clips = src[PATHS[3]]
    write('actual_clip.inc', '\n'.join(extract_block(clips, r'^int ' + name + r'\(', name)
          for name in ('rdClip_Face3GSRGB', 'rdClip_Face3GTRGB')))
    # Use the production stack work-buffer declarations rather than a private
    # larger buffer that could hide an overrun.
    write('actual_clip_buffers.inc', between(clips, '#else // RDCLIP_WORK_BUFFERS_IN_STACK_MEM\n',
                                            '// TODO: Non-GT versions...?').rsplit('#endif', 1)[0])
    cache = extract_block(src[PATHS[1]], r'^int rdCache_SendFaceListToHardware\(', 'hardware cache')
    normalize = between(cache, '\nsolid_tri:\n', '\nLABEL_232:\n')
    encode = between(cache, '            if ( lighting_capability == 0) // Added: v137 nullptr check\n',
                     '\nskip_colormap_deref:\n')
    encode = '            if ( lighting_capability == 0)\n' + encode
    write('actual_solid_normalize.inc', normalize)
    write('actual_solid_encode.inc', encode)
    things = src[PATHS[8]]
    loader = extract_block(things, r'^int sithThing_ReadStaticThingsListText\(', 'placed thing loader')
    write('actual_thing_loader.inc', loader)
    # Move the actual inheritance call back after the positional assignment.
    # This restores the baseline ordering without replacing the loader logic.
    inheritance = '                sithThing_SetThingBasedOn(v21, v22);\n'
    positional = '                    v21->archlightIdx = v23;\n                }\n#endif\n'
    if loader.count(inheritance) != 1 or loader.count(positional) != 1:
        raise RuntimeError('Placed ARCH ordering control changed')
    old_loader = loader.replace(inheritance, '').replace(positional, positional + inheritance)
    write('old_thing_loader.inc', old_loader)
    write('actual_thing_helpers.inc', '\n'.join(extract_block(things,
          r'^(?:int|void|SithThing\*) ' + name + r'\(', name) for name in
          ('sithThing_Reset', 'sithThing_SetThingBasedOn', 'sithThing_InitializeWorldThings',
           'sithThing_SetPositionAndOrient')))
    write('actual_thing_flags.inc', '        case THINGPARAM_THINGFLAGS:\n' + between(things,
          '        case THINGPARAM_THINGFLAGS:\n', '        case THINGPARAM_TIMER:\n'))
    write('actual_thing_args.inc', '\n'.join(extract_block(src[PATHS[9]],
          r'^int ' + name + r'\(', name) for name in
          ('stdConffile_ReadArgsFromStr', 'stdConffile_ReadArgs')))
    old_scale = re.sub(r'\*iter(Red|Green|Blue)Intense = v73;', r'*iter\1Intense = v73 * 63.0;', normalize)
    if old_scale == normalize:
        raise RuntimeError('Solid scale control changed')
    write('old_solid_normalize.inc', old_scale)
    old_channels = encode.replace('colors[baseLight].g', 'colors[baseLight].r').replace('colors[baseLight].b', 'colors[baseLight].r')
    if old_channels == encode:
        raise RuntimeError('Palette channel control changed')
    write('old_solid_encode.inc', old_channels)
    types = src[PATHS[4]]
    write('actual_thing_types.inc', '\n'.join(extract_block(types,
          r'^typedef struct ' + name + r'\s*\{', name) + ' ' + name + ';'
          for name in ('StdConffileArg', 'StdConffileEntry')))
    names = ('rdClipFrustum', 'rdColor24', 'rdColormap', 'rdProcEntry', 'rdMeshinfo', 'rdFace',
             'sithSurfaceInfo', 'sithArchLightMesh', 'sithArchLight', 'rdLight')
    write('actual_types.inc', '\n'.join(extract_block(types, r'^typedef struct ' + name + r'\s*\{', name)
                                         + ' ' + name + ';' for name in names))
    enums = src[PATHS[5]]
    constants = []
    for name in ('RD_GEOMETRY_SOLID', 'RD_GEOMETRY_FULL', 'RD_LIGHTMODE_FULLYLIT', 'RD_LIGHTMODE_NOTLIT',
                 'RD_LIGHTMODE_DIFFUSE', 'RD_LIGHTMODE_GOURAUD', 'RD_ZBUFFER_READ_NOWRITE',
                 'RD_ZBUFFER_READ_WRITE', 'SPHERE_FULLY_INSIDE', 'SPHERE_FULLY_OUTSIDE', 'SPHERE_CLIPPING_EDGE',
                 'CLIPSTAT_LEFT', 'CLIPSTAT_RIGHT', 'CLIPSTAT_NONE_VISIBLE', 'RD_THING_MODEL3',
                 'RD_THING_PARTICLE', 'SITH_MT_PATH'):
        matches = re.findall(r'^\s*' + name + r'\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)', enums, re.M)
        if len(matches) != 1:
            raise RuntimeError('Constant changed: ' + name)
        constants.append('enum { ' + name + ' = ' + matches[0] + ' };')
    write('actual_constants.inc', '\n'.join(constants))
    shutil.copyfile(Path(__file__).with_name('mots_lighting_test.c'), work / 'mots_lighting_test.c')
    shutil.copyfile(Path(__file__).with_name('mots_thing_loader_test.c'), work / 'mots_thing_loader_test.c')
    return inputs


def execute(command, cwd, env):
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=120)
    return result


def run(cc, sanitize):
    with tempfile.TemporaryDirectory(prefix='openmots-lighting-') as tmp:
        work = Path(tmp)
        inputs = prepare(work)
        env = os.environ.copy()
        flags = ['-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                 '-Wno-unused-variable', '-Wno-unused-but-set-variable', '-Wno-unused-label',
                 '-Wno-unused-function', '-Wno-unused-parameter', '-Wno-sign-compare']
        if sanitize:
            flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
            env.setdefault('ASAN_OPTIONS', 'detect_leaks=1:halt_on_error=1')
            env['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
        print(subprocess.check_output([cc, '--version'], text=True).splitlines()[0])
        for name, defines, scenario in (
            ('current', [], None), ('old-alpha', ['-DOLD_ALPHA'], 'alpha'),
            ('old-scale', ['-DOLD_SCALE'], 'solid'), ('old-channels', ['-DOLD_CHANNELS'], 'solid'),
            ('old-vertex-base', ['-DOLD_VERTEX_BASE'], 'model'),
            ('old-double-base', ['-DOLD_DOUBLE_BASE'], 'model')):
            binary = work / (name + ('.exe' if os.name == 'nt' else ''))
            built = execute([cc, *flags, *defines, 'mots_lighting_test.c', '-lm', '-o', str(binary)], work, env)
            if built.returncode:
                raise RuntimeError('Compile ' + name + ':\n' + built.stdout + built.stderr)
            result = execute([str(binary)] + ([scenario] if scenario else []), work, env)
            if scenario:
                if result.returncode != 1 or 'FAIL ' + scenario not in result.stderr:
                    raise RuntimeError('Old-behavior control was not rejected: ' + name + '\n' + result.stdout + result.stderr)
                print('PASS rejected ' + name + ' by independent expected output')
            elif result.returncode:
                raise RuntimeError('Production path failure:\n' + result.stdout + result.stderr)
            else:
                print(result.stdout, end='')
        for name, defines, control in (
            ('thing-loader-mots', ['-DJKM_LIGHTING'], False),
            ('thing-loader-jk', [], False),
            ('old-thing-loader', ['-DJKM_LIGHTING', '-DOLD_THING_LOADER'], True)):
            binary = work / (name + ('.exe' if os.name == 'nt' else ''))
            built = execute([cc, *flags, *defines, 'mots_thing_loader_test.c', '-o', str(binary)], work, env)
            if built.returncode:
                raise RuntimeError('Compile ' + name + ':\n' + built.stdout + built.stderr)
            result = execute([str(binary)], work, env)
            if control:
                if result.returncode != 1 or 'FAIL thing-loader' not in result.stderr:
                    raise RuntimeError('Old loader ordering was not rejected:\n' + result.stdout + result.stderr)
                print('PASS rejected old-thing-loader by independent placed ARCH expectation')
            elif result.returncode:
                raise RuntimeError('Production loader failure:\n' + result.stdout + result.stderr)
            else:
                print(result.stdout, end='')
        for name, data in inputs.items():
            if (ROOT / name).read_bytes() != data:
                raise RuntimeError('Production input changed during test: ' + name)
            print('SHA256', hashlib.sha256(data).hexdigest(), name)
        print('PASS ASan+UBSan enabled' if sanitize else 'PASS unsanitized run (sanitizers not requested)')


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
