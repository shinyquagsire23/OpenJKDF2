#!/usr/bin/env python3
"""Compile actual sound storage/eviction functions with asset-free controlled IO."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    paths = ['src/Devices/sithSound.c', 'src/Devices/sithSound.h', 'src/World/sithWorld.c',
             'src/Cog/sithCogExec.c', 'src/types.h', 'src/Tests/sound_cache_test.c',
             'src/Tests/run_sound_cache_test.py', 'src/engine_config.h']
    sources = {p: (ROOT / p).read_bytes() for p in paths}
    value = re.sub(r'^#include[^\n]*\n', '', sources[paths[0]].decode(), flags=re.M)
    production = value[:value.index('#ifdef TARGET_RETRO_HOMEBREW\n// Added: fileRead')]
    production += value[value.index('int sithSound_UnloadData('):value.index('stdSound_buffer_t* sithSound_LoadData(')]
    production += value[value.index('int sithSound_FreeUpMemory('):value.index('stdSound_buffer_t* sithSound_InitFromPath(')]
    header = sources[paths[1]].decode() + '\n' + sources['src/engine_config.h'].decode()
    api = '\n'.join(line for line in header.splitlines()
                    if line.startswith('#define SITHSOUND_') or re.match(r'^(int|void|sithSound\*) sithSound_.*;', line)
                    and not line.startswith('int sithSound_LoadFileData'))
    types = sources['src/types.h'].decode()
    file_types = set(re.findall(r'^typedef\s+\w+\s+stdFile_t;', types, re.M))
    if len(file_types) != 1:
        raise RuntimeError('Expected one platform-independent file-handle type; review fixture.')
    sound_type = types[types.index('typedef struct sithSound\n'):types.index('} sithSound;') + len('} sithSound;')]
    world = sources[paths[2]].decode()
    shutdown = world[world.index('void sithWorld_Shutdown()'):world.index('void sithWorld_SetLoadProgressCallback(')]
    assert 'sithSound_GetWorldSoundByIndex(pWorld, i)' in world
    cog_source = sources[paths[3]].decode()
    cog = cog_source[cog_source.index('sithSound* sithCogExec_PopSound('):cog_source.index('SithSector* sithCogExec_PopSector(')]
    assert 'return sithSound_GetWorldSoundByIndex(world, idx);' in cog and 'sounds[' not in cog
    memory = world[world.index('    aCount[6] = pWorld->numSoundsLoaded;'):world.index('    aCount[8] = pWorld->numCogScripts;')]
    logs = []
    with tempfile.TemporaryDirectory(prefix='openjkdf2-sound-cache-') as temp:
        stage = Path(temp)
        (stage / 'sound_api.inc').write_text(api)
        (stage / 'sound_type.inc').write_text(sound_type)
        (stage / 'file_type.inc').write_text(next(iter(file_types)) + '\n')
        (stage / 'sound_production.inc').write_text(production)
        (stage / 'sound_shutdown.inc').write_text(shutdown)
        (stage / 'sound_cog.inc').write_text(cog)
        (stage / 'sound_memory.inc').write_text(memory)
        (stage / 'sound_cache_test.c').write_bytes(sources['src/Tests/sound_cache_test.c'])
        command = [os.environ.get('CC', 'gcc'), '-std=c11', '-DNO_JK_MMAP', '-Wall', '-Wextra', '-Werror',
                   '-Wno-unused-variable', '-Wno-unused-function', '-Wno-sign-compare', '-g', '-O1',
                   '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-no-pie', 'sound_cache_test.c', '-o', 'sound-cache']
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')

        def check(kind, build_command, expect_failure=None):
            built = subprocess.run(build_command, cwd=stage, capture_output=True, text=True, encoding="utf-8", timeout=90)
            if built.returncode:
                raise RuntimeError(built.stdout + built.stderr)
            result = subprocess.run([str(stage / 'sound-cache')], cwd=stage, env=env,
                                    capture_output=True, text=True, encoding="utf-8", timeout=90)
            logs.append(dict(kind=kind, exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr))
            if expect_failure:
                if result.returncode == 0 or expect_failure not in result.stderr:
                    raise RuntimeError('Negative control did not fail its expected assertion: ' + result.stderr)
            elif result.returncode:
                raise RuntimeError(result.stdout + result.stderr)

        check('production-standalone', command)
        # Keep the full shutdown body and compose the adjacent model-cache cleanup.
        composed = shutdown
        if 'sithModel_FreeWorldModels(' not in composed:
            anchor = '        SITH_FREE(sithWorld_g_pCurrentWorld);'
            if composed.count(anchor) != 1:
                raise RuntimeError('Review shutdown fallback boundary')
            composed = composed.replace(anchor,
                '#ifdef NO_JK_MMAP\n'
                '        if (sithWorld_g_pCurrentWorld->aModels)\n'
                '            sithModel_FreeWorldModels(sithWorld_g_pCurrentWorld);\n'
                '#endif\n' + anchor)
        (stage / 'sound_shutdown.inc').write_text(composed, encoding='utf-8')
        check('composed-shutdown', command + ['-DTEST_COMPOSED_SHUTDOWN'])
        call = 'sithModel_FreeWorldModels(sithWorld_g_pCurrentWorld);'
        if composed.count(call) != 1: raise RuntimeError('Review counterpart cleanup control')
        (stage / 'sound_shutdown.inc').write_text(composed.replace(call, '(void)0;'), encoding='utf-8')
        check('missing-counterpart-cleanup-negative-control', command + ['-DTEST_COMPOSED_SHUTDOWN'],
              'counterpart_world->aModels')
        (stage / 'sound_shutdown.inc').write_text(shutdown, encoding='utf-8')
        check('legacy-fixed-allocation', [p for p in command if p != '-DNO_JK_MMAP'])
        mutants = [
            ('fixed-capacity', 'pendingPage = sithSound_NewPage(sithWorld_g_pLastLoadedWorld);',
             'pendingPage = (0 ? sithSound_NewPage(sithWorld_g_pLastLoadedWorld) : NULL);', "load(1, 'f')"),
            ('ignored-cache-failure', 'if (!stdHashtbl_Add(sithSound_hashtable, sound->sound_fname, sound))',
             'if (!stdHashtbl_Add(sithSound_hashtable, sound->sound_fname, sound) && 0)', "!load(1, 'f')"),
            ('eviction-skips-pages', 'sithSound *sound = sithSound_GetWorldSoundByIndex(world, v3);',
             'sithSound *sound = v3 == 0 ? sithSound_GetWorldSoundByIndex(world, v3) : NULL;', 'sithSound_FreeUpMemory(400) == 400'),
            ('leaked-page', 'SITH_FREE(page);', '(void)page;', '!live_allocations && !sithSound_pages'),
            ('static-id-alias', 'sound->id |= 0x8000;', 'sound->id |= 0x8001;', 'last->id == 0xfffe'),
        ]
        for name, before, after, failure in mutants:
            assert production.count(before) == 1, name
            (stage / 'sound_production.inc').write_text(production.replace(before, after))
            check(name + '-negative-control', command, failure)
    for p, data in sources.items():
        assert (ROOT / p).read_bytes() == data, p
    receipt = dict(schema='openjkdf2.sound-cache-test.v1', sanitizers=['address', 'undefined'], game_launched=False,
                   boundary='production storage, ID lookup, PCM eviction/free, and world shutdown; synthetic WAV/audio/cache IO',
                   logs=logs, source_sha256={p: hashlib.sha256(data).hexdigest() for p, data in sources.items()})
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
