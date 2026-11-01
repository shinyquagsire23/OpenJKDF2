#!/usr/bin/env python3
"""Compile the actual model-store functions with synthetic parsers and assets."""
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
    paths = ['src/World/sithModel.c', 'src/World/sithModel.h', 'src/World/sithWorld.c',
             'src/Cog/sithCogExec.c', 'src/Tests/model_cache_test.c', 'src/Tests/run_model_cache_test.py',
             'src/engine_config.h']
    sources = {p: (ROOT / p).read_bytes() for p in paths}
    value = sources[paths[0]].decode()
    value = re.sub(r'^#include[^\n]*\n', '', value, flags=re.M)
    # The report-only geometry accounting routine is outside the tested store.
    begin = value.index('uint32_t sithModel_GetModelMemUsage(')
    end = value.index('int sithModel_AllocWorldModels(', begin)
    production = value[:begin] + value[end:]
    header = sources[paths[1]].decode() + '\n' + sources['src/engine_config.h'].decode()
    api = '\n'.join(line for line in header.splitlines()
                    if line.startswith('#define SITHMODEL_') or re.match(r'^(int|void|rdModel3\*) sithModel_.*;', line))
    assert 'sithModel_GetWorldModelByIndex(pWorld, i)' in sources[paths[2]].decode()
    world = sources[paths[2]].decode()
    shutdown = world[world.index('void sithWorld_Shutdown()'):world.index('void sithWorld_SetLoadProgressCallback(')]
    cog = sources[paths[3]].decode().split('rdModel3* sithCogExec_PopModel3(', 1)[1].split('rdKeyframe*', 1)[0]
    assert 'return sithModel_GetModelByIndex(idx);' in cog and 'aModels[' not in cog
    logs = []
    with tempfile.TemporaryDirectory(prefix='openjkdf2-model-cache-') as temp:
        temp = Path(temp)
        (temp / 'model_api.inc').write_text(api)
        (temp / 'model_production.inc').write_text(production)
        (temp / 'model_shutdown.inc').write_text(shutdown)
        (temp / 'model_cache_test.c').write_bytes(sources[paths[4]])
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1', UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        compiler = os.environ.get('CC', 'gcc')
        command = [compiler, '-std=c11', '-DNO_JK_MMAP', '-Wall', '-Wextra', '-Werror', '-g', '-O1',
                   '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-no-pie', 'model_cache_test.c', '-o', 'model-cache']
        result = subprocess.run(command, cwd=temp, capture_output=True, text=True, encoding="utf-8", timeout=90)
        if result.returncode: raise RuntimeError(result.stdout + result.stderr)
        result = subprocess.run([str(temp / 'model-cache')], cwd=temp, env=env, capture_output=True, text=True, encoding="utf-8", timeout=90)
        logs.append(dict(kind='production', exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr))
        if result.returncode: raise RuntimeError(result.stdout + result.stderr)
        # Exercise the adjacent sound-cache cleanup even when this topic is independent.
        composed = shutdown
        if 'sithSound_FreeWorldSounds(' not in composed:
            anchor = '        SITH_FREE(sithWorld_g_pCurrentWorld);'
            if composed.count(anchor) != 1:
                raise RuntimeError('Review shutdown fallback boundary')
            composed = composed.replace(anchor,
                '#ifdef NO_JK_MMAP\n'
                '        if (sithWorld_g_pCurrentWorld->sounds)\n'
                '            sithSound_FreeWorldSounds(sithWorld_g_pCurrentWorld);\n'
                '#endif\n' + anchor)
        (temp / 'model_shutdown.inc').write_text(composed, encoding='utf-8')
        built = subprocess.run(command + ['-DTEST_COMPOSED_SHUTDOWN'], cwd=temp,
                               capture_output=True, text=True, encoding='utf-8', timeout=90)
        if built.returncode: raise RuntimeError(built.stdout + built.stderr)
        result = subprocess.run([str(temp / 'model-cache')], cwd=temp, env=env,
                                capture_output=True, text=True, encoding='utf-8', timeout=90)
        logs.append(dict(kind='composed-shutdown', exit_code=result.returncode,
                         stdout=result.stdout, stderr=result.stderr))
        if result.returncode: raise RuntimeError(result.stdout + result.stderr)
        # A removed counterpart cleanup must fail before its owning world is freed.
        call = 'sithSound_FreeWorldSounds(sithWorld_g_pCurrentWorld);'
        if composed.count(call) != 1: raise RuntimeError('Review counterpart cleanup control')
        (temp / 'model_shutdown.inc').write_text(composed.replace(call, '(void)0;'), encoding='utf-8')
        built = subprocess.run(command + ['-DTEST_COMPOSED_SHUTDOWN'], cwd=temp,
                               capture_output=True, text=True, encoding='utf-8', timeout=90)
        if built.returncode: raise RuntimeError(built.stdout + built.stderr)
        result = subprocess.run([str(temp / 'model-cache')], cwd=temp, env=env,
                                capture_output=True, text=True, encoding='utf-8', timeout=90)
        logs.append(dict(kind='missing-counterpart-cleanup-negative-control', exit_code=result.returncode,
                         stdout=result.stdout, stderr=result.stderr))
        if result.returncode == 0 or 'counterpart_world->sounds' not in result.stderr:
            raise RuntimeError('Counterpart cleanup control missed its ownership assertion\n' + result.stderr)
        (temp / 'model_shutdown.inc').write_text(shutdown, encoding='utf-8')
        legacy = [part for part in command if part != '-DNO_JK_MMAP']
        subprocess.run(legacy, cwd=temp, check=True, capture_output=True, text=True, encoding="utf-8", timeout=90)
        result = subprocess.run([str(temp / 'model-cache')], cwd=temp, env=env, capture_output=True, text=True, encoding="utf-8", timeout=30)
        logs.append(dict(kind='injected-executable-layout', exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr))
        if result.returncode: raise RuntimeError(result.stdout + result.stderr)
        # Reintroduce the original fixed-capacity behavior without changing tests.
        altered = production.replace('pendingPage = sithModel_NewPage(sithWorld_g_pLastLoadedWorld);',
                                     'pendingPage = (0 ? sithModel_NewPage(sithWorld_g_pLastLoadedWorld) : NULL);')
        assert altered != production
        (temp / 'model_production.inc').write_text(altered)
        subprocess.run(command, cwd=temp, check=True, capture_output=True, text=True, encoding="utf-8", timeout=90)
        result = subprocess.run([str(temp / 'model-cache')], cwd=temp, env=env, capture_output=True, text=True, encoding="utf-8", timeout=30)
        logs.append(dict(kind='fixed-capacity-negative-control', exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr))
        if result.returncode == 0 or "load(1, 'f')" not in result.stderr:
            raise RuntimeError('Original capacity mutant did not fail the expected growth assertion\n' + result.stderr)
    receipt = dict(schema='openjkdf2.model-cache-test.v1', sanitizers=['address', 'undefined'], game_launched=False,
                   model_parser='synthetic; malformed 3DO cleanup not tested', logs=logs,
                   source_sha256={p: hashlib.sha256(data).hexdigest() for p, data in sources.items()})
    for p, data in sources.items(): assert (ROOT / p).read_bytes() == data, p
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
