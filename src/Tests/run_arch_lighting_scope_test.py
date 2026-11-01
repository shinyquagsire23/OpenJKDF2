#!/usr/bin/env python3
"""Compile the actual internal ARCH scope helper with actual model/world types."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--cc',default='cc');ap.add_argument('--sanitize',action='store_true');ap.add_argument('--baseline-helper',type=Path);ap.add_argument('--negative-controls',action='store_true');args=ap.parse_args()
    with tempfile.TemporaryDirectory(prefix='openjk-arch-scope-') as tmp:
        work=Path(tmp)
        # Model headers include the generated global declarations. The fixture
        # supplies its few globals explicitly; no structure layout is replaced.
        (work/'globals.h').write_text('/* Standalone fixture: globals supplied by the test. */\n',encoding='utf-8')
        cmd=[args.cc,'-std=c99','-O1','-g','-Wall','-Wextra','-Werror','-DLINUX','-DSTDSOUND_NULL','-DJKM_LIGHTING','-I',str(work),'-I',str(ROOT/'src')]
        if args.baseline_helper:
            text=args.baseline_helper.read_text(encoding='utf-8');start=text.index('static int sithRender_DrawLevelGeometryThing(');opening=text.index('{',start);depth=0
            for i in range(opening,len(text)):
                depth+=(text[i]=='{')-(text[i]=='}')
                if depth==0:break
            (work/'arch_scope_baseline.inc').write_text(text[start:i+1],encoding='utf-8')
            cmd+=['-DARCH_SCOPE_BASELINE']
        if args.sanitize:cmd+=['-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie','-no-pie']
        exe=work/'arch-scope-test'
        cmd+=[str(ROOT/'src/Tests/arch_lighting_scope_test.c'),'-lm','-o',str(exe)]
        env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        def execute():
            build=subprocess.run(cmd,capture_output=True,text=True,encoding='utf-8',timeout=45,env=env)
            if build.returncode:raise RuntimeError(build.stderr)
            return subprocess.run([str(exe)],capture_output=True,text=True,encoding='utf-8',timeout=15,env=env)
        result=execute();print(result.stdout,end='');print(result.stderr,end='')
        if result.returncode:raise SystemExit(result.returncode)
        if args.negative_controls:
            header=(ROOT/'src/Engine/sithRenderArchLighting.h').read_text(encoding='utf-8')
            (work/'Engine').mkdir()
            controls={
                'missing-green-restore':('mesh->paGreenIntensities = saved[j].green;', '(void)0;'),
                'reused-active-buffer':('if (buffer->inUse) continue;', '(void)0;'),
            }
            for name,(old,new) in controls.items():
                if header.count(old)!=1:raise RuntimeError('Control anchor changed: '+name)
                (work/'Engine/sithRenderArchLighting.h').write_text(header.replace(old,new),encoding='utf-8')
                rejected=execute()
                if rejected.returncode!=1 or 'CHECK' in rejected.stderr or 'ERROR: AddressSanitizer' in rejected.stderr:
                    raise RuntimeError('Control not cleanly rejected: '+name+'\n'+rejected.stdout+rejected.stderr)
                if 'failures' not in rejected.stdout or not rejected.stderr:raise RuntimeError('No assertion evidence: '+name)
                print('PASS rejected '+name+' by pointer-restoration assertions')

if __name__=='__main__':main()
