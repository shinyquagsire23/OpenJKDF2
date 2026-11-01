#!/usr/bin/env python3
"""Compile real scheduler/time/COG functions against bounded consumer seams."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]

def braced(text,start):
    opening=text.index('{',start);depth=0
    for i in range(opening,len(text)):
        depth+=(text[i]=='{')-(text[i]=='}')
        if depth==0:return text[start:i+1]
    raise ValueError('unterminated production block')

def function(text,name):
    match=re.search(r'^(?:void|int) '+re.escape(name)+r'\([^\n]*',text,re.M)
    if not match:raise ValueError('missing '+name)
    return braced(text,match.start())

def production():
    main=(ROOT/'src/Main/sithMain.c').read_text()
    start=main.index('if (NEEDS_STEPPED_PHYS)',main.index('++jkPlayer_currentTickIdx;'))
    stepped=braced(main,start)
    tail=main[start+len(stepped):]
    otherwise=braced(tail,tail.index('{'))
    # This is the complete normal stepped/unstepped branch, including controls.
    branch='static void production_normal_update(void){\n'+stepped+'\nelse\n'+otherwise+'\n}\n'
    times=(ROOT/'src/Gameplay/sithTime.c').read_text()
    times=re.sub(r'^#include[^\n]*\n','',times,flags=re.M)
    cog=(ROOT/'src/Cog/sithCog.c').read_text()
    verbs=(ROOT/'src/Cog/sithCogFunction.c').read_text()
    events=(ROOT/'src/Gameplay/sithEvent.c').read_text()
    config=(ROOT/'src/engine_config.h').read_text()
    defs=[]
    for name in ('NEEDS_STEPPED_PHYS','TARGET_PHYSTICK_FPS','DELTA_PHYSTICK_FPS'):
        hits=re.findall(r'^#define '+name+r'[^\n]*',config,re.M)
        defs.append(hits[-1]) # desktop, not TARGET_RETRO_HOMEBREW
    defs+=['#define FIXED_TIMESTEP_PHYS','#define SITHTIME_MINDELTA 1','#define SITHTIME_MAXDELTA 500',
           '#define SITHTIME_MINDELTA_US 1','#define SITHTIME_MAXDELTA_US 500000']
    return '\n'.join(defs)+'\n'+times+'\n'+function(verbs,'sithCogFunction_GetGameTime')+'\n'+function(verbs,'sithCogFunction_GetFlexGameTime')+'\n'+function(cog,'sithCog_ProcessCog')+'\n'+function(events,'sithEvent_Process')+'\n'+branch

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--cc',default='cc');ap.add_argument('--sanitize',action='store_true');ap.add_argument('--negative-controls',action='store_true');args=ap.parse_args()
    code=production();fixture=(ROOT/'src/Tests/stepped_clock_test.c').read_text()
    variants={'production':code}
    if args.negative_controls:
        update='sithTime_g_secGameTime = (flex32_t)sithTime_g_msecGameTime * 0.001;'
        # Remove only the substep assignment; Time_SetFrameTime stays intact.
        head,branch=code.rsplit('static void production_normal_update',1)
        loop_start=branch.index('for (int i = 0; i < wholeFramesToApply; i++)')
        prefix,loop=branch[:loop_start],branch[loop_start:]
        if loop.count(update)!=1:raise ValueError('expected one substep synchronization')
        variants['missing-substep-sync']=head+'static void production_normal_update'+prefix+loop.replace(update,';',1)
        restore='sithTime_g_secGameTime = secGameTimeBeforeSteps;'
        if branch.count(restore)!=1:raise ValueError('expected one outer-time restore')
        variants['missing-outer-restore']=head+'static void production_normal_update'+branch.replace(restore,';',1)
        variants['wrong-clock-units']=head+'static void production_normal_update'+prefix+loop.replace(update,'sithTime_g_secGameTime = (flex32_t)sithTime_g_msecGameTime;',1)
    with tempfile.TemporaryDirectory(prefix='openjkdf2-clock-') as tmp:
        out=Path(tmp);(out/'fixture.c').write_text(fixture)
        for micro in (False,True):
            for name,source in variants.items():
                (out/'stepped_clock_production.inc').write_text(source)
                exe=out/('clock-test.exe' if __import__('os').name=='nt' else 'clock-test')
                cmd=[args.cc,'-std=c99','-O1','-g','-Wall','-Wextra','-Wno-unused-variable','-Wno-unused-function','-Wno-sign-compare','-Wno-parentheses']
                if micro:cmd+=['-DMICROSECOND_TIME']
                if args.sanitize:cmd+=['-fsanitize=address,undefined','-fno-omit-frame-pointer','-fno-pie','-no-pie']
                cmd+=[str(out/'fixture.c'),'-lm','-o',str(exe)]
                build=subprocess.run(cmd,capture_output=True,text=True,encoding='utf-8',timeout=45)
                if build.returncode:raise RuntimeError(build.stderr)
                if build.stderr:print(build.stderr,end='')
                result=subprocess.run([str(exe)],capture_output=True,text=True,encoding='utf-8',timeout=15)
                label=('microseconds' if micro else 'milliseconds')+'/'+name
                print(label+': '+result.stdout.strip())
                if name=='production':
                    if result.returncode:raise RuntimeError(result.stderr)
                elif result.returncode!=1 or 'failed:' not in result.stderr:
                    raise RuntimeError('negative control not rejected: '+label+'\n'+result.stderr)
                else:print('negative control rejected')

if __name__=='__main__':main()
