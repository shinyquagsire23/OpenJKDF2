#!/usr/bin/env python3
"""Actual-type stepped consumer comparison; no VM/game/retail/network execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]

def braced(text,start):
    opening=text.index('{',start);depth=0
    # Function names and braces are stable anchors; types come from real headers.
    tokens=re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\x27(?:\\.|[^\x27\\])*\x27|[{}]',text[opening:],re.S)
    for token in tokens:
        depth+=(token.group()=='{')-(token.group()=='}')
        if depth==0:return text[start:opening+token.end()]
    raise ValueError('Unterminated source block')

def function(text,name):
    match=re.search(r'^(?:void|int|flex_t) '+name+r'\([^\n]*',text,re.M)
    if not match:raise ValueError(name)
    return braced(text,match.start())

def prepare(work):
    paths=['src/Main/sithMain.c','src/Gameplay/sithTime.c','src/World/sithWeapon.c','src/Gameplay/sithInventory.c','src/AI/sithAI.c','src/AI/sithAICmd.c','src/types.h','src/types_enums.h','src/engine_config.h','src/World/sithSoundClass.h']
    inputs={p:(ROOT/p).read_bytes() for p in paths};src={p:b.decode('utf-8').replace('\r\n','\n') for p,b in inputs.items()}
    main=src[paths[0]];start=main.index('if (NEEDS_STEPPED_PHYS)',main.index('++jkPlayer_currentTickIdx;'));step=braced(main,start);tail=main[start+len(step):];other=braced(tail,tail.index('{'))
    branch='static void production_normal_update(void){\n'+step+'\nelse\n'+other+'\n}\n'
    bodies={'time.inc':re.sub(r'^#include[^\n]*\n','',src[paths[1]],flags=re.M),
        'weapon.inc':'\n'.join(function(src[paths[2]],n) for n in ('sithWeapon_SetMountWait','sithWeapon_SetFireWait','sithWeapon_UpdateActorWeaponState','sithWeapon_ActivateWeapon')),
        'inventory.inc':'\n'.join(function(src[paths[3]],n) for n in ('sithInventory_ActivateBin','sithInventory_DeactivateBin','sithInventory_SendFire')),
        'ai.inc':'\n'.join(function(src[paths[4]],n) for n in ('sithAI_Process','sithAI_InstinctUpdate')),
        'turret.inc':function(src[paths[5]],'sithAICmd_TurretFire')}
    controls=function(src[paths[2]],'sithWeapon_ProcessWeaponControls')
    gate=re.search(r'if \( sithTime_g_secGameTime < sithWeapon_secMountWait \)\s*return 0;',controls)
    if not gate:raise ValueError('Mount gate changed')
    bodies['mount_gate.inc']=gate.group()
    sound=re.search(r'SITH_SC_FIRE1\s*=\s*(\d+)',src[paths[9]])
    bodies['sound_constant.inc']='enum { SITH_SC_FIRE1 = '+sound[1]+' };'
    bodies['globals.h']='/* Standalone fixture supplies global state; real structure headers are included. */'
    for name,body in bodies.items():(work/name).write_text(body+'\n',encoding='utf-8')
    # Restore the prior PR policy without changing step selection/delta/order.
    outer=branch
    marker='if (wholeFramesToApply != 0)'
    if marker in outer:
        block=braced(outer,outer.index(marker))
        outer=outer.replace(block,'',1)
        outer=outer.replace('sithControl_FinishRead();','sithControl_FinishRead();\n            sithTime_g_msecGameTime -= sithTime_g_frameTime;',1)
    sync='sithTime_g_secGameTime = (flex32_t)sithTime_g_msecGameTime * 0.001;'
    if outer.count(sync)!=1:raise ValueError('Expected one substep synchronization in outer-control variant')
    old=outer.replace(sync,'(void)0; /* prior incoherent seconds control */',1)
    return inputs,{'production':branch,'outer-controls':outer,'old-seconds':old}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--cc',default='cc');ap.add_argument('--sanitize',action='store_true');ap.add_argument('--output',type=Path);args=ap.parse_args()
    receipt={'scope':'Actual type headers and complete normal/time/weapon/bin/AI scheduler/turret bodies; source mount-guard block. Synthetic aim/input/world-iteration/COG/projectile seams. No full VM/native/retail/network test.','compiler':subprocess.check_output([args.cc,'--version'],text=True,encoding='utf-8',timeout=15).splitlines()[0],'sanitize':args.sanitize,'runs':[]}
    checks=0;errors=[]
    with tempfile.TemporaryDirectory(prefix='openjk-clock-consumers-') as tmp:
        work=Path(tmp);inputs,variants=prepare(work)
        receipt['source_sha256']={p:hashlib.sha256(b).hexdigest() for p,b in inputs.items()}
        env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        for micro in (False,True):
            for name,body in variants.items():
                (work/'branch.inc').write_text(body,encoding='utf-8')
                cmd=[args.cc,'-std=c99','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-variable','-Wno-unused-parameter','-Wno-unused-function','-Wno-parentheses','-Wno-sign-compare','-DLINUX','-DSTDSOUND_NULL','-DQOL_IMPROVEMENTS','-I',str(work),'-I',str(ROOT/'src')]
                if micro:cmd+=['-DMICROSECOND_TIME']
                if args.sanitize:cmd+=['-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer','-fno-pie','-no-pie']
                exe=work/'consumers';cmd+=[str(ROOT/'src/Tests/clock_consumers_test.c'),'-lm','-o',str(exe)]
                compiled=subprocess.run(cmd,capture_output=True,text=True,encoding='utf-8',env=env,timeout=45)
                if compiled.returncode:raise RuntimeError(compiled.stderr)
                run=subprocess.run([str(exe)],capture_output=True,text=True,encoding='utf-8',env=env,timeout=15)
                if run.returncode:raise RuntimeError(run.stdout+run.stderr)
                result=json.loads(run.stdout);receipt['runs'].append({'variant':name,'microsecond_time':micro,'compile_argv':cmd,'compile_deadline_seconds':45,'compile_exit':0,'compile_warnings':compiled.stderr,'run_deadline_seconds':15,'run_exit':0,'results':result})
                print(('microseconds' if micro else 'milliseconds')+'/'+name+': '+', '.join(c['case']+'='+str(c['weapon_fire_messages'])+'/'+str(c['bin_fire_messages'])+'/'+str(c['turret_fire_calls']) for c in result))
        def check(condition,label):
            nonlocal checks
            checks+=1
            if not condition:errors.append(label)
        for micro in (False,True):
            modes={r['variant']:{c['case']:c for c in r['results']} for r in receipt['runs'] if r['microsecond_time']==micro}
            for case,correct,previous in [('held-repeat-100ms',3,1),('held-repeat-500ms',5,1),('held-repeat-mp50hz',2,1),('held-repeat-unstepped',1,1)]:
                for field in ('weapon_fire_messages','bin_fire_messages','turret_fire_calls'):
                    check(modes['production'][case][field]==correct,case+' production '+field)
                    check(modes['old-seconds'][case][field]==previous,case+' old '+field)
            for field in ('weapon_fire_messages','bin_fire_messages'):
                check(modes['production']['control-activation-100ms'][field]==3,'new activation catches up: '+field)
                check(modes['outer-controls']['control-activation-100ms'][field]==1,'outer activation remains once: '+field)
                check(modes['production']['zero-step-activation'][field]==modes['outer-controls']['zero-step-activation'][field]==1,'zero-step unchanged: '+field)
            check(modes['production']['control-activation-then-bin-cancel']['bin_cancel_elapsed']==0,'same-frame cancellation must not return negative elapsed')
            check(modes['outer-controls']['control-activation-then-bin-cancel']['bin_cancel_elapsed']<-.09,'outer-control negative-duration control is exercised')
            check(modes['production']['mount-expiry-inside-frame']['control_accepted']==0,'first-step controls defer future mount deadline')
            check(modes['outer-controls']['mount-expiry-inside-frame']['control_accepted']==1,'outer controls accept elapsed mount deadline')
            check(modes['production']['zero-step-activation']['observations']==modes['outer-controls']['zero-step-activation']['observations'],'zero-step observations unchanged')
            check(modes['production']['zero-step-activation']['steps']==0,'zero-step case truly schedules no step')
        check(all((ROOT/p).read_bytes()==b for p,b in inputs.items()),'source bytes unchanged')
    receipt.update(checks=checks,failures=errors)
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    print(f'Consumer assertions: {checks} checks, {len(errors)} failures')
    for error in errors:print('FAIL '+error)
    raise SystemExit(bool(errors))

if __name__=='__main__':main()
