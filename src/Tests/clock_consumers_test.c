/* Actual production types and consumer bodies. Aim math, input, world
 * iteration, COG dispatch and projectile creation are controlled seams.
 * Counts due messages/calls, not in-game projectiles or native gameplay. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "types.h"
#include "sound_constant.inc"
static SithAIControlBlock sithAI_actors[1];
static int sithAI_inittedActors=0;
int Main_bMotsCompat=0;
static int sithNet_MultiModeFlags;
static SithAIClass aiClass;
static SithThing turretThing,targetThing,templateThing;
static SithPlayer player;
static SithThing thing={.idx=7,.actorParams={.pPlayer=&player}};
static sithCog weaponCog={0},binCog={0};
static SithInventoryType sithInventory_g_aTypes[SITHBIN_NUMBINS];
static int sithWeapon_8BD024=-1,sithWeapon_8BD05C,sithWeapon_CurWeaponMode,sithWeapon_senderIndex;
static flex_t sithWeapon_secMountWait,sithWeapon_fireWait,sithWeapon_fireRate,sithWeapon_LastFireTimeSecs,sithWeapon_8BD0A0[2];
static int jkPlayer_bJankyPhysics,sithNet_isMulti,sithNet_isServer=1,sithNet_tickrate=30;
static int g_sithMode,g_debugmodeFlags,sithMessage_g_inputstream,sithControl_physStepsThisFrame;
static flex_t stdControl_updateKHz=.001f,stdControl_updateHz=1000;
static flex_t sithTime_g_frameTimeFlex,sithTime_g_fps;
static flex32_t sithTime_g_secGameTime;
static uint32_t sithTime_g_frameTime,sithTime_g_msecGameTime,sithTime_g_clockTime;
static uint32_t sithTime_msecPauseStartTime;
static int sithTime_g_bPaused;
static uint32_t platformMsec;
static uint64_t platformUsec;
static uint32_t stdPlatform_GetTimeMsec(void){return platformMsec;}
static uint64_t Linux_TimeUs(void){return platformUsec;}
void sithTime_SetFrameTime(int);
static int controlAction,stepAction,steps,phase,controlAccepted;
static flex_t repeatDelay,cancelElapsed;
static int weaponCalls,binCalls,aiCalls;
typedef struct {int kind,phase;uint32_t ms;float sec;} Observation;
static Observation observations[1024];static int count;
static void observe(int kind){assert(count<1024);observations[count++]=(Observation){kind,phase,sithTime_g_msecGameTime,sithTime_g_secGameTime};}
static int sithInventory_GetCurrentWeapon(SithThing*p){return 0;}
static SithInventoryType* sithInventory_GetType(int n){return &sithInventory_g_aTypes[n];}
static void sithCog_SendMessage(sithCog*c,int msg,int a,int b,int d,int e,int f){observe(msg==SITH_MESSAGE_ACTIVATE?4:5);}
static flex_t sithCog_SendMessageEx(sithCog*c,int msg,int a,int b,int d,int e,int f,flex_t g,flex_t h,flex_t i,flex_t j){if(msg==SITH_MESSAGE_FIRE){if(c==&weaponCog)++weaponCalls;else ++binCalls;observe(c==&weaponCog?1:2);}return 0;}
static void sithCog_ThingSendMessage(SithThing*a,SithThing*b,int m){}
static void sithCog_ThingSendMessageEx(SithThing*a,SithThing*b,int m,flex_t d,flex_t e,flex_t f,flex_t g){}
static void sithThing_SyncThing(SithThing*t,int mask){}
static void sithAI_EmitEvent(SithAIControlBlock*a,int b,int c){}
static void sithPuppet_SetArmedMode(SithThing*a,int b){}
static void sithAI_sub_4EAD60(SithAIControlBlock*a){}
static flex_t _frand(void){return .5f;}
static int rdVector_IsZero3(rdVector3*v){return v->x==0&&v->y==0&&v->z==0;}
static void rdVector_Copy3(rdVector3*a,rdVector3*b){*a=*b;}
static void rdVector_ScaleAdd3Acc(rdVector3*a,rdVector3*b,flex_t c){}
static void rdVector_Normalize3Acc(rdVector3*a){}
static void rdMatrix_TransformVectorOrtho34(rdVector3*a,rdVector3*b,rdMatrix34*c){*a=*b;}
static void rdVector_ExtractAngle(rdVector3*a,rdVector3*b){*b=(rdVector3){0};}
static flex_t stdMath_NormalizeAngleAcute(flex_t a){return a;}
static void sithActor_UpdateAimJoints(SithThing*a){}
static void rdMatrix_Copy34(rdMatrix34*a,rdMatrix34*b){*a=*b;}
static void rdMatrix_PreRotate34(rdMatrix34*a,rdVector3*b){}
static void sithSoundClass_PlayModeFirst(SithThing*a,int b){}
static SithThing* sithWeapon_WeaponFire(SithThing*a,SithThing*b,rdVector3*c,rdVector3*d,int e,int f,flex_t g,int h,flex_t i){++aiCalls;observe(3);return NULL;}
static void sithActor_KillActor(SithThing*a,SithThing*b,int c){}
#define _memcpy memcpy
void sithAI_InstinctUpdate(SithAIControlBlock*);
#include "time.inc"
#include "weapon.inc"
#include "inventory.inc"
#include "turret.inc"
#include "ai.inc"
static void sithControl_ReadControls(void){}
static int actual_mount_gate(void){
#include "mount_gate.inc"
    return 1;
}
static void sithControl_Update(flex_t dt,uint32_t ms){
    phase=0;observe(0);
    if(controlAction==1){sithWeapon_ActivateWeapon(&thing,&weaponCog,repeatDelay,0);sithInventory_ActivateBin(&thing,&binCog,repeatDelay,1);}
    if(controlAction==2){sithWeapon_SetFireWait(&thing,repeatDelay);}
    if(controlAction==3 && actual_mount_gate()){++controlAccepted;sithWeapon_ActivateWeapon(&thing,&weaponCog,repeatDelay,0);}
}
static void sithControl_FinishRead(void){phase=1;}
static void sithSoundMixer_Update(flex_t dt){}
static void sithEvent_Process(void){}
static void sithMessage_ProcessMessages(void){}
static void sithSurface_Tick(flex_t dt){}
static void sithThing_Update(flex_t dt,uint32_t ms){
    ++steps;
    if(stepAction==1 && steps==1)cancelElapsed=sithInventory_DeactivateBin(&thing,NULL,1);
    sithWeapon_UpdateActorWeaponState(&thing);sithInventory_SendFire(&thing);
}
static void sithThing_MotsTick(int a,int b,int c){}
static void sithCog_ProcessCogs(void){}
#include "branch.inc"
static void run(const char*name,unsigned delta,flex_t delay,flex_t initialWait,int control,int action,int multi,int rate,int janky){
    platformMsec=0;platformUsec=0;sithTime_g_bPaused=0;g_debugmodeFlags=0;sithTime_Startup();sithTime_SetGameTime(1000);
    sithNet_isMulti=multi;sithNet_tickrate=rate;jkPlayer_bJankyPhysics=janky;
    memset(&player,0,sizeof(player));memset(sithAI_actors,0,sizeof(sithAI_actors));memset(&aiClass,0,sizeof(aiClass));
    sithWeapon_8BD024=-1;sithWeapon_8BD05C=0;sithWeapon_secMountWait=control==3?1.05f:0;sithWeapon_CurWeaponMode=(control==1 || control==3)?-1:0;
    sithWeapon_fireWait=initialWait;sithWeapon_fireRate=delay;repeatDelay=delay;
    sithInventory_g_aTypes[0]=(SithInventoryType){.flags=ITEMINFO_WEAPON,.cog=&weaponCog};
    sithInventory_g_aTypes[1]=(SithInventoryType){.flags=SITHINVENTORY_TYPE_AUTOAIM|SITHINVENTORY_TYPE_REGISTERED,.cog=&binCog};
    player.aItems[1]=(SithInventoryItem){.activationDelaySecs=delay,.binWait=initialWait,.activatedTimeSecs=1.0f};
    turretThing=(SithThing){.actorParams={.pWeaponTemplate=&templateThing,.health=100,.maxHealth=100}};
    targetThing=(SithThing){0};
    aiClass.entries[0].fltArg[0]=delay*1000;aiClass.entries[0].param1=SITHAI_MODE_ATTACKING;aiClass.entries[0].func=sithAICmd_TurretFire;
    sithAI_actors[0]=(SithAIControlBlock){.thing=&turretThing,.pDistractor=&targetThing,.pClass=&aiClass,.flags=SITHAI_MODE_ATTACKING,.numInstincts=1};
    sithAI_actors[0].aInstinctStates[0].param0=initialWait;
    weaponCalls=binCalls=aiCalls=count=steps=controlAccepted=0;controlAction=control;stepAction=action;cancelElapsed=0;
    platformMsec=delta;platformUsec=(uint64_t)delta*1000;sithTime_Advance();
    uint32_t outerMs=sithTime_g_msecGameTime;float outerSec=sithTime_g_secGameTime;
    production_normal_update();assert(sithTime_g_msecGameTime==outerMs&&sithTime_g_secGameTime==outerSec);
    printf("{\"control_accepted\":%d,\"case\":\"%s\",\"steps\":%d,\"weapon_fire_messages\":%d,\"bin_fire_messages\":%d,\"turret_fire_calls\":%d,\"bin_cancel_elapsed\":%.9g,\"outer_ms\":%u,\"observations\":[",controlAccepted,name,steps,weaponCalls,binCalls,aiCalls,cancelElapsed,outerMs);
    for(int i=0;i<count;i++){if(i)printf(",");printf("{\"kind\":%d,\"phase\":%d,\"ms\":%u,\"sec\":%.9g}",observations[i].kind,observations[i].phase,observations[i].ms,observations[i].sec);}
    printf("]}");
}
int main(void){
    printf("[");
    run("held-repeat-100ms",100,.025f,1.02f,0,0,0,30,0);printf(",\n");
    run("held-repeat-500ms",500,.1f,1.01f,0,0,0,30,0);printf(",\n");
    run("control-activation-100ms",100,.025f,.99f,1,0,0,30,0);printf(",\n");
    run("control-firewait-100ms",100,.025f,1.02f,2,0,0,30,0);printf(",\n");
    run("control-activation-then-bin-cancel",100,.025f,1.02f,1,1,0,30,0);printf(",\n");
    run("held-repeat-unstepped",100,.025f,1.02f,0,0,0,30,1);printf(",\n");
    run("held-repeat-mp50hz",100,.025f,1.02f,0,0,1,100,0);printf(",\n");
    run("mount-expiry-inside-frame",100,.025f,.99f,3,0,0,30,0);printf(",\n");
    run("zero-step-activation",3,.025f,.99f,1,0,0,30,0);
    printf("]\n");return 0;
}
