/* Scheduler clock fixture. Production functions are injected by the runner.
 * Game consumers are observation seams; ProcessCog and Event_Process are real.
 * This does not execute the COG VM, rendering, networking or game physics. */
#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef float flex_t;
typedef float flex32_t;
typedef double flex_d_t;
typedef struct sithCog {
    int flags, script_running;
    uint32_t msecNextPulseTime, msecPulseInterval, field_20, msecTimerTimeout;
} sithCog;
typedef struct {struct {int flags;} trackParams;} Thing;
typedef struct {Thing *aThings;} World;
static Thing things[1];
static World world={things},*sithWorld_g_pCurrentWorld=&world;
static sithCog pulseCog, sleepCog;
typedef struct {int value;} SithEventParams;
typedef struct SithEvent {uint32_t msecEventTime;int taskNum;SithEventParams params;struct SithEvent*pNextEvent;} SithEvent;
typedef struct {int startMode;uint32_t msecLastIntervalTime,rate;int(*pfProcess)(int32_t,SithEventParams*);} SithEventTask;
static SithEventTask sithEvent_aTasks[6];
static SithEvent *sithEvent_g_pFirstQueuedEvent, queuedEvent;
enum {SITH_COG_DISABLED=1,SITH_COG_PULSE_SET=2,SITH_COG_TIMER_SET=4,SITH_COG_DEBUG=8,
    SITH_MESSAGE_PULSE=13,SITH_MESSAGE_TIMER=14,SITHEVENT_TASKPERIODIC=1,
    DEBUGFLAG_NO_AIEVENTS=1,DEBUGFLAG_SLOWMO=0x400};
static int jkPlayer_bJankyPhysics,sithNet_isMulti,sithNet_isServer=1,sithNet_tickrate=30;
static int g_sithMode,g_debugmodeFlags,sithMessage_g_inputstream=1,sithControl_physStepsThisFrame;
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
static uint32_t pushedInt;
static float pushedFlex;
static void sithCogExec_PushInt(sithCog*c,uint32_t v){(void)c;pushedInt=v;}
static void sithCogExec_PushFlex(sithCog*c,float v){(void)c;pushedFlex=v;}
void sithCogFunction_GetGameTime(sithCog*);
void sithCogFunction_GetFlexGameTime(sithCog*);
void sithTime_SetFrameTime(int);
void sithCog_ProcessCog(sithCog*);
void sithEvent_Process(void);
enum {CONTROL,SOUND,PERIODIC,QUEUED,MESSAGE,AI,SURFACE,THING,MOTS,COG,PULSE,TIMER,WAKE,PHASES};
typedef struct {int phase;uint32_t ms;float sec;} Sample;
static Sample samples[4096];
static int nsamples,failures,checks,freedEvents;
static int counts[PHASES];
static int checkCogMonotonic,haveLastCog;
static uint32_t lastCogMs;
#define CHECK(c) do {++checks;if(!(c)){++failures;if(failures<=12)fprintf(stderr,"line %d failed: %s\n",__LINE__,#c);}}while(0)
static void observe(int phase){
    assert(nsamples<4096);
    sithCogFunction_GetGameTime(NULL);sithCogFunction_GetFlexGameTime(NULL);
    samples[nsamples++]=(Sample){phase,pushedInt,pushedFlex};++counts[phase];
    /* Match existing SetFrameTime/SetGameTime conversion, including float32
     * precision loss. Do not demand impossible late-session strict increases. */
    float expected=(float)pushedInt*.001;
    CHECK(pushedFlex==expected);
    if(checkCogMonotonic && phase==COG){
        if(haveLastCog)CHECK(pushedInt>=lastCogMs);
        lastCogMs=pushedInt;haveLastCog=1;
    }
}
static void sithControl_ReadControls(void){}
static void sithControl_Update(flex_t dt,uint32_t ms){(void)dt;(void)ms;observe(CONTROL);}
static void sithControl_FinishRead(void){}
static void sithSoundMixer_Update(flex_t dt){(void)dt;observe(SOUND);}
static void sithMessage_ProcessMessages(void){observe(MESSAGE);}
static void sithAI_Process(void){observe(AI);}
static void sithSurface_Tick(flex_t dt){(void)dt;observe(SURFACE);}
static void sithThing_Update(flex_t dt,uint32_t ms){(void)dt;(void)ms;observe(THING);}
static void sithThing_MotsTick(int a,int b,int c){(void)a;(void)b;(void)c;observe(MOTS);}
static void sithCog_ProcessCogs(void){observe(COG);sithCog_ProcessCog(&pulseCog);sithCog_ProcessCog(&sleepCog);}
static void sithCog_SendMessage(sithCog*c,int message,int a,int b,int d,int e,int f){
    (void)c;(void)a;(void)b;(void)d;(void)e;(void)f;
    observe(message==SITH_MESSAGE_PULSE?PULSE:TIMER);
}
static void sithCogExec_Execute(sithCog*c){observe(WAKE);c->script_running=0;}
static int periodic(int32_t elapsed,SithEventParams*p){CHECK(elapsed>10);CHECK(p==NULL);observe(PERIODIC);return 1;}
static int queued(int32_t elapsed,SithEventParams*p){CHECK(elapsed==0);CHECK(p==&queuedEvent.params);observe(QUEUED);return 1;}
static void sithEvent_FreeEvent(SithEvent*e){CHECK(e==&queuedEvent);++freedEvents;}

#include "stepped_clock_production.inc"

static void reset(uint32_t start,int multi,int rate,int janky,int slow){
    platformMsec=0;platformUsec=0;sithTime_g_bPaused=0;
    sithTime_Startup();sithTime_SetGameTime(start);
    sithNet_isMulti=multi;sithNet_tickrate=rate;jkPlayer_bJankyPhysics=janky;
    g_debugmodeFlags=slow?DEBUGFLAG_SLOWMO:0;
    nsamples=0;memset(counts,0,sizeof(counts));freedEvents=0;
    memset(sithEvent_aTasks,0,sizeof(sithEvent_aTasks));
    sithEvent_g_pFirstQueuedEvent=NULL;
    pulseCog=(sithCog){0};sleepCog=(sithCog){0};
}
static void update_frame(void){
    sithTime_Advance();
    uint32_t oldms=sithTime_g_msecGameTime,oldDelta=sithTime_g_frameTime;
    float oldsec=sithTime_g_secGameTime,oldflex=sithTime_g_frameTimeFlex,oldfps=sithTime_g_fps;
    production_normal_update();
    CHECK(sithTime_g_msecGameTime==oldms);CHECK(sithTime_g_secGameTime==oldsec);
    CHECK(sithTime_g_frameTime==oldDelta);CHECK(sithTime_g_frameTimeFlex==oldflex);CHECK(sithTime_g_fps==oldfps);
}
static void frame(uint32_t delta){
    platformMsec+=delta;platformUsec+=(uint64_t)delta*1000;update_frame();
}
static void basic_cases(void){
    const struct {int delta,multi,rate,janky,slow,steps;} cases[]={
        {33,0,30,0,0,5},{17,0,30,0,0,3},{7,0,30,0,0,1},{3,0,30,0,0,0},
        {33,1,30,0,0,5},{33,1,30,1,0,5},{40,1,100,0,0,2},
        {33,0,30,1,0,1},{100,0,30,0,0,15},{50,0,30,0,1,2},
    };
    for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++){
        reset(1000,cases[i].multi,cases[i].rate,cases[i].janky,cases[i].slow);frame(cases[i].delta);
        CHECK(counts[COG]==cases[i].steps);CHECK(counts[CONTROL]==1);
        CHECK(counts[SOUND]==cases[i].steps);CHECK(counts[THING]==cases[i].steps);
    }
}
static void pulse_sleep_event_case(void){
    reset(1000,0,30,0,0);
    pulseCog=(sithCog){.flags=SITH_COG_PULSE_SET|SITH_COG_TIMER_SET,
        .msecNextPulseTime=1000,.msecPulseInterval=12,.field_20=1012};
    sleepCog=(sithCog){.script_running=2,.msecTimerTimeout=1012};
    sithEvent_aTasks[1]=(SithEventTask){SITHEVENT_TASKPERIODIC,1000,10,periodic};
    sithEvent_aTasks[2].pfProcess=queued;
    queuedEvent=(SithEvent){.msecEventTime=1006,.taskNum=2};sithEvent_g_pFirstQueuedEvent=&queuedEvent;
    frame(33);
    CHECK(counts[PULSE]==3);CHECK(counts[TIMER]==1);CHECK(counts[WAKE]==1);
    CHECK(counts[PERIODIC]==2);CHECK(counts[QUEUED]==1);CHECK(freedEvents==1);
    uint32_t pulseMs[]={1000,1012,1024};float pulseSec[]={1.f,1.012f,1.024f};int pulse=0;
    for(int i=0;i<nsamples;i++){
        if(samples[i].phase==PULSE){CHECK(samples[i].ms==pulseMs[pulse]);CHECK(samples[i].sec==pulseSec[pulse]);++pulse;}
        if(samples[i].phase==TIMER)CHECK(samples[i].ms==1012);
        if(samples[i].phase==WAKE)CHECK(samples[i].ms==1018);
        if(samples[i].phase==QUEUED)CHECK(samples[i].ms==1012);
    }
    /* Next frame starts at 1033ms; the 1036ms pulse runs at 1039ms,
     * then again at 1051ms. The existing scheduler does not catch up pulses. */
    frame(33);CHECK(counts[COG]==10);CHECK(counts[PULSE]==5);
    float prev=-1;
    for(int i=0;i<nsamples;i++)if(samples[i].phase==PULSE){CHECK(samples[i].sec>prev);prev=samples[i].sec;}
}
static void boundary_cases(void){
    const uint32_t starts[]={0,16777216,268435456,UINT32_MAX-100};
    for(unsigned i=0;i<sizeof(starts)/sizeof(starts[0]);i++){
        reset(starts[i],0,30,0,0);frame(33);frame(3);frame(4);frame(7);frame(17);frame(50);
    }
    reset(1000,0,30,0,0);frame(3);CHECK(counts[COG]==0);frame(3);CHECK(counts[COG]==1);
    sithTime_Pause();CHECK(sithTime_g_bPaused==1);CHECK(sithTime_physicsRolloverFrames==0);
    platformMsec+=1000;platformUsec+=1000000;sithTime_Resume();CHECK(!sithTime_g_bPaused);
    int before=counts[COG];frame(7);CHECK(counts[COG]==before+1);
    /* Savegame/time reset uses existing Time_SetGameTime; no new accumulator. */
    sithTime_SetGameTime(123456);CHECK(sithTime_g_msecGameTime==123456);
    CHECK(sithTime_g_secGameTime==123.456f);frame(33);
}
static void irregular_frame_cases(void){
    /* A 6ms carry at150Hz is unreachable after round-to-nearest. Produce
     * a real3ms carry, then verify4ms schedules one step at1000, not two. */
    reset(997,0,30,0,0);frame(3);CHECK(counts[COG]==0);
    CHECK(fabs(sithTime_physicsRolloverFrames-.003)<.0000001);
    frame(4);CHECK(counts[COG]==1);
    for(int i=0;i<nsamples;i++)if(samples[i].phase==COG)CHECK(samples[i].ms==1000);
    CHECK(sithTime_g_msecGameTime==1004);

    const unsigned usec[]={3000,4000,1000,6750,11250,16667,33333,555,9445,50000};
    for(int mode=0;mode<4;mode++)for(int slow=0;slow<2;slow++){
        reset(1000,mode==1||mode==2,mode==2?100:30,mode==1||mode==3,slow);
        haveLastCog=0;checkCogMonotonic=1;
        for(int repeat=0;repeat<32;repeat++)for(unsigned n=0;n<sizeof(usec)/sizeof(usec[0]);n++){
            nsamples=0;platformUsec+=usec[n];platformMsec=platformUsec/1000;
            update_frame();
            /* round(float(frame count)) introduces a small rounding error,
             * hence the absolute100ns allowance around half a timestep. */
            CHECK(fabs(sithTime_physicsRolloverFrames)<=DELTA_PHYSTICK_FPS*.5+.0000001);
        }
        CHECK(haveLastCog);checkCogMonotonic=0;
    }
}
int main(void){
    basic_cases();pulse_sleep_event_case();boundary_cases();irregular_frame_cases();
    printf("stepped clock: %d checks, %d failures\n",checks,failures);
    return failures?1:0;
}
