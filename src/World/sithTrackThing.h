#ifndef _SITHTRACKTHING_H
#define _SITHTRACKTHING_H

#include "types.h"

#define sithTrackThing_SkipToFrame_ADDR (0x004FA770)
#define sithTrackThing_MoveToFrame_ADDR (0x004FA840)
#define sithTrackThing_RotatePivot_ADDR (0x004FA8A0)
#define sithTrackThing_Rotate_ADDR (0x004FA980)
#define sithTrackThing_Arrivedidk_ADDR (0x004FAAC0)
#define sithTrackThing_sub_4FACC0_ADDR (0x004FACC0)
#define sithTrackThing_PrepareForOrient_ADDR (0x004FAD50)
#define sithTrackThing_Tick_ADDR (0x004FAF00)
#define sithTrackThing_LoadPathParams_ADDR (0x004FB390)
#define sithTrackThing_BlockedIdk_ADDR (0x004FB4E0)
#define sithTrackThing_StoppedMoving_ADDR (0x004FB500)
#define sithTrackThing_Stop_ADDR (0x004FB5F0)
#define sithTrackThing_PathMovePause_ADDR (0x004FB650)
#define sithTrackThing_PathMoveResume_ADDR (0x004FB690)
#define sithTrackThing_idkpathmove_ADDR (0x004FB6D0)

void sithTrackThing_MoveToFrame(sithThing *thing, int goalFrame, flex_t a3);
void sithTrackThing_Arrivedidk(sithThing *thing);
void sithTrackThing_Tick(sithThing *thing, flex_t deltaSeconds);
void sithTrackThing_BlockedIdk(sithThing* pThing);
void sithTrackThing_StoppedMoving(sithThing* pThing);
void sithTrackThing_PrepareForOrient(sithThing *thing, rdVector3 *a2, flex_t a3);
int sithTrackThing_LoadPathParams(stdConffileArg *arg, sithThing *thing, int param);
void sithTrackThing_Stop(sithThing *thing);
void sithTrackThing_idkpathmove(sithThing *thing, sithThing *thing2, rdVector3 *a3);
void sithTrackThing_RotatePivot(sithThing *thing, rdVector3 *a2, rdVector3 *a3, flex_t a4);
void sithTrackThing_Rotate(sithThing *trackThing, rdVector3 *rot);
void sithTrackThing_SkipToFrame(sithThing *trackThing, uint32_t goalframeNum, flex_t a3);
int sithTrackThing_PathMovePause(sithThing *trackThing);
int sithTrackThing_PathMoveResume(sithThing *trackThing);

//static int (*sithTrackThing_LoadPathParams)(stdConffileArg *arg, sithThing *thing, int a3) = (void*)sithTrackThing_LoadPathParams_ADDR;
//static void (*sithTrackThing_Tick)(sithThing *thing, flex_t a2) = (void*)sithTrackThing_Tick_ADDR;
//static void (*sithTrackThing_Stop)(sithThing* thing) = (void*)sithTrackThing_Stop_ADDR;
//static void (*sithTrackThing_MoveToFrame)(sithThing *a1, int a2, flex_t a3) = (void*)sithTrackThing_MoveToFrame_ADDR;
//static void (*sithTrackThing_SkipToFrame)(sithThing *a1, int a2, flex_t a3) = (void*)sithTrackThing_SkipToFrame_ADDR;
//static int (*sithTrackThing_RotatePivot)(sithThing *a1, rdVector3 *a2, rdVector3 *a3, flex_t a4) = (void*)sithTrackThing_RotatePivot_ADDR;
//static void (*sithTrackThing_Rotate)(sithThing *a1, rdVector3 *a2) = (void*)sithTrackThing_Rotate_ADDR;
//static int (*sithTrackThing_PathMovePause)(sithThing *a1) = (void*)sithTrackThing_PathMovePause_ADDR;
//static int (*sithTrackThing_PathMoveResume)(sithThing *a1) = (void*)sithTrackThing_PathMoveResume_ADDR;
//static void (*sithTrackThing_idkpathmove)(sithThing *a1, sithThing *a2, rdVector3 *a3) = (void*)sithTrackThing_idkpathmove_ADDR;
//static void (*sithTrackThing_Arrivedidk)(sithThing *thing) = (void*)sithTrackThing_Arrivedidk_ADDR;
//static void (*sithTrackThing_PrepareForOrient)(sithThing *a1, rdVector3 *a2, flex_t a3) = (void*)sithTrackThing_PrepareForOrient_ADDR;

#endif // _SITHTRACKTHING_H
