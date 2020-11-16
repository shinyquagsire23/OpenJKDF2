#ifndef _SITHTRACKTHING_H
#define _SITHTRACKTHING_H

typedef struct sithThing sithThing;

#define sithTrackThing_SkipToFrame_ADDR (0x004FA770)
#define sithTrackThing_MoveToFrame_ADDR (0x004FA840)
#define sithTrackThing_RotatePivot_ADDR (0x004FA8A0)
#define sithTrackThing_Rotate_ADDR (0x004FA980)
#define sithTrackThing_Arrivedidk_ADDR (0x004FAAC0)
#define sithTrackThing_idk_ADDR (0x004FAF00)
#define sithTrackThing_LoadPathParams_ADDR (0x004FB390)
#define sithTrackThing_BlockedIdk_ADDR (0x004FB4E0)
#define sithTrackThing_StoppedMoving_ADDR (0x004FB500)
#define sithTrackThing_Stop_ADDR (0x004FB5F0)
#define sithTrackThing_PathMovePause_ADDR (0x004FB650)
#define sithTrackThing_PathMoveResume_ADDR (0x004FB690)
#define sithTrackThing_idkpathmove_ADDR (0x004FB6D0)

static void (*sithTrackThing_Stop)(sithThing* thing) = (void*)sithTrackThing_Stop_ADDR;
static void (*sithTrackThing_MoveToFrame)(sithThing *a1, int a2, float a3) = (void*)sithTrackThing_MoveToFrame_ADDR;
static void (*sithTrackThing_SkipToFrame)(sithThing *a1, int a2, float a3) = (void*)sithTrackThing_SkipToFrame_ADDR;
static int (*sithTrackThing_RotatePivot)(sithThing *a1, rdVector3 *a2, rdVector3 *a3, float a4) = (void*)sithTrackThing_RotatePivot_ADDR;
static void (*sithTrackThing_Rotate)(sithThing *a1, rdVector3 *a2) = (void*)sithTrackThing_Rotate_ADDR;
static int (*sithTrackThing_PathMovePause)(sithThing *a1) = (void*)sithTrackThing_PathMovePause_ADDR;
static int (*sithTrackThing_PathMoveResume)(sithThing *a1) = (void*)sithTrackThing_PathMoveResume_ADDR;

#endif // _SITHTRACKTHING_H
