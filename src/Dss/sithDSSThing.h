#ifndef _DSS_SITHDSSTHING_H
#define _DSS_SITHDSSTHING_H

#include "types.h"
#include "globals.h"

#define sithDSSThing_Pos_ADDR (0x004F3120)
#define sithDSSThing_ProcessPos_ADDR (0x004F3270)
#define sithDSSThing_UpdateState_ADDR (0x004F3420)
#define sithDSSThing_ProcessStateUpdate_ADDR (0x004F35E0)
#define sithDSSThing_PlaySound_ADDR (0x004F37B0)
#define sithDSSThing_ProcessPlaySound_ADDR (0x004F3870)
#define sithDSSThing_PlaySoundMode_ADDR (0x004F3960)
#define sithDSSThing_ProcessPlaySoundMode_ADDR (0x004F39C0)
#define sithDSSThing_PlayKey_ADDR (0x004F3A30)
#define sithDSSThing_ProcessPlayKey_ADDR (0x004F3AA0)
#define sithDSSThing_PlayKeyMode_ADDR (0x004F3B30)
#define sithDSSThing_ProcessPlayKeyMode_ADDR (0x004F3B90)
#define sithDSSThing_SetModel_ADDR (0x004F3C00)
#define sithDSSThing_ProcessSetModel_ADDR (0x004F3C80)
#define sithDSSThing_StopKey_ADDR (0x004F3CF0)
#define sithDSSThing_ProcessStopKey_ADDR (0x004F3D50)
#define sithDSSThing_StopSound_ADDR (0x004F3DC0)
#define sithDSSThing_ProcessStopSound_ADDR (0x004F3E10)
#define sithDSSThing_Fire_ADDR (0x004F3E70)
#define sithDSSThing_ProcessFire_ADDR (0x004F3F60)
#define sithDSSThing_Death_ADDR (0x004F4040)
#define sithDSSThing_ProcessDeath_ADDR (0x004F40B0)
#define sithDSSThing_DamageThing_ADDR (0x004F4120)
#define sithDSSThing_ProcessDamage_ADDR (0x004F41A0)
#define sithDSSThing_FullDescription_ADDR (0x004F4210)
#define sithDSSThing_ProcessFullDescription_ADDR (0x004F46F0)
#define sithDSSThing_PathMove_ADDR (0x004F4C60)
#define sithDSSThing_ProcessPathMove_ADDR (0x004F4D60)
#define sithDSSThing_Attachment_ADDR (0x004F4E80)
#define sithDSSThing_ProcessAttachment_ADDR (0x004F4F50)
#define sithDSSThing_Take_ADDR (0x004F5040)
#define sithDSSThing_ProcessTake_ADDR (0x004F5150)
#define sithDSSThing_CreateThing_ADDR (0x004F5220)
#define sithDSSThing_ProcessCreateThing_ADDR (0x004F52E0)
#define sithDSSThing_DestroyThing_ADDR (0x004F53D0)
#define sithDSSThing_ProcessDestroyThing_ADDR (0x004F5410)
#define sithSector_TransitionMovingThing_ADDR (0x004F5440)

void sithDSSThing_Pos(SithThing *pThing, int toID, int dpFlags);
int sithDSSThing_ProcessPos(SithMessage *pMsg);

void sithDSSThing_UpdateState(SithThing *pThing, int toID, int outstream);
int sithDSSThing_ProcessStateUpdate(SithMessage *pMsg);

void sithDSSThing_PlaySound(SithThing *pThing, rdVector3 *pPos, sithSound *hSnd, flex32_t volume, flex32_t pan, int playflags, int guid, int idTo, int outstream);
int sithDSSThing_ProcessPlaySound(SithMessage *pMsg);

void sithDSSThing_PlaySoundMode(SithThing *pThing, int16_t mode, int channel, flex32_t a4);
int sithDSSThing_ProcessPlaySoundMode(SithMessage *pMsg);

void sithDSSThing_PlayKey(SithThing *pThing, rdKeyframe *pKey, int flags, int16_t lo, int trackGUID, int idTo, int outstream);
int sithDSSThing_ProcessPlayKey(SithMessage *pMsg);

void sithDSSThing_PlayKeyMode(SithThing *pThing, int16_t mode, int trackGUID, int idTo, int outstream);
int sithDSSThing_ProcessPlayKeyMode(SithMessage *pMsg);

void sithDSSThing_SetModel(SithThing *pThing, int idTo);
int sithDSSThing_ProcessSetModel(SithMessage *pMsg);

void sithDSSThing_StopKey(SithThing *pThing, int trackGUID, flex32_t fadeTime, int idTo, int outstream);
int sithDSSThing_ProcessStopKey(SithMessage *pMsg);

void sithDSSThing_StopSound(sithPlayingSound *hChannel, flex32_t secFadeTime, int idTo, int outstream);
int sithDSSThing_ProcessStopSound(SithMessage *pMsg);

void sithDSSThing_Fire(SithThing *pWeapon, SithThing *pProjectile, rdVector3 *pFireOffset, rdVector3 *pAimError, sithSound *pFireSound, int16_t anim, flex32_t scale, int16_t scaleFlags, flex32_t a9, int thingId, int sendtoId, int mpFlags, int idk);
int sithDSSThing_ProcessFire(SithMessage *pMsg);
int sithDSSThing_ProcessMOTSNew2(SithMessage *msg);

void sithDSSThing_Death(SithThing *pThing, SithThing *pKiller, char bKillPlayer, int to, int outstream);
int sithDSSThing_ProcessDeath(SithMessage *pMsg);

void sithDSSThing_DamageThing(SithThing *pVictim, SithThing *pPurpetrator, flex32_t damage, int16_t hitType, int idTo, int outstream);
int sithDSSThing_ProcessDamage(SithMessage *pMsg);

void sithDSSThing_FullDescription(SithThing *pThing, int idTo, int outstream);
int sithDSSThing_ProcessFullDescription(SithMessage *pMsg);

void sithDSSThing_PathMove(SithThing *pThing, int16_t frame, flex32_t speed, int moveType, int idTo, int outstream);
int sithDSSThing_ProcessPathMove(SithMessage *pMsg);

void sithDSSThing_Attachment(SithThing *pThing, int idTo, int outstream, int sendFlags);
int sithDSSThing_ProcessAttachment(SithMessage *pMsg);

void sithDSSThing_Take(SithThing *pItem, SithThing *pThing, int outstream);
int sithDSSThing_ProcessTake(SithMessage *pMsg);

void sithDSSThing_CreateThing(SithThing *pTemplate, SithThing *pNewThing, SithThing *pMarker, SithSector *pSector, rdVector3 *pos, rdVector3 *pyr, int outstream, int sendFlags);
int sithDSSThing_ProcessCreateThing(SithMessage *pMsg);

void sithDSSThing_DestroyThing(int guid, int idTo);
int sithDSSThing_ProcessDestroyThing(SithMessage *pMsg);

void sithDSSThing_MoveToPos(SithThing *pThing, rdVector3 *pPos, SithSector *pSector);

int sithDSSThing_ProcessMOTSNew1(SithMessage *msg);
void sithDSSThing_SendMOTSNew1(SithThing* pThing1, SithThing* pThing2, SithThing* pThing3, SithSector* pSector, 
    rdVector3* pVec1, rdVector3* pVec2, int mpFlags, int param_8);

//static void (*sithDSSThing_PlayKey)(SithThing *a1, rdKeyframe *a2, int a3, wchar_t a4, int a5, int a6, int a7) = (void*)sithDSSThing_PlayKey_ADDR;
//static void (*sithDSSThing_StopKey)(SithThing *a1, int a2, flex32_t a3, int a4, int a5) = (void*)sithDSSThing_StopKey_ADDR;
//static void (*sithDSSThing_SetModel)(SithThing *a1, int a2) = (void*)sithDSSThing_SetModel_ADDR;
//static int (*sithDSSThing_StopSound)(sithPlayingSound *a1, flex32_t a2, int a3, int a4) = (void*)sithDSSThing_StopSound_ADDR;
//static int (*sithDSSThing_PlaySoundMode)(SithThing *a1, int16_t a2, int a3, flex32_t a4) = (void*)sithDSSThing_PlaySoundMode_ADDR;
//static int (*sithDSSThing_Fire)(SithThing *weapon, SithThing *projectile, rdVector3 *fireOffset, rdVector3 *aimError, sithSound *fireSound, __int16 anim, flex32_t scale, __int16 scaleFlags, flex32_t a9, int thingId, int a11, int a12) = (void*)sithDSSThing_Fire_ADDR;
//static void (*sithDSSThing_PathMove)(SithThing *a1, __int16 a2, flex32_t a3, int a4, int a5, int a6) = (void*)sithDSSThing_PathMove_ADDR;
//static void (*sithDSSThing_PlayKeyMode)(SithThing *a1, __int16 a2, int a3, int a4, int a5) = (void*)sithDSSThing_PlayKeyMode_ADDR;
//static void (*sithDSSThing_DestroyThing)(int a1, int a2) = (void*)sithDSSThing_DestroyThing_ADDR;
//static int (*sithDSSThing_CreateThing)(SithThing *a1, SithThing *a2, SithThing *a3, SithSector *a4, int *a5, int *a6, int a7, int a8) = (void*)sithDSSThing_CreateThing_ADDR;
//static void (*sithDSSThing_DamageThing)(SithThing *a1, SithThing *a2, flex32_t a3, __int16 a4, int a5, int a6) = (void*)sithDSSThing_DamageThing_ADDR;
//static void (*sithDSSThing_UpdateState)(SithThing *a1, int a2, int a3) = (void*)sithDSSThing_UpdateState_ADDR;
//static void (*sithDSSThing_Take)(SithThing *a1, SithThing *a2, int a3) = (void*)sithDSSThing_Take_ADDR;


#endif // _DSS_SITHDSSTHING_H