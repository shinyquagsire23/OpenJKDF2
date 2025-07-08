#ifndef _SITHCOG_H
#define _SITHCOG_H

#include "types.h"
#include "globals.h"
#include "Cog/sithCogExec.h"

#define jkCog_RegisterVerbs_ADDR (0x40A110)
#define jkCog_Startup_ADDR (0x40A0C0)
#define sithCogFunction_Startup_ADDR (0x00505400)
#define sithCogFunctionThing_Startup_ADDR (0x005014E0)
#define sithCogFunctionAI_Startup_ADDR (0x00500B00)
#define sithCogFunctionSound_Startup_ADDR (0x004FF060)
#define sithCogFunctionPlayer_Startup_ADDR (0x004E0780)
#define sithCogFunctionSector_Startup_ADDR (0x004FE680)
#define sithCogFunctionSurface_Startup_ADDR (0x004FFB50)

#define sithCog_Startup_ADDR (0x004DE070)
#define sithCog_Shutdown_ADDR (0x004DE590)
#define sithCog_Open_ADDR (0x004DE5D0)
#define sithCog_Close_ADDR (0x004DE7E0)
#define sithCog_Free_ADDR (0x004DE820)
#define sithCog_FreeEntry_ADDR (0x004DE9B0)
#define sithCog_Free2_ADDR (0x004DEA20)
#define sithCog_HandleThingTimerPulse_ADDR (0x004DEA60)
#define sithCog_SendSimpleMessageToAll_ADDR (0x004DEAD0)
#define sithCog_SendMessageToAll_ADDR (0x004DEB00)
#define sithCog_SendMessage_ADDR (0x004DEBE0)
#define sithCog_SendMessageEx_ADDR (0x004DEDC0)
#define sithCog_InitScripts_ADDR (0x004DEFF0)
#define sithCog_InitCogs_ADDR (0x004DF080)
#define sithCog_Load_ADDR (0x004DF110)
#define sithCog_LoadEntry_ADDR (0x004DF410)
#define sithCog_ThingsSectorsRegSymbolIdk_ADDR (0x004DF610)
#define sithCog_LoadCogscript_ADDR (0x004DF7D0)
#define sithCog_GetByIdx_ADDR (0x004DF930)
#define sithCog_ThingFromSymbolidk_ADDR (0x004DF980)
#define sithCog_Thingidk_ADDR (0x004DFA00)
#define sithCog_Sectoridk_ADDR (0x004DFA60)
#define sithCog_SendMessageFromThing_ADDR (0x004DFAC0)
#define sithCog_SendMessageFromThingEx_ADDR (0x004DFAF0)
#define sithCog_SendMessageFromSector_ADDR (0x004DFD60)
#define sithCog_SendMessageFromSectorEx_ADDR (0x004DFD90)
#define sithCog_SendMessageFromSurface_ADDR (0x004DFED0)
#define sithCog_SendMessageFromSurfaceEx_ADDR (0x004DFF00)
#define sithCogScript_Load_ADDR (0x004E0040)
#define sithCogScript_LoadEntry_ADDR (0x004E0240)
#define sithCogScript_Tick_ADDR (0x004E0300)
#define sithCogScript_TickAll_ADDR (0x004E0400)
#define sithCogScript_DevCmdCogStatus_ADDR (0x004E0480)
#define sithCogScript_RegisterMessageSymbol_ADDR (0x004E0600)
#define sithCogScript_TimerTick_ADDR (0x004E0640)
#define sithCogScript_RegisterGlobalMessage_ADDR (0x004E06C0)
#define sithCogScript_RegisterVerb_ADDR (0x004E0700)

#define COG_SHOULD_SYNC(ctx) (sithComm_multiplayerFlags && !(ctx->flags & SITH_COG_NO_SYNC) && ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN)


//static int32_t (*_sithCog_Load)(sithWorld *world, int32_t a2) = (void*)sithCog_Load_ADDR;
//static int32_t (*sithCogScript_Load)(sithWorld *world, int32_t a2) = (void*)sithCogScript_Load_ADDR;
//static void (*sithCogScript_RegisterVerb)(void* a, intptr_t func, char* cmd) = (void*)0x4E0700;
//static void (__cdecl *sithCog_SendMessage)(sithCog *a1, int32_t msgid, int32_t senderType, int32_t senderIndex, int32_t sourceType, int32_t sourceIndex, int32_t linkId) = (void*)0x4DEBE0;
//static flex_t (__cdecl *sithCog_SendMessageEx)(sithCog *a1, SITH_MESSAGE message, int32_t senderType, int32_t senderIndex, int32_t sourceType, int32_t sourceIndex, int32_t linkId, flex_t param0, flex_t param1, flex_t param2, flex_t param3) = (void*)0x4DEDC0;
//static void (*sithCog_HandleThingTimerPulse)(sithThing *a1) = (void*)sithCog_HandleThingTimerPulse_ADDR;
//static int32_t (*sithCog_ThingsSectorsRegSymbolIdk)(sithCog *a1, sithCogReference *a2, sithCogSymbol *a3) = (void*)sithCog_ThingsSectorsRegSymbolIdk_ADDR;
//static sithCog* (*_sithCog_LoadCogscript)(const char *fpath) = (void*)sithCog_LoadCogscript_ADDR;

int32_t sithCog_Startup();
int32_t sithCog_StartupEnhanced(); // Added
void sithCog_Shutdown();
int32_t sithCog_Open();
void sithCog_Close();
int sithCog_Load(sithWorld *world, int a2);
sithCog* sithCog_LoadCogscript(const char *fpath);
int32_t sithCog_LoadEntry(sithCogSymbol *cogSymbol, sithCogReference *cogIdk, char *val);
int32_t sithCog_ThingsSectorsRegSymbolIdk(sithCog *cog, sithCogReference *idk, sithCogSymbol *symbol);
void sithCog_HandleThingTimerPulse(sithThing *thing);

void sithCogFunction_Startup(sithCogSymboltable* a1);
void sithCogThing_Startup(sithCogSymboltable* a1);
void sithCogFunctionSound_Startup(sithCogSymboltable* a1);
void sithCogFunctionSector_Startup(sithCogSymboltable* a1);
void sithCogSurface_Startup(sithCogSymboltable* a1);

void sithCog_SendMessageFromThing(sithThing *a1, sithThing *a2, int32_t msg);
cog_flex_t sithCog_SendMessageFromThingEx(sithThing *sender, sithThing *receiver, SITH_MESSAGE message, cog_flex_t param0, cog_flex_t param1, cog_flex_t param2, cog_flex_t param3);
void sithCog_SendMessageFromSurface(sithSurface *surface, sithThing *thing, int32_t msg);
cog_flex_t sithCog_SendMessageFromSurfaceEx(sithSurface *sender, sithThing *thing, SITH_MESSAGE msg, cog_flex_t a4, cog_flex_t a5, cog_flex_t a6, cog_flex_t a7);
void sithCog_SendMessageFromSector(sithSector *sector, sithThing *thing, int32_t message);
cog_flex_t sithCog_SendMessageFromSectorEx(sithSector *a1, sithThing *sourceType, SITH_MESSAGE message, cog_flex_t param0, cog_flex_t param1, cog_flex_t param2, cog_flex_t param3);
void sithCog_SendSimpleMessageToAll(int32_t a1, int32_t a2, int32_t a3, int32_t a4, int32_t a5);
void sithCog_SendMessageToAll(int32_t cmdid, int32_t senderType, int32_t senderIdx, int32_t sourceType, int32_t sourceIdx, cog_flex_t arg0, cog_flex_t arg1, cog_flex_t arg2, cog_flex_t arg3);
void sithCog_SendMessage(sithCog *cog, int32_t msgid, int32_t senderType, int32_t senderIndex, int32_t sourceType, int32_t sourceIndex, int32_t linkId);
cog_flex_t sithCog_SendMessageEx(sithCog *cog, int32_t message, int32_t senderType, int32_t senderIndex, int32_t sourceType, int32_t sourceIndex, int32_t linkId, cog_flex_t param0, cog_flex_t param1, cog_flex_t param2, cog_flex_t param3);
void sithCog_Free(sithWorld *world);

//static int32_t (*_sithCog_Open)() = (void*)sithCog_Open_ADDR;
//static double (*sithCog_SendMessageFromSurfaceEx)(sithSurface *a1, sithThing *a2, int32_t a3, cog_flex_t a4, cog_flex_t a5, cog_flex_t a6, cog_flex_t a7) = (void*)sithCog_SendMessageFromSurfaceEx_ADDR;
//static cog_flex_t (*_sithCog_SendMessageFromThingEx)(sithThing *sender, sithThing *receiver, SITH_MESSAGE message, cog_flex_t param0, cog_flex_t param1, cog_flex_t param2, cog_flex_t param3) = (void*)sithCog_SendMessageFromThingEx_ADDR;
//static void (*sithCog_SendMessageFromSectorEx)(sithSector *a1, sithThing *sourceType, SITH_MESSAGE message, cog_flex_t param0, cog_flex_t param1, cog_flex_t param2, cog_flex_t param3) = (void*)sithCog_SendMessageFromSectorEx_ADDR;
//static void (*sithCog_SendMessageToAll)(int32_t cmdid, int32_t senderType, int32_t senderIdx, int32_t sourceType, int32_t sourceIdx, cog_flex_t arg0, cog_flex_t arg1, cog_flex_t arg2, cog_flex_t arg3) = (void*)sithCog_SendMessageToAll_ADDR;
//static void (*sithCog_Free)(sithWorld* world) = (void*)sithCog_Free_ADDR;
//static void (*sithCogScript_Tick)(sithCog* cog) = (void*)sithCogScript_Tick_ADDR;

int sithCogScript_Load(sithWorld *lvl, int a2);
sithCogScript* sithCogScript_LoadEntry(const char *pFpath, int32_t unk);
void sithCogScript_RegisterVerb(sithCogSymboltable *a1, cogSymbolFunc_t a2, const char *a3);
void sithCogScript_RegisterMessageSymbol(sithCogSymboltable *a1, int32_t a2, const char *a3);
void sithCogScript_RegisterGlobalMessage(sithCogSymboltable *a1, const char *a2, int32_t a3);
void sithCogScript_TickAll();
void sithCogScript_Tick(sithCog *cog);
int sithCogScript_TimerTick(int32_t deltaMs, sithEventInfo *info);
int sithCogScript_DevCmdCogStatus(stdDebugConsoleCmd *cmd, const char *extra);
sithCog* sithCog_GetByIdx(int32_t idx);




// General
extern void sithCogFunction_Pow(sithCog* ctx);
extern void sithCogFunction_Wakeup(sithCog* ctx);
extern void sithCogFunction_VectorEqual(sithCog* ctx);
extern void sithCogFunction_FireProjectileData(sithCog* ctx);
extern void sithCogFunction_FireProjectileLocal(sithCog* ctx);
extern void sithCogFunction_GetWeaponBin(sithCog* ctx);
extern void sithCogFunction_SendMessageExRadius(sithCog* ctx);
extern void sithCogFunction_WorldFlash(sithCog* ctx);
extern void sithCogFunction_SetCameraZoom(sithCog* ctx);
extern void sithCogFunction_GetActionCog(sithCog* ctx);
extern void sithCogFunction_SetActionCog(sithCog* ctx);
extern void sithCogFunction_Sin(sithCog* ctx);
extern void sithCogFunction_Cos(sithCog* ctx);
extern void sithCogFunction_Tan(sithCog* ctx);
extern void sithCogFunction_GetCogFlags(sithCog* ctx);
extern void sithCogFunction_SetCogFlags(sithCog* ctx);
extern void sithCogFunction_ClearCogFlags(sithCog* ctx);
extern void sithCogFunction_DebugBreak(sithCog* ctx);
extern void sithCogFunction_GetSysDate(sithCog* ctx);
extern void sithCogFunction_GetSysTime(sithCog* ctx);
extern void sithCogFunction_SetCameraFocii(sithCog* ctx);

// AI
extern void sithCogFunctionAI_FirstThingInCone(sithCog *ctx);
extern void sithCogFunctionAI_NextThingInCone(sithCog *ctx);

extern void sithCogFunctionAI_AIGetAlignment(sithCog *ctx);
extern void sithCogFunctionAI_AISetAlignment(sithCog *ctx);
extern void sithCogFunctionAI_AISetInterest(sithCog *ctx);
extern void sithCogFunctionAI_AIGetInterest(sithCog *ctx);
extern void sithCogFunctionAI_AISetDistractor(sithCog *ctx);
extern void sithCogFunctionAI_AIAddAlignmentPriority(sithCog *ctx);
extern void sithCogFunctionAI_AIRemoveAlignmentPriority(sithCog *ctx);

// Player
extern void sithCogFunctionPlayer_KillPlayerQuietly(sithCog* ctx);

// Sector
extern void sithCogFunctionSector_ChangeAllSectorsLight(sithCog* ctx);
extern void sithCogFunctionSector_FindSectorAtPos(sithCog* ctx);
extern void sithCogFunctionSector_IsSphereInSector(sithCog* ctx);
extern void sithCogFunctionSector_GetSectorAmbientLight(sithCog* ctx);
extern void sithCogFunctionSector_SetSectorAmbientLight(sithCog* ctx);

// Sound
extern void sithCogFunctionSound_PlaySoundThingLocal(sithCog* ctx);
extern void sithCogFunctionSound_PlaySoundPosLocal(sithCog* ctx);

extern void sithCogFunctionSound_PlaySoundThing(sithCog* ctx);
extern void sithCogFunctionSound_PlaySoundPos(sithCog* ctx);
extern void sithCogFunctionSound_PlaySoundLocal(sithCog* ctx);
extern void sithCogFunctionSound_PlaySoundGlobal(sithCog* ctx);

// Surface
extern void sithCogFunctionSurface_GetSurfaceVertexLight(sithCog* ctx);
extern void sithCogFunctionSurface_SetSurfaceVertexLight(sithCog* ctx);
extern void sithCogFunctionSurface_GetSurfaceVertexLightRGB(sithCog* ctx);
extern void sithCogFunctionSurface_SetSurfaceVertexLightRGB(sithCog* ctx);

// Thing
extern void sithCogFunctionThing_CreateThingLocal(sithCog* ctx);
extern void sithCogFunctionThing_CreateThingAtPosOwner(sithCog* ctx);
extern void sithCogFunctionThing_CreateThingAtPos(sithCog* ctx);
extern void sithCogFunctionThing_SetThingParent(sithCog* ctx);
extern void sithCogFunctionThing_SetThingPosEx(sithCog* ctx);
extern void sithCogFunctionThing_GetThingLvecPYR(sithCog* ctx);
extern void sithCogFunctionThing_GetCurInvWeapon(sithCog* ctx);
extern void sithCogFunctionThing_GetActorWeapon(sithCog* ctx);
extern void sithCogFunctionThing_SetThingLookPYR(sithCog* ctx);
extern void sithCogFunctionThing_GetThingGUID(sithCog* ctx);
extern void sithCogFunctionThing_GetGUIDThing(sithCog* ctx);
extern void sithCogFunctionThing_GetThingMaxVelocity(sithCog* ctx);
extern void sithCogFunctionThing_SetThingMaxVelocity(sithCog* ctx);
extern void sithCogFunctionThing_GetThingMaxAngularVelocity(sithCog* ctx);
extern void sithCogFunctionThing_SetThingMaxAngularVelocity(sithCog* ctx);
extern void sithCogFunctionThing_GetActorHeadPYR(sithCog* ctx);
extern void sithCogFunctionThing_SetActorHeadPYR(sithCog* ctx);
extern void sithCogFunctionThing_SetThingJointAngle(sithCog* ctx);
extern void sithCogFunctionThing_GetThingJointAngle(sithCog* ctx);
extern void sithCogFunctionThing_SetThingMaxHeadPitch(sithCog* ctx);
extern void sithCogFunctionThing_SetThingMinHeadPitch(sithCog* ctx);
extern void sithCogFunctionThing_InterpolatePYR(sithCog* ctx);
extern void sithCogFunctionThing_SetWeaponTarget(sithCog* ctx);
extern void sithCogFunctionThing_GetCurInvWeaponMots(sithCog* ctx);

// JK
extern void jkCog_PrintUniVoice(sithCog* ctx);
extern void jkCog_GetSaberSideMat(sithCog* ctx);
extern void jkCog_SyncForcePowers(sithCog* ctx);
extern void jkCog_BeginCutscene(sithCog* ctx);
extern void jkCog_EndCutscene(sithCog* ctx);
extern void jkCog_StartupCutscene(sithCog* ctx);
extern void jkCog_GetMultiParam(sithCog* ctx);
extern void jkCog_InsideLeia(sithCog* ctx);
extern void jkCog_CreateBubble(sithCog* ctx);
extern void jkCog_DestroyBubble(sithCog* ctx);
extern void jkCog_GetBubbleDistance(sithCog* ctx);
extern void jkCog_ThingInBubble(sithCog* ctx);
extern void jkCog_GetFirstBubble(sithCog* ctx);
extern void jkCog_GetNextBubble(sithCog* ctx);
extern void jkCog_GetBubbleType(sithCog* ctx);
extern void jkCog_GetBubbleRadius(sithCog* ctx);
extern void jkCog_SetBubbleType(sithCog* ctx);
extern void jkCog_SetBubbleRadius(sithCog* ctx);
extern void jkCog_Screenshot(sithCog* ctx);
extern void jkCog_GetOpenFrames(sithCog* ctx);
extern void jkCog_dwGetActivateBin(sithCog* ctx);
extern void jkCog_addBeam(sithCog* ctx);
extern void jkCog_addLaser(sithCog* ctx);
extern void jkCog_removeLaser(sithCog* ctx);
extern void jkCog_getLaserId(sithCog* ctx);
extern void jkCog_dwPlayCammySpeech(sithCog* ctx);
extern void jkCog_stub0Args(sithCog* ctx);
extern void jkCog_stub1Args(sithCog* ctx);
extern void jkCog_stub2Args(sithCog* ctx);

// JK13
extern void jkCogExt_GetThingAttachSurface(sithCog* ctx);
extern void jkCogExt_GetThingAttachThing(sithCog* ctx);
extern void jkCogExt_GetCameraFov(sithCog* ctx);
extern void jkCogExt_GetCameraOffset(sithCog* ctx);
extern void jkCogExt_SetCameraFov(sithCog* ctx);
extern void jkCogExt_SetCameraOffset(sithCog* ctx);
extern void jkCogExt_Absolute(sithCog* ctx);
extern void jkCogExt_Arccosine(sithCog* ctx);
extern void jkCogExt_Arcsine(sithCog* ctx);
extern void jkCogExt_Arctangent(sithCog* ctx);
extern void jkCogExt_Ceiling(sithCog* ctx);
extern void jkCogExt_Cosine(sithCog* ctx);
extern void jkCogExt_Floor(sithCog* ctx);
extern void jkCogExt_Power(sithCog* ctx);
extern void jkCogExt_Randomflex(sithCog* ctx);
extern void jkCogExt_Randomint(sithCog* ctx);
extern void jkCogExt_Sine(sithCog* ctx);
extern void jkCogExt_Squareroot(sithCog* ctx);
extern void jkCogExt_GetHotkeyCog(sithCog* ctx);
extern void jkCogExt_SetHotkeyCog(sithCog* ctx);
extern void jkCogExt_IsAdjoin(sithCog* ctx);
extern void jkCogExt_SetGameSpeed(sithCog* ctx);
extern void jkCogExt_GetThingHeadLvec(sithCog* ctx);
extern void jkCogExt_GetThingHeadPitch(sithCog* ctx);
extern void jkCogExt_GetThingHeadPYR(sithCog* ctx);
extern void jkCogExt_GetThingPYR(sithCog* ctx);
extern void jkCogExt_SetThingHeadPYR(sithCog* ctx);
extern void jkCogExt_SetThingPosEx(sithCog* ctx);
extern void jkCogExt_SetThingPYR(sithCog* ctx);
extern void jkCogExt_SetThingLRUVecs(sithCog* ctx);
extern void jkCogExt_SetThingSector(sithCog* ctx);
extern void jkCogExt_RestoreJoint(sithCog* ctx);
extern void jkCogExt_GetThingAirDrag(sithCog* ctx);
extern void jkCogExt_GetThingEyeOffset(sithCog* ctx);
extern void jkCogExt_GetThingHeadPitchMax(sithCog* ctx);
extern void jkCogExt_GetThingHeadPitchMin(sithCog* ctx);
extern void jkCogExt_GetThingJumpSpeed(sithCog* ctx);
extern void jkCogExt_SetThingAirDrag(sithCog* ctx);
extern void jkCogExt_SetThingEyeOffset(sithCog* ctx);
extern void jkCogExt_SetThingHeadPitchMinMax(sithCog* ctx);
extern void jkCogExt_SetThingJumpSpeed(sithCog* ctx);
extern void jkCogExt_SetThingMesh(sithCog* ctx);
extern void jkCogExt_SetThingParent(sithCog* ctx);
extern void jkCogExt_SetSaberFaceFlags(sithCog* ctx);

#endif // _SITHCOG_H
