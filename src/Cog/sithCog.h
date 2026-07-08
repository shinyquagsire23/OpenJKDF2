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
#define sithCog_FreeWorldCogs_ADDR (0x004DE820)
#define sithCog_FreeEntry_ADDR (0x004DE9B0)
#define sithCog_FreeScriptEntry_ADDR (0x004DEA20)
#define sithCog_UpdateThingTimer_ADDR (0x004DEA60)
#define sithCog_BroadcastMessage_ADDR (0x004DEAD0)
#define sithCog_BroadcastMessageEx_ADDR (0x004DEB00)
#define sithCog_SendMessage_ADDR (0x004DEBE0)
#define sithCog_SendMessageEx_ADDR (0x004DEDC0)
#define sithCog_AllocWorldCogScripts_ADDR (0x004DEFF0)
#define sithCog_AllocWorldCogs_ADDR (0x004DF080)
#define sithCog_ReadCogsListText_ADDR (0x004DF110)
#define sithCog_ParseSymbolRef_ADDR (0x004DF410)
#define sithCog_LinkCog_ADDR (0x004DF610)
#define sithCog_Load_ADDR (0x004DF7D0)
#define sithCog_GetCogByIndex_ADDR (0x004DF930)
#define sithCog_LinkCogToThing_ADDR (0x004DF980)
#define sithCog_LinkCogToSurface_ADDR (0x004DFA00)
#define sithCog_LinkCogToSector_ADDR (0x004DFA60)
#define sithCog_ThingSendMessage_ADDR (0x004DFAC0)
#define sithCog_ThingSendMessageEx_ADDR (0x004DFAF0)
#define sithCog_SectorSendMessage_ADDR (0x004DFD60)
#define sithCog_SectorSendMessageEx_ADDR (0x004DFD90)
#define sithCog_SurfaceSendMessage_ADDR (0x004DFED0)
#define sithCog_SurfaceSendMessageEx_ADDR (0x004DFF00)
#define sithCog_ReadCogScriptsListText_ADDR (0x004E0040)
#define sithCog_LoadScript_ADDR (0x004E0240)
#define sithCog_ProcessCog_ADDR (0x004E0300)
#define sithCog_ProcessCogs_ADDR (0x004E0400)
#define sithCog_CogStatus_ADDR (0x004E0480)
#define sithCog_AddIntSymbol_ADDR (0x004E0600)
#define sithCog_TimerEventTask_ADDR (0x004E0640)
#define sithCog_AddFloatSymbol_ADDR (0x004E06C0)
#define sithCog_RegisterFunction_ADDR (0x004E0700)

#define COG_SHOULD_SYNC(ctx) (sithMessage_g_outputstream && !(ctx->flags & SITH_COG_NO_SYNC) && ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN)


//static int32_t (*_sithCog_Load)(SithWorld *world, int32_t a2) = (void*)sithCog_ReadCogsListText_ADDR;
//static int32_t (*sithCog_ReadCogScriptsListText)(SithWorld *world, int32_t a2) = (void*)sithCog_ReadCogScriptsListText_ADDR;
//static void (*sithCog_RegisterFunction)(void* a, intptr_t func, char* cmd) = (void*)0x4E0700;
//static void (__cdecl *sithCog_SendMessage)(sithCog *a1, int32_t msgid, int32_t senderType, int32_t senderIndex, int32_t sourceType, int32_t sourceIndex, int32_t linkId) = (void*)0x4DEBE0;
//static flex_t (__cdecl *sithCog_SendMessageEx)(sithCog *a1, SITH_MESSAGE message, int32_t senderType, int32_t senderIndex, int32_t sourceType, int32_t sourceIndex, int32_t linkId, flex_t param0, flex_t param1, flex_t param2, flex_t param3) = (void*)0x4DEDC0;
//static void (*sithCog_UpdateThingTimer)(SithThing *a1) = (void*)sithCog_UpdateThingTimer_ADDR;
//static int32_t (*sithCog_LinkCog)(sithCog *a1, SithCogSymbolRef *a2, SithCogSymbol *a3) = (void*)sithCog_LinkCog_ADDR;
//static sithCog* (*_sithCog_LoadCogscript)(const char *fpath) = (void*)sithCog_Load_ADDR;

int32_t sithCog_Startup();
int32_t sithCog_StartupEnhanced(); // Added
void sithCog_Shutdown();
int32_t sithCog_Open();
void sithCog_Close();
int sithCog_ReadCogsListText(SithWorld *world, int a2);
sithCog* sithCog_Load(const char *fpath);
int32_t sithCog_ParseSymbolRef(SithCogSymbol *cogSymbol, SithCogSymbolRef *cogIdk, char *val);
int32_t sithCog_LinkCog(sithCog *cog, SithCogSymbolRef *idk, SithCogSymbol *symbol);
void sithCog_UpdateThingTimer(SithThing *thing);

void sithCogFunction_Startup(SithCogSymbolTable* a1);
void sithCogThing_Startup(SithCogSymbolTable* a1);
void sithCogFunctionSound_Startup(SithCogSymbolTable* a1);
void sithCogFunctionSector_Startup(SithCogSymbolTable* a1);
void sithCogSurface_Startup(SithCogSymbolTable* a1);

void sithCog_ThingSendMessage(SithThing *a1, SithThing *a2, int32_t msg);
cog_flex_t sithCog_ThingSendMessageEx(SithThing *sender, SithThing *receiver, SITH_MESSAGE message, cog_flex_t param0, cog_flex_t param1, cog_flex_t param2, cog_flex_t param3);
void sithCog_SurfaceSendMessage(SithSurface *surface, SithThing *thing, int32_t msg);
cog_flex_t sithCog_SurfaceSendMessageEx(SithSurface *sender, SithThing *thing, SITH_MESSAGE msg, cog_flex_t a4, cog_flex_t a5, cog_flex_t a6, cog_flex_t a7);
void sithCog_SectorSendMessage(SithSector *sector, SithThing *thing, int32_t message);
cog_flex_t sithCog_SectorSendMessageEx(SithSector *a1, SithThing *sourceType, SITH_MESSAGE message, cog_flex_t param0, cog_flex_t param1, cog_flex_t param2, cog_flex_t param3);
void sithCog_BroadcastMessage(int32_t a1, int32_t a2, int32_t a3, int32_t a4, int32_t a5);
void sithCog_BroadcastMessageEx(int32_t cmdid, int32_t senderType, int32_t senderIdx, int32_t sourceType, int32_t sourceIdx, cog_flex_t arg0, cog_flex_t arg1, cog_flex_t arg2, cog_flex_t arg3);
void sithCog_SendMessage(sithCog *cog, int32_t msgid, int32_t senderType, int32_t senderIndex, int32_t sourceType, int32_t sourceIndex, int32_t linkId);
cog_flex_t sithCog_SendMessageEx(sithCog *cog, int32_t message, int32_t senderType, int32_t senderIndex, int32_t sourceType, int32_t sourceIndex, int32_t linkId, cog_flex_t param0, cog_flex_t param1, cog_flex_t param2, cog_flex_t param3);
void sithCog_FreeWorldCogs(SithWorld *world);
void sithCog_FreeEntry(sithCog *cog);
void sithCog_FreeScriptEntry(SithCogScript *cogscript);
int sithCog_AllocWorldCogScripts(SithWorld *world, int num);
int sithCog_AllocWorldCogs(SithWorld *world, int num);
int sithCog_LinkCogToThing(sithCog *cog, SithThing *thing, int linkId, int mask);
int sithCog_LinkCogToSurface(sithCog *cog, SithSurface *surface, int linkId, int mask);
int sithCog_LinkCogToSector(sithCog *cog, SithSector *sector, int linkId, int mask);

//static int32_t (*_sithCog_Open)() = (void*)sithCog_Open_ADDR;
//static double (*sithCog_SurfaceSendMessageEx)(SithSurface *a1, SithThing *a2, int32_t a3, cog_flex_t a4, cog_flex_t a5, cog_flex_t a6, cog_flex_t a7) = (void*)sithCog_SurfaceSendMessageEx_ADDR;
//static cog_flex_t (*_sithCog_SendMessageFromThingEx)(SithThing *sender, SithThing *receiver, SITH_MESSAGE message, cog_flex_t param0, cog_flex_t param1, cog_flex_t param2, cog_flex_t param3) = (void*)sithCog_ThingSendMessageEx_ADDR;
//static void (*sithCog_SectorSendMessageEx)(SithSector *a1, SithThing *sourceType, SITH_MESSAGE message, cog_flex_t param0, cog_flex_t param1, cog_flex_t param2, cog_flex_t param3) = (void*)sithCog_SectorSendMessageEx_ADDR;
//static void (*sithCog_BroadcastMessageEx)(int32_t cmdid, int32_t senderType, int32_t senderIdx, int32_t sourceType, int32_t sourceIdx, cog_flex_t arg0, cog_flex_t arg1, cog_flex_t arg2, cog_flex_t arg3) = (void*)sithCog_BroadcastMessageEx_ADDR;
//static void (*sithCog_FreeWorldCogs)(SithWorld* world) = (void*)sithCog_FreeWorldCogs_ADDR;
//static void (*sithCog_ProcessCog)(sithCog* cog) = (void*)sithCog_ProcessCog_ADDR;

int sithCog_ReadCogScriptsListText(SithWorld *lvl, int a2);
SithCogScript* sithCog_LoadScript(const char *pFpath, int32_t unk);
void sithCog_RegisterFunction(SithCogSymbolTable *a1, cogSymbolFunc_t a2, const char *a3);
void sithCog_AddIntSymbol(SithCogSymbolTable *a1, int32_t a2, const char *a3);
void sithCog_AddFloatSymbol(SithCogSymbolTable *a1, const char *a2, int32_t a3);
void sithCog_ProcessCogs();
void sithCog_ProcessCog(sithCog *cog);
int sithCog_TimerEventTask(int32_t deltaMs, SithEventParams *info);
int sithCog_CogStatus(stdDebugConsoleCmd *cmd, const char *extra);
sithCog* sithCog_GetCogByIndex(int32_t idx);




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
extern void sithCogFunctionThing_GetThingLVecPYR(sithCog* ctx);
extern void sithCogFunctionThing_GetCurInvWeapon(sithCog* ctx);
extern void sithCogFunctionThing_GetActorWeapon(sithCog* ctx);
extern void sithCogFunctionThing_SetThingLookPYR(sithCog* ctx);
extern void sithCogFunctionThing_GetThingGuid(sithCog* ctx);
extern void sithCogFunctionThing_GetGuidThing(sithCog* ctx);
extern void sithCogFunctionThing_GetThingMaxVelocity(sithCog* ctx);
extern void sithCogFunctionThing_SetThingMaxVelocity(sithCog* ctx);
extern void sithCogFunctionThing_GetThingMaxAngularVelocity(sithCog* ctx);
extern void sithCogFunctionThing_SetThingMaxAngularVelocity(sithCog* ctx);
extern void sithCogFunctionThing_GetActorHeadPYR(sithCog* ctx);
extern void sithCogFunctionThing_SetHeadPYR(sithCog* ctx);
extern void sithCogFunctionThing_SetJointAngle(sithCog* ctx);
extern void sithCogFunctionThing_GetJointAngle(sithCog* ctx);
extern void sithCogFunctionThing_SetMaxHeadPitch(sithCog* ctx);
extern void sithCogFunctionThing_SetMinHeadPitch(sithCog* ctx);
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
