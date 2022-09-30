#ifndef _SITHTHING_H
#define _SITHTHING_H

#include "types.h"
#include "globals.h"

#include "Engine/rdThing.h"
#include "Gameplay/sithPlayer.h"
#include "General/stdConffile.h"

#define sithThing_Startup_ADDR (0x004CC130)
#define sithThing_Shutdown_ADDR (0x004CC1A0)
#define sithThing_SetHandler_ADDR (0x004CC1D0)
#define sithThing_TickAll_ADDR (0x004CC1E0)
#define sithThing_TickPhysics_ADDR (0x004CC4C0)
#define sithThing_Remove_ADDR (0x004CC610)
#define sithThing_GetParent_ADDR (0x004CC6A0)
#define sithThing_GetThingByIdx_ADDR (0x004CC6D0)
#define sithThing_GetById_ADDR (0x004CC710)
#define sithThing_Destroy_ADDR (0x004CC7A0)
#define sithThing_Damage_ADDR (0x004CC7D0)
#define sithThing_Create_idk_ADDR (0x004CC8C0)
#define sithThing_Free_ADDR (0x004CCA10)
#define sithThing_freestuff_ADDR (0x004CCBC0)
#define sithThing_idkjkl_ADDR (0x004CCD40)
#define sithThing_sub_4CCE60_ADDR (0x004CCE60)
#define sithThing_FreeEverythingNet_ADDR (0x004CCF20)
#define sithThing_FreeEverything_ADDR (0x004CD050)
#define sithThing_sub_4CD100_ADDR (0x004CD100)
#define sithThing_DoesRdThingInit_ADDR (0x004CD190)
#define sithThing_MoveToSector_ADDR (0x004CD1E0)
#define sithThing_LeaveSector_ADDR (0x004CD220)
#define sithThing_EnterSector_ADDR (0x004CD2C0)
#define sithThing_EnterWater_ADDR (0x004CD370)
#define sithThing_ExitWater_ADDR (0x004CD480)
#define sithThing_doesinitidk_ADDR (0x004CD570)
#define sithThing_SetPosAndRot_ADDR (0x004CD7E0)
#define sithThing_SetNewModel_ADDR (0x004CD830)
#define sithThing_sub_4CD8A0_ADDR (0x004CD8A0)
#define sithThing_Create_ADDR (0x004CD9E0)
#define sithThing_SpawnTemplate_ADDR (0x004CDCD0)
#define sithThing_AttachToSurface_ADDR (0x004CDE80)
#define sithThing_LandThing_ADDR (0x004CE050)
#define sithThing_AttachThing_ADDR (0x004CE2C0)
#define sithThing_DetachThing_ADDR (0x004CE380)
#define sithThing_detachallchildren_ADDR (0x004CE540)
#define sithThing_IsAttachFlagsAnd6_ADDR (0x004CE560)
#define sithThing_LotsOfFreeing_ADDR (0x004CE580)
#define sithThing_Load_ADDR (0x004CE710)
#define sithThing_ParseArgs_ADDR (0x004CEB90)
#define sithThing_LoadThingParam_ADDR (0x004CECB0)
#define sithThing_TypeIdxFromStr_ADDR (0x004CF320)
#define sithThing_GetIdxFromThing_ADDR (0x004CF380)
#define sithThing_Checksum_ADDR (0x004CF3C0)
#define sithThing_SetSyncFlags_ADDR (0x004CF560)
#define sithThing_Sync_ADDR (0x004CF5D0)
#define sithThing_ShouldSync_ADDR (0x004CF660)
#define sithThing_netidk2_ADDR (0x004CF690)
#define sithThing_Release_ADDR (0x004E0740)

enum MOVETYPE
{
    SITH_MT_NONE = 0x0,
    SITH_MT_PHYSICS = 0x1,
    SITH_MT_PATH = 0x2,
};

enum THING_PHYSFLAGS
{
    SITH_PF_USEGRAVITY = 0x1,
    SITH_PF_USESTHRUST = 0x2,
    SITH_PF_4 = 0x4,
    SITH_PF_8 = 0x8,
    SITH_PF_SURFACEALIGN = 0x10,
    SITH_PF_SURFACEBOUNCE = 0x20,
    SITH_PF_FLOORSTICK = 0x40,
    SITH_PF_WALLSTICK = 0x80,
    SITH_PF_100 = 0x100,
    SITH_PF_ROTVEL = 0x200,
    SITH_PF_BANKEDTURNS = 0x400,
    SITH_PF_800 = 0x800,
    SITH_PF_ANGTHRUST = 0x1000,
    SITH_PF_FLY = 0x2000,
    SITH_PF_FEELBLASTFORCE = 0x4000,
    SITH_PF_8000 = 0x8000,
    SITH_PF_CROUCHING = 0x10000,
    SITH_PF_20000 = 0x20000,
    SITH_PF_PARTIALGRAVITY = 0x40000,
    SITH_PF_80000 = 0x80000,
    SITH_PF_MIDAIR = 0x100000,
    SITH_PF_200000 = 0x200000,
    SITH_PF_NOTHRUST = 0x400000,
    SITH_PF_800000 = 0x800000,
    SITH_PF_1000000 = 0x1000000,
    SITH_PF_2000000 = 0x2000000,
    SITH_PF_4000000 = 0x4000000,
    SITH_PF_8000000 = 0x8000000,
};

enum THINGPARAM
{
    THINGPARAM_0     = 0,
    THINGPARAM_TYPE,
    THINGPARAM_COLLIDE,
#ifdef JKM_PARAMS
    THINGPARAM_TREESIZE,
#endif
    THINGPARAM_MOVE,
    THINGPARAM_SIZE,
    THINGPARAM_THINGFLAGS,
    THINGPARAM_TIMER,
    THINGPARAM_LIGHT,
    THINGPARAM_ATTACH,
    THINGPARAM_SOUNDCLASS,
    THINGPARAM_MODEL3D,
    THINGPARAM_SPRITE,
    THINGPARAM_SURFDRAG,
    THINGPARAM_AIRDRAG,
    THINGPARAM_STATICDRAG,
    THINGPARAM_MASS,
    THINGPARAM_HEIGHT,
    THINGPARAM_PHYSFLAGS,
    THINGPARAM_MAXROTVEL,
    THINGPARAM_MAXVEL,
    THINGPARAM_VEL,
    THINGPARAM_ANGVEL,
    THINGPARAM_TYPEFLAGS,
    THINGPARAM_HEALTH,
    THINGPARAM_MAXTHRUST,
    THINGPARAM_MAXROTTHRUST,
    THINGPARAM_JUMPSPEED,
    THINGPARAM_WEAPON,
    THINGPARAM_WEAPON2,
    THINGPARAM_DAMAGE,
    THINGPARAM_MINDDAMAGE,
    THINGPARAM_DAMAGECLASS,
    THINGPARAM_EXPLODE,
    THINGPARAM_FRAME,
    THINGPARAM_NUMFRAMES,
    THINGPARAM_PUPPET,
    THINGPARAM_BLASTTIME,
    THINGPARAM_FORCE,
    THINGPARAM_MAXLIGHT,
    THINGPARAM_RANGE,
    THINGPARAM_FLASHRGB,
    THINGPARAM_AICLASS,
    THINGPARAM_COG,
    THINGPARAM_RESPAWN,
#ifdef JKM_PARAMS
    THINGPARAM_RESPAWNFACTOR,
#endif
    THINGPARAM_MATERIAL,
    THINGPARAM_RATE,
    THINGPARAM_COUNT,
    THINGPARAM_ELEMENTSIZE,
    THINGPARAM_PARTICLE,
    THINGPARAM_MAXHEALTH,
    THINGPARAM_MOVESIZE,
    THINGPARAM_ORIENTSPEED,
    THINGPARAM_BUOYANCY,
    THINGPARAM_EYEOFFSET,
    THINGPARAM_MINHEADPITCH,
    THINGPARAM_MAXHEADPITCH,
    THINGPARAM_FIREOFFSET,
    THINGPARAM_LIGHTOFFSET,
    THINGPARAM_LIGHTINTENSITY,
    THINGPARAM_POINTS,
    THINGPARAM_DEBRIS,
    THINGPARAM_CREATETHING,
    THINGPARAM_TRAILTHING,
    THINGPARAM_TRAILCYLRADIUS,
    THINGPARAM_TRAINRANDANGLE,
    THINGPARAM_MINSIZE,
    THINGPARAM_PITCHRANGE,
    THINGPARAM_YAWRANGE,
    THINGPARAM_ERROR,
    THINGPARAM_FOV,
    THINGPARAM_CHANCE,
    THINGPARAM_ORIENT,
    THINGPARAM_FLESHHIT
};

enum THINGTYPE
{
    SITH_THING_FREE   = 0,
    SITH_THING_CAMERA  = 1,
    SITH_THING_ACTOR  = 2,
    SITH_THING_WEAPON  = 3,
    SITH_THING_DEBRIS  = 4,
    SITH_THING_ITEM   = 5,
    SITH_THING_EXPLOSION  = 6,
    SITH_THING_COG    = 7,
    SITH_THING_GHOST  = 8,
    SITH_THING_CORPSE  = 9,
    SITH_THING_PLAYER  = 10,
    SITH_THING_PARTICLE  = 11,
    SITH_THING_INVALID  = 12

    // Jones
    /*
    SITH_THING_HINT = 12,
    SITH_THING_SPRITE = 13,
    SITH_THING_POLYLINE = 14,
    SITH_THING_NUMTYPES = 15,
    */
};

enum SITH_DAMAGE
{
    SITH_DAMAGE_IMPACT   = 0x01,
    SITH_DAMAGE_ENERGY   = 0x02,
    SITH_DAMAGE_FIRE     = 0x04,
    SITH_DAMAGE_FORCE    = 0x08,
    SITH_DAMAGE_SABER    = 0x10,
    SITH_DAMAGE_DROWN    = 0x20,
    SITH_DAMAGE_FALL    = 0x40,
};

enum SITH_TF
{
    SITH_TF_LIGHT    = 1,
    SITH_TF_WILLBEREMOVED  = 2,
    SITH_TF_4  = 4,
    SITH_TF_LEVELGEO  = 8,
    SITH_TF_10       = 0x10,
    SITH_TF_20       = 0x20,
    SITH_TF_STANDABLE  = 0x40,
    SITH_TF_80       = 0x80,
    SITH_TF_INVULN   = 0x100,
    SITH_TF_DEAD     = 0x200,
    SITH_TF_CAPTURED = 0x400,
    SITH_TF_NOIMPACTDAMAGE  = 0x800,
    SITH_TF_NOEASY   = 0x1000,
    SITH_TF_NOMEDIUM  = 0x2000,
    SITH_TF_NOHARD   = 0x4000,
    SITH_TF_8000     = 0x8000,
    SITH_TF_10000    = 0x10000,
    SITH_TF_PULSE    = 0x20000,
    SITH_TF_TIMER    = 0x40000,
    SITH_TF_DISABLED  = 0x80000,
    SITH_TF_INCAMFOV  = 0x100000,
    SITH_TF_RENDERWEAPON  = 0x200000,
    SITH_TF_METAL    = 0x400000,
    SITH_TF_EARTH    = 0x800000,
    SITH_TF_1000000  = 0x1000000,
    SITH_TF_WATER    = 0x2000000,
    SITH_TF_IGNOREGOURAUDDISTANCE  = 0x4000000,
    SITH_TF_DROWNS   = 0x8000000,
    SITH_TF_WATERCREATURE  = 0x10000000,
    SITH_TF_SPLASHES  = 0x20000000,
    SITH_TF_40000000 = 0x40000000,
    SITH_TF_80000000 = 0x80000000,
};

enum THING_TYPEFLAGS
{
    THING_TYPEFLAGS_1  = 0x1,
    THING_TYPEFLAGS_FORCE  = 0x2,
    THING_TYPEFLAGS_DAMAGE  = 0x4,
    THING_TYPEFLAGS_8  = 0x8,
    THING_TYPEFLAGS_LIGHT  = 0x10,
    THING_TYPEFLAGS_20  = 0x20,
    THING_TYPEFLAGS_40  = 0x40,
    THING_TYPEFLAGS_80  = 0x80,
    THING_TYPEFLAGS_DROID  = 0x100,
    THING_TYPEFLAGS_BOSS  = 0x200,
    THING_TYPEFLAGS_DEAF  = 0x400,
    THING_TYPEFLAGS_BLIND  = 0x800,
    THING_TYPEFLAGS_1000  = 0x1000,
    THING_TYPEFLAGS_ISBLOCKING  = 0x2000,
    THING_TYPEFLAGS_4000  = 0x4000,
    THING_TYPEFLAGS_8000  = 0x8000,
    THING_TYPEFLAGS_SCREAMING  = 0x10000,
    THING_TYPEFLAGS_20000  = 0x20000,
    THING_TYPEFLAGS_40000  = 0x40000,
    THING_TYPEFLAGS_CANTSHOOTUNDERWATER  = 0x80000,
    THING_TYPEFLAGS_100000  = 0x100000,
    THING_TYPEFLAGS_IMMOBILE  = 0x200000,
    THING_TYPEFLAGS_400000  = 0x400000,
    THING_TYPEFLAGS_800000  = 0x800000,
    THING_TYPEFLAGS_1000000  = 0x1000000,
    THING_TYPEFLAGS_2000000  = 0x2000000,
    THING_TYPEFLAGS_4000000  = 0x4000000,
    THING_TYPEFLAGS_8000000  = 0x8000000,
    THING_TYPEFLAGS_10000000  = 0x10000000,
    THING_TYPEFLAGS_20000000  = 0x20000000,
    THING_TYPEFLAGS_40000000  = 0x40000000,
    THING_TYPEFLAGS_80000000  = 0x80000000
};

enum SITH_AF
{
    SITH_AF_CAN_ROTATE_HEAD = 0x1,
    SITH_AF_CENTER_VIEW = 0x2,
    SITH_AF_FIELDLIGHT = 0x4,
    SITH_AF_INVULNERABLE = 0x8,
    SITH_AF_HEAD_IS_CENTERED = 0x10,
    SITH_AF_EXPLODE_WHEN_KILLED = 0x20,
    SITH_AF_BREATH_UNDER_WATER = 0x40,
    SITH_AF_INVISIBLE = 0x80,
    SITH_AF_DROID  = 0x100,
    SITH_AF_BOSS = 0x200,
    SITH_AF_DEAF = 0x400,
    SITH_AF_BLIND = 0x800,
    SITH_AF_1000 = 0x1000,
    SITH_AF_BLEEDS = 0x2000,
    SITH_AF_4000 = 0x4000,
    SITH_AF_CAN_SEE_INVISIBLE = 0x8000,
    SITH_AF_SCREAMING = 0x10000, // Jones: SLIP_SLOPE
    SITH_AF_DELAYFIRE = 0x20000,
    SITH_AF_IMMOBILE = 0x40000,
    SITH_AF_CANTSHOOTUNDERWATER = 0x80000,
    SITH_AF_NOTARGET = 0x100000,
    SITH_AF_DISABLED = 0x200000,
    SITH_AF_FALLING_TO_DEATH = 0x400000,
    SITH_AF_NOHUD = 0x800000,
    SITH_AF_FULL_ACTOR_DAMAGE = 0x1000000,
    SITH_AF_CAN_SEE_IN_DARK = 0x2000000,
    SITH_AF_4000000 = 0x4000000,
    SITH_AF_8000000 = 0x8000000,
    SITH_AF_FLYERMOVE = 0x10000000,
    SITH_AF_20000000 = 0x20000000,
    SITH_AF_40000000 = 0x40000000, // Jones: ELECTRICT_WHIP
    SITH_AF_80000000 = 0x80000000, // Jones: ARACHNID
};

enum THING_SYNC_FLAGS
{
    THING_SYNC_POS = 1,
    THING_SYNC_STATE = 2,
    THING_SYNC_FULL = 4,

    // Added
    THING_SYNC_AI = 8,
    THING_SYNC_PUPPET = 0x10,

    // Helper
    THING_SYNC_ALL = 0xFF,
};

int sithThing_Startup();
int sithThing_Shutdown();
void sithThing_SetHandler(sithThing_handler_t handler);
void sithThing_TickAll(float deltaSeconds, int deltaMs);
void sithThing_Remove(sithThing *thing);
sithThing* sithThing_GetParent(sithThing *thing);
sithThing* sithThing_GetThingByIdx(int idx);
void sithThing_sub_4CCE60();
void sithThing_FreeEverything(sithThing *thing);
void sithThing_sub_4CD100(sithThing *thing);
int sithThing_DoesRdThingInit(sithThing *thing);
sithThing* sithThing_sub_4CD8A0(sithThing *thing, sithThing *a2);
int sithThing_ParseArgs(stdConffileArg *arg, sithThing *thing);
int sithThing_Load(sithWorld *world, int a2);
int sithThing_LoadThingParam(stdConffileArg *arg, sithThing *thing, int param);
void sithThing_SetPosAndRot(sithThing *this, rdVector3 *pos, rdMatrix34 *rot);
int sithThing_SetNewModel(sithThing *thing, rdModel3 *model);
void sithThing_LeaveSector(sithThing *thing);
void sithThing_EnterSector(sithThing *thing, sithSector *sector, int a3, int a4);
void sithThing_EnterWater(sithThing *thing, int a2);
void sithThing_ExitWater(sithThing *thing, int a2);
uint32_t sithThing_Checksum(sithThing *thing, unsigned int last_hash);
int sithThing_netidk2(int a1);
int sithThing_GetIdxFromThing(sithThing *thing);
void sithThing_TickPhysics(sithThing *thing, float deltaSecs);
void sithThing_freestuff(sithWorld *world);
void sithThing_Free(sithWorld *world);
sithThing* sithThing_SpawnTemplate(sithThing *templateThing, sithThing *spawnThing);
sithThing* sithThing_Create(sithThing *templateThing, const rdVector3 *position, const rdMatrix34 *lookOrientation, sithSector *sector, sithThing *prevThing);
void sithThing_FreeEverythingNet(sithThing *thing);
void sithThing_AttachToSurface(sithThing *thing, sithSurface *surface, int a3);
void sithThing_LandThing(sithThing *a1, sithThing *a2, rdFace *a3, rdVector3 *a4, int a5);
void sithThing_MoveToSector(sithThing *thing, sithSector *sector, int a4);
int sithThing_DetachThing(sithThing *thing);
void sithThing_Destroy(sithThing *thing);
float sithThing_Damage(sithThing *sender, sithThing *reciever, float amount, int damageClass);
void sithThing_detachallchildren(sithThing *thing);
void sithThing_AttachThing(sithThing *parent, sithThing *child);
void sithThing_SetSyncFlags(sithThing *pThing, int flags);
int sithThing_ShouldSync(sithThing *thing);
sithThing* sithThing_GetById(int thing_id);
int sithThing_HasAttachment(sithThing *thing);
void sithThing_Sync();
int sithThing_Release(sithThing *pThing);

int sithThing_MotsTick(int param_1,int param_2,float param_3); // MOTS added

//static float (*sithThing_Hit)(sithThing *sender, sithThing *receiver, float amount, int a4) = (void*)sithThing_Hit_ADDR;
//static void (*sithThing_LandThing)(sithThing *a1, sithThing *a2, rdFace *a3, rdVector3* a4, int a5) = (void*)sithThing_LandThing_ADDR;
static int (*_sithThing_Load)(sithWorld *world, int a2) = (void*)sithThing_Load_ADDR;
//static int (*sithThing_LoadThingParam)(stdConffileArg *arg, sithThing *thing, int param) = (void*)sithThing_LoadThingParam_ADDR;
//static int (*sithThing_LoadActorPlayerParams)(stdConffileArg *arg, sithThing *thing, unsigned int param) = (void*)sithThing_LoadActorPlayerParams_ADDR;
//static void (*sithThing_TickPhysics)(sithThing *thing, float arg4) = (void*)sithThing_TickPhysics_ADDR;
//static int (__cdecl *sithThing_DoesRdThingInit)(sithThing *thing) = (void*)0x4CD190;
//static int (__cdecl *sithThing_sub_4CD8A0)(sithThing *thing, sithThing *a2) = (void*)0x4CD8A0;
//static signed int (*sithThing_ParseArgs)(stdConffileArg *a1, sithThing *thing) = (void*)0x004CEB90;
//static void (*sithThing_Free)(sithWorld* world) = (void*)sithThing_Free_ADDR;

//static sithThing* (*sithThing_Create)(sithThing *a1, rdVector3 *a2, const rdMatrix34 *a3, sithSector *sector, sithThing *a5) = (void*)sithThing_Create_ADDR;
//static sithThing* (*sithThing_SpawnTemplate)(sithThing *a1, sithThing *a2) = (void*)sithThing_SpawnTemplate_ADDR;
//static float (*sithThing_Damage)(sithThing *sender, sithThing *reciever, float amount, int damageClass) = (void*)sithThing_Damage_ADDR;
//static void (*sithThing_Destroy)(sithThing *a1) = (void*)sithThing_Destroy_ADDR;
//static void (*sithThing_LeaveSector)(sithThing *a1) = (void*)sithThing_LeaveSector_ADDR;
//static void (*sithThing_SetPosAndRot)(sithThing *thing, rdVector3 *pos, rdMatrix34 *rot) = (void*)sithThing_SetPosAndRot_ADDR;
//static void (*sithThing_MoveToSector)(sithThing *a1, sithSector *a2, int a4) = (void*)sithThing_MoveToSector_ADDR;
//static void (*sithThing_EnterSector)(sithThing *a1, sithSector *a2, int a3, int a4) = (void*)sithThing_EnterSector_ADDR;
//static int (*sithThing_DetachThing)(sithThing *a1) = (void*)sithThing_DetachThing_ADDR;
//static int (*sithThing_Release)(sithThing *a1) = (void*)sithThing_Release_ADDR;
//static sithThing* (*sithThing_GetParent)(sithThing *a1) = (void*)sithThing_GetParent_ADDR;
//static void (*sithThing_SetSyncFlags)(sithThing *a1, int a2) = (void*)sithThing_SetSyncFlags_ADDR;
//static void (*sithThing_AttachToSurface)(sithThing *a1, sithSurface *a2, int a3) = (void*)sithThing_AttachToSurface_ADDR;
//static void (*sithThing_AttachThing)(sithThing *parent, sithThing *child) = (void*)sithThing_AttachThing_ADDR;
//static int (*sithThing_SetNewModel)(sithThing *a1, rdModel3 *a2) = (void*)sithThing_SetNewModel_ADDR;

#endif // _SITHTHING_H
