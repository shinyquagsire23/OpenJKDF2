#ifndef _SITHTHING_H
#define _SITHTHING_H

#include "types.h"
#include "globals.h"

#include "Engine/rdThing.h"
#include "World/sithPlayer.h"
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
#define sithThing_SyncThingPos_ADDR (0x004CF560)
#define sithThing_netidk_ADDR (0x004CF5D0)
#define sithThing_ShouldSync_ADDR (0x004CF660)
#define sithThing_netidk2_ADDR (0x004CF690)
#define sithThing_Release_ADDR (0x004E0740)
#define sithThing_Hit_ADDR (0x004ECC90)
#define sithThing_HurtSound_ADDR (0x004ECE90)
#define sithThing_SpawnDeadBodyMaybe_ADDR (0x004ECFE0)
#define sithThing_LoadActorPlayerParams_ADDR (0x004ED7E0)

enum MOVETYPE
{
  SITH_MT_NONE = 0x0,
  SITH_MT_PHYSICS = 0x1,
  SITH_MT_PATH = 0x2,
};

enum THING_PHYSFLAGS
{
  PHYSFLAGS_GRAVITY = 0x1,
  PHYSFLAGS_USESTHRUST = 0x2,
  PHYSFLAGS_4 = 0x4,
  PHYSFLAGS_8 = 0x8,
  PHYSFLAGS_SURFACEALIGN = 0x10,
  PHYSFLAGS_SURFACEBOUNCE = 0x20,
  PHYSFLAGS_FLOORSTICK = 0x40,
  PHYSFLAGS_WALLSTICK = 0x80,
  PHYSFLAGS_100 = 0x100,
  PHYSFLAGS_ROTVEL = 0x200,
  PHYSFLAGS_BANKEDTURNS = 0x400,
  PHYSFLAGS_800 = 0x800,
  PHYSFLAGS_ANGTHRUST = 0x1000,
  PHYSFLAGS_FLYING = 0x2000,
  PHYSFLAGS_FEELBLASTFORCE = 0x4000,
  PHYSFLAGS_8000 = 0x8000,
  PHYSFLAGS_CROUCHING = 0x10000,
  PHYSFLAGS_20000 = 0x20000,
  PHYSFLAGS_PARTIALGRAVITY = 0x40000,
  PHYSFLAGS_80000 = 0x80000,
  PHYSFLAGS_MIDAIR = 0x100000,
  PHYSFLAGS_200000 = 0x200000,
  PHYSFLAGS_NOTHRUST = 0x400000,
  PHYSFLAGS_800000 = 0x800000,
  PHYSFLAGS_1000000 = 0x1000000,
  PHYSFLAGS_2000000 = 0x2000000,
  PHYSFLAGS_4000000 = 0x4000000,
  PHYSFLAGS_8000000 = 0x8000000,
};

enum THINGPARAM
{
    THINGPARAM_0     = 0,
    THINGPARAM_TYPE  = 1,
    THINGPARAM_COLLIDE  = 2,
    THINGPARAM_MOVE  = 3,
    THINGPARAM_SIZE  = 4,
    THINGPARAM_THINGFLAGS  = 5,
    THINGPARAM_TIMER  = 6,
    THINGPARAM_LIGHT  = 7,
    THINGPARAM_ATTACH  = 8,
    THINGPARAM_SOUNDCLASS  = 9,
    THINGPARAM_MODEL3D  = 0x0A,
    THINGPARAM_SPRITE  = 0x0B,
    THINGPARAM_SURFDRAG  = 0x0C,
    THINGPARAM_AIRDRAG  = 0x0D,
    THINGPARAM_STATICDRAG  = 0x0E,
    THINGPARAM_MASS  = 0x0F,
    THINGPARAM_HEIGHT  = 0x10,
    THINGPARAM_PHYSFLAGS  = 0x11,
    THINGPARAM_MAXROTVEL  = 0x12,
    THINGPARAM_MAXVEL  = 0x13,
    THINGPARAM_VEL   = 0x14,
    THINGPARAM_ANGVEL  = 0x15,
    THINGPARAM_TYPEFLAGS  = 0x16,
    THINGPARAM_HEALTH  = 0x17,
    THINGPARAM_MAXTHRUST  = 0x18,
    THINGPARAM_MAXROTTHRUST  = 0x19,
    THINGPARAM_JUMPSPEED  = 0x1A,
    THINGPARAM_WEAPON  = 0x1B,
    THINGPARAM_WEAPON2  = 0x1C,
    THINGPARAM_DAMAGE  = 0x1D,
    THINGPARAM_MINDDAMAGE  = 0x1E,
    THINGPARAM_DAMAGECLASS  = 0x1F,
    THINGPARAM_EXPLODE  = 0x20,
    THINGPARAM_FRAME  = 0x21,
    THINGPARAM_NUMFRAMES  = 0x22,
    THINGPARAM_PUPPET  = 0x23,
    THINGPARAM_BLASTTIME  = 0x24,
    THINGPARAM_FORCE  = 0x25,
    THINGPARAM_MAXLIGHT  = 0x26,
    THINGPARAM_RANGE  = 0x27,
    THINGPARAM_FLASHRGB  = 0x28,
    THINGPARAM_AICLASS  = 0x29,
    THINGPARAM_COG   = 0x2A,
    THINGPARAM_RESPAWN  = 0x2B,
    THINGPARAM_MATERIAL  = 0x2C,
    THINGPARAM_RATE  = 0x2D,
    THINGPARAM_COUNT  = 0x2E,
    THINGPARAM_ELEMENTSIZE  = 0x2F,
    THINGPARAM_PARTICLE  = 0x30,
    THINGPARAM_MAXHEALTH  = 0x31,
    THINGPARAM_MOVESIZE  = 0x32,
    THINGPARAM_ORIENTSPEED  = 0x33,
    THINGPARAM_BUOYANCY  = 0x34,
    THINGPARAM_EYEOFFSET  = 0x35,
    THINGPARAM_MINHEADPITCH  = 0x36,
    THINGPARAM_MAXHEADPITCH  = 0x37,
    THINGPARAM_FIREOFFSET  = 0x38,
    THINGPARAM_LIGHTOFFSET  = 0x39,
    THINGPARAM_LIGHTINTENSITY  = 0x3A,
    THINGPARAM_POINTS  = 0x3B,
    THINGPARAM_DEBRIS  = 0x3C,
    THINGPARAM_CREATETHING  = 0x3D,
    THINGPARAM_TRAILTHING  = 0x3E,
    THINGPARAM_TRAILCYLRADIUS  = 0x3F,
    THINGPARAM_TRAINRANDANGLE  = 0x40,
    THINGPARAM_MINSIZE  = 0x41,
    THINGPARAM_PITCHRANGE  = 0x42,
    THINGPARAM_YAWRANGE  = 0x43,
    THINGPARAM_ERROR  = 0x44,
    THINGPARAM_FOV   = 0x45,
    THINGPARAM_CHANCE  = 0x46,
    THINGPARAM_ORIENT  = 0x47,
    THINGPARAM_FLESHHIT  = 0x48
};

enum THINGTYPE
{
    THINGTYPE_FREE   = 0,
    THINGTYPE_CAMERA  = 1,
    THINGTYPE_ACTOR  = 2,
    THINGTYPE_WEAPON  = 3,
    THINGTYPE_DEBRIS  = 4,
    THINGTYPE_ITEM   = 5,
    THINGTYPE_EXPLOSION  = 6,
    THINGTYPE_COG    = 7,
    THINGTYPE_GHOST  = 8,
    THINGTYPE_CORPSE  = 9,
    THINGTYPE_PLAYER  = 10,
    THINGTYPE_PARTICLE  = 11,
    THINGTYPE_INVALID  = 12
};

enum SITH_DT
{
    SITH_DT_IMPACT   = 0x01,
    SITH_DT_ENERGY   = 0x02,
    SITH_DT_FIRE     = 0x04,
    SITH_DT_FORCE    = 0x08,
    SITH_DT_SABER    = 0x10
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
    SITH_TF_4000000  = 0x4000000,
    SITH_TF_DROWNS   = 0x8000000,
    SITH_TF_WATERCREATURE  = 0x10000000,
    SITH_TF_SPLASHES  = 0x20000000
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
int sithThing_LoadActorPlayerParams(stdConffileArg *arg, sithThing *thing, unsigned int param);
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
float sithThing_Hit(sithThing *sender, sithThing *receiver, float amount, int flags);
void sithThing_HurtSound(sithThing *thing, float amount, int hurtType);
void sithThing_SpawnDeadBodyMaybe(sithThing *thing, sithThing *a3, int a4);
void sithThing_detachallchildren(sithThing *thing);
void sithThing_AttachThing(sithThing *parent, sithThing *child);
void sithThing_SyncThingPos(sithThing *thing, int a2);
int sithThing_ShouldSync(sithThing *thing);
sithThing* sithThing_GetById(int thing_id);
int sithThing_HasAttachment(sithThing *thing);

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
static int (*sithThing_Release)(sithThing *a1) = (void*)sithThing_Release_ADDR;
//static sithThing* (*sithThing_GetParent)(sithThing *a1) = (void*)sithThing_GetParent_ADDR;
//static void (*sithThing_SyncThingPos)(sithThing *a1, int a2) = (void*)sithThing_SyncThingPos_ADDR;
//static void (*sithThing_AttachToSurface)(sithThing *a1, sithSurface *a2, int a3) = (void*)sithThing_AttachToSurface_ADDR;
//static void (*sithThing_AttachThing)(sithThing *parent, sithThing *child) = (void*)sithThing_AttachThing_ADDR;
//static int (*sithThing_SetNewModel)(sithThing *a1, rdModel3 *a2) = (void*)sithThing_SetNewModel_ADDR;

#endif // _SITHTHING_H
