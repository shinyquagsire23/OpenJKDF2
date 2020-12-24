#ifndef _SITHTHING_H
#define _SITHTHING_H

#include "Primitives/rdVector.h"
#include "Primitives/rdMatrix.h"
#include "Engine/rdThing.h"
#include "World/sithPlayer.h"
#include "General/stdConffile.h"

#define sithThing_Startup_ADDR (0x004CC130)
#define sithThing_Shutdown_ADDR (0x004CC1A0)
#define sithThing_SetHandler_ADDR (0x004CC1D0)
#define sithThing_TickMaybe_ADDR (0x004CC1E0)
#define sithThing_DetachThing_ADDR (0x004CC4C0)
#define sithThing_Remove_ADDR (0x004CC610)
#define sithThing_GetParent_ADDR (0x004CC6A0)
#define sithThing_GetThingByIdx_ADDR (0x004CC6D0)
#define sithThing_GetById_ADDR (0x004CC710)
#define sithThing_Destroy_ADDR (0x004CC7A0)
#define sithThing_Damage_ADDR (0x004CC7D0)
#define sithThing_Create_ADDR (0x004CC8C0)
#define sithThing_Free_ADDR (0x004CCA10)
#define sithThing_SpawnThingInSector_ADDR (0x4CD9E0)
#define sithThing_SpawnTemplate_ADDR (0x4CDCD0)
#define sithThing_LeaveSector_ADDR (0x004CD220)
#define sithThing_SetPosAndRot_ADDR (0x004CD7E0)
#define sithThing_MoveToSector_ADDR (0x004CD1E0)
#define sithThing_EnterSector_ADDR (0x4CD2C0)
#define sithThing_DetachThing__ADDR (0x4CE380)
#define sithThing_Release_ADDR (0x4E0740)
#define sithThing_SyncThingPos_ADDR (0x4CF560)
#define sithThing_AttachToSurface_ADDR (0x4CDE80)
#define sithThing_AttachThing_ADDR (0x4CE2C0)
#define sithThing_SetNewModel_ADDR (0x4CD830)

typedef struct sithAnimclass sithAnimclass;
typedef struct sithSector sithSector;
typedef struct sithSurface sithSurface;

enum MOVETYPE
{
  MOVETYPE_NONE = 0x0,
  MOVETYPE_PHYSICS = 0x1,
  MOVETYPE_PATH = 0x2,
};

enum THING_PHYSFLAGS
{
  PHYSFLAGS_GRAVITY = 0x1,
  PHYSFLAGS_USESTHRUST = 0x2,
  THINGSTATE_4 = 0x4,
  THINGSTATE_8 = 0x8,
  PHYSFLAGS_SURFACEALIGN = 0x10,
  PHYSFLAGS_SURFACEBOUNCE = 0x20,
  PHYSFLAGS_FLOORSTICK = 0x40,
  PHYSFLAGS_WALLSTICK = 0x80,
  THINGSTATE_100 = 0x100,
  PHYSFLAGS_ROTVEL = 0x200,
  PHYSFLAGS_BANKEDTURNS = 0x400,
  THINGSTATE_800 = 0x800,
  PHYSFLAGS_ANGTHRUST = 0x1000,
  PHYSFLAGS_FLYING = 0x2000,
  PHYSFLAGS_FEELBLASTFORCE = 0x4000,
  THINGSTATE_8000 = 0x8000,
  PHYSFLAGS_CROUCHING = 0x10000,
  THINGSTATE_20000 = 0x20000,
  PHYSFLAGS_PARTIALGRAVITY = 0x40000,
  THINGSTATE_80000 = 0x80000,
  PHYSFLAGS_MIDAIR = 0x100000,
  THINGSTATE_200000 = 0x200000,
  PHYSFLAGS_NOTHRUST = 0x400000,
  THINGSTATE_800000 = 0x800000,
  THINGSTATE_1000000 = 0x1000000,
  THINGSTATE_2000000 = 0x2000000,
  THINGSTATE_4000000 = 0x4000000,
  THINGSTATE_8000000 = 0x8000000,
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

typedef struct sithThing sithThing; 
typedef struct sithCog sithCog;
typedef struct sithPuppet sithPuppet;
typedef struct jkPlayerInfo jkPlayerInfo;

typedef struct sithThingParticleParams
{
    uint32_t field_0;
    uint32_t count;
    uint32_t field_8;
    float elementSize;
    float growthSpeed;
    float minSize;
    float range;
    float pitchRange;
    float yawRange;
    float rate;
    uint32_t field_28;
    uint32_t field_2C;
    uint32_t field_30;
    uint32_t field_34;
    rdVector3 field_38;
    uint32_t field_44;
    uint32_t field_48;
    uint32_t field_4C;
    uint32_t field_50;
    uint32_t field_54;
    uint32_t field_58;
    uint32_t field_5C;
    uint32_t field_60;
    uint32_t field_64;
    uint32_t field_68;
    uint32_t field_6C;
    uint32_t field_70;
    uint32_t field_74;
    uint32_t field_78;
    uint32_t field_7C;
} sithThingParticleParams;

typedef struct sithThingExplosionParams
{
    uint32_t typeflags;
    uint32_t lifeLeftMs;
    float range;
    float force;
    int blastTime;
    float maxLight;
    uint32_t field_18;
    float damage;
    uint32_t damageClass;
    int flashR;
    int flashG;
    int flashB;
    sithThing* debrisTemplates[4];
    uint32_t field_40;
    uint32_t field_44;
    uint32_t field_48;
    uint32_t field_4C;
    uint32_t field_50;
    uint32_t field_54;
    uint32_t field_58;
    uint32_t field_5C;
    uint32_t field_60;
    uint32_t field_64;
    uint32_t field_68;
    uint32_t field_6C;
    uint32_t field_70;
    uint32_t field_74;
    uint32_t field_78;
    uint32_t field_7C;
    uint32_t field_80;
} sithThingExplosionParams;

typedef struct sithBackpackItem
{
    int16_t binIdx;
    int16_t field_2;
    float value;
} sithBackpackItem;

typedef struct sithThingItemParams
{
    uint32_t typeflags;
    rdVector3 position;
    sithSector* sector;
    uint32_t respawn;
    uint32_t respawnTime;
    int16_t numBins;
    int16_t field_1E;
    sithBackpackItem contents[12];
    uint32_t field_80;
} sithThingItemParams;

typedef struct sithThingWeaponParams
{
    uint32_t typeflags;
    uint32_t damageClass;
    rdMaterial* material;
    float damage;
    sithThing* explodeTemplate;
    sithThing* fleshHitTemplate;
    uint32_t field_18;
    float rate;
    float mindDamage;
    sithThing* trailThing;
    float elementSize;
    float trailCylRadius;
    float trainRandAngle;
    uint32_t field_34;
    float range;
    float force;
    uint32_t field_40;
    uint32_t field_44;
    uint32_t field_48;
    uint32_t field_4C;
    uint32_t field_50;
    uint32_t field_54;
    uint32_t field_58;
    uint32_t field_5C;
    uint32_t field_60;
    uint32_t field_64;
    uint32_t field_68;
    uint32_t field_6C;
    uint32_t field_70;
    uint32_t field_74;
    uint32_t field_78;
    uint32_t field_7C;
    uint32_t field_80;
    uint32_t field_84;
    uint32_t field_88;
    uint32_t field_8C;
} sithThingWeaponParams;

typedef struct sithThingActorParams
{
    uint32_t typeflags;
    float health;
    float maxHealth;
    float force;
    float jumpSpeed;
    float extraSpeed;
    float maxThrust;
    float maxRotThrust;
    sithThing* templateWeapon;
    sithThing* templateWeapon2;
    sithThing* templateExplode;
    rdVector3 eyePYR;
    rdVector3 eyeOffset;
    float minHeadPitch;
    float maxHeadPitch;
    rdVector3 fire_offset;
    rdVector3 lightOffset;
    float lightIntensity;
    rdVector3 saberBladePos;
    float timeLeftLengthChange;
    uint32_t field_1A8;
    uint32_t field_1AC;
    float chance;
    float fov;
    float error;
    uint32_t field_1BC;
    sithPlayerInfo *playerinfo;
    uint32_t field_1C4;
    uint32_t field_1C8;
    uint32_t field_1CC;
} sithThingActorParams;

typedef struct sithThingPhysParams
{
    uint32_t physflags;
    rdVector3 vel;
    rdVector3 angVel;
    rdVector3 acceleration;
    rdVector3 field_1F8;
    float mass;
    float height;
    float airDrag;
    float surfaceDrag;
    float staticDrag;
    float maxRotVel;
    float maxVel;
    float orientSpeed;
    float buoyancy;
} sithThingPhysParams;

typedef struct sithThingFrame
{
    rdVector3 pos;
    rdVector3 rot;
} sithThingFrame;

typedef struct sithThingTrackParams
{
    uint32_t numFrames;
    uint32_t loadedFrames;
    sithThingFrame *frames;
    uint32_t field_C;
    rdVector3 vel;
    uint32_t field_1C;
    float field_20;
    uint32_t field_24;
    uint32_t field_28;
    uint32_t field_2C;
    uint32_t field_30;
    uint32_t field_34;
    uint32_t field_38;
    uint32_t field_3C;
    uint32_t field_40;
    uint32_t field_44;
    rdVector3 field_48;
} sithThingTrackParams;

typedef struct sithThing
{
    uint32_t thingflags;
    uint32_t thingIdx;
    uint32_t thing_id;
    uint32_t thingType;
    uint32_t move_type;
    uint32_t thingtype;
    uint32_t lifeLeftMs;
    uint32_t timer;
    uint32_t pulse_end_ms;
    uint32_t pulse_ms;
    uint32_t collide;
    float moveSize;
    float collideSize;
    uint32_t attach_flags;
    rdVector3 field_38;
    uint32_t field_44;
    float field_48;
    uint32_t field_4C;
    uint32_t field_50;
    uint32_t field_54;
    sithThing* attachedThing;
    sithSector* sector;
    sithThing* nextThing;
    sithThing* prevThing;
    sithThing* attachedParentMaybe;
    sithThing* childThing;
    sithThing* parentThing;
    uint32_t signature;
    sithThing* templateBase;
    uint32_t template;
    sithThing* prev_thing;
    uint32_t child_signature;
    rdMatrix34 lookOrientation;
    rdVector3 position;
    rdThing rdthing;
    uint32_t field_10C;
    float radius_idk;
    uint32_t field_114;
    float light;
    float light_2;
    int isVisible;
    void* soundclass;
    sithAnimclass* animclass;
    sithPuppet* puppet;
    union
    {
        sithThingActorParams actorParams;
        sithThingWeaponParams weaponParams;
        sithThingItemParams itemParams;
        sithThingExplosionParams explosionParams;
        sithThingParticleParams particleParams;
    };
    union
    {
        sithThingPhysParams physicsParams;
        sithThingTrackParams trackParams;
    };
    rdVector3 addedVelocity;
    rdVector3 velocityMaybe;
    float field_240;
    uint32_t field_244;
    uint32_t field_248;
    uint32_t field_24C;
    uint32_t field_250;
    uint32_t curframe;
    uint32_t field_258;
    uint32_t goalframe;
    uint32_t field_260;
    float waggle;
    rdVector3 field_268;
    void* ai;
    void* actor;
    char template_name[32];
    sithCog* class_cog;
    sithCog* capture_cog;
    jkPlayerInfo* playerInfo;
    uint32_t jkFlags;
    float userdata;
} sithThing;

static int (__cdecl *sithThing_DoesRdThingInit)(sithThing *thing) = (void*)0x4CD190;
static int (__cdecl *sithThing_sub_4CD8A0)(sithThing *thing, sithThing *a2) = (void*)0x4CD8A0;
static signed int (*sithThing_ParseArgs)(stdConffileArg *a1, sithThing *thing) = (void*)0x004CEB90;

static sithThing* (*sithThing_SpawnThingInSector)(sithThing *a1, rdVector3 *a2, rdMatrix34 *a3, sithSector *sector, sithThing *a5) = (void*)sithThing_SpawnThingInSector_ADDR;
static sithThing* (*sithThing_SpawnTemplate)(sithThing *a1, sithThing *a2) = (void*)sithThing_SpawnTemplate_ADDR;
static float (*sithThing_Damage)(sithThing *sender, sithThing *reciever, float amount, int damageClass) = (void*)sithThing_Damage_ADDR;
static void (*sithThing_Destroy)(sithThing *a1) = (void*)sithThing_Destroy_ADDR;
static void (*sithThing_LeaveSector)(sithThing *a1) = (void*)sithThing_LeaveSector_ADDR;
static void (*sithThing_SetPosAndRot)(sithThing *thing, rdVector3 *pos, rdMatrix34 *rot) = (void*)sithThing_SetPosAndRot_ADDR;
static void (*sithThing_MoveToSector)(sithThing *a1, sithSector *a2, int a4) = (void*)sithThing_MoveToSector_ADDR;
static void (*sithThing_EnterSector)(sithThing *a1, sithSector *a2, int a3, int a4) = (void*)sithThing_EnterSector_ADDR;
static int (*sithThing_DetachThing_)(sithThing *a1) = (void*)sithThing_DetachThing__ADDR;
static int (*sithThing_Release)(sithThing *a1) = (void*)sithThing_Release_ADDR;
static sithThing* (*sithThing_GetParent)(sithThing *a1) = (void*)sithThing_GetParent_ADDR;
static void (*sithThing_SyncThingPos)(sithThing *a1, int a2) = (void*)sithThing_SyncThingPos_ADDR;
static void (*sithThing_AttachToSurface)(sithThing *a1, sithSurface *a2, int a3) = (void*)sithThing_AttachToSurface_ADDR;
static void (*sithThing_AttachThing)(sithThing *parent, sithThing *child) = (void*)sithThing_AttachThing_ADDR;
static int (*sithThing_SetNewModel)(sithThing *a1, rdModel3 *a2) = (void*)sithThing_SetNewModel_ADDR;

#endif // _SITHTHING_H
