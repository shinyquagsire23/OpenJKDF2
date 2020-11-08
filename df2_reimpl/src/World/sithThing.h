#ifndef _SITHTHING_H
#define _SITHTHING_H

#include "Primitives/rdVector.h"
#include "Primitives/rdMatrix.h"
#include "Engine/rdThing.h"
#include "World/sithPlayer.h"

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

typedef struct sithAnimclass sithAnimclass;

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

typedef struct sithThing sithThing; 
typedef struct sithCog sithCog;

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
    float move_size;
    float collide_size;
    uint32_t attach_flags;
    uint32_t field_38;
    uint32_t field_3C;
    uint32_t field_40;
    uint32_t field_44;
    uint32_t field_48;
    uint32_t field_4C;
    uint32_t field_50;
    uint32_t field_54;
    sithThing* attachedThing;
    void* sector;
    sithThing* next_thing;
    uint32_t field_64;
    sithThing* attachedParentMaybe;
    sithThing* childThing;
    sithThing* parentThing;
    uint32_t signature;
    uint32_t template_related;
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
    uint32_t unkPtrMajorMode;
    uint32_t typeflags;
    float health;
    float maxHealth;
    float force;
    float jumpSpeed;
    float extraSpeed;
    float maxThrust_;
    float maxRotThrust;
    uint32_t templateWeapon;
    uint32_t templateWeapon2;
    uint32_t templateExplode;
    rdVector3 field_15C;
    rdVector3 eyeOffset;
    float minHeadPitch;
    float maxHeadPitch;
    rdVector3 fire_offset;
    rdVector3 lightOffset;
    float lightIntensity;
    uint32_t field_198;
    uint32_t field_19C;
    uint32_t field_1A0;
    float timeLeftLengthChange;
    uint32_t field_1A8;
    uint32_t field_1AC;
    float chance;
    float fov;
    float error;
    uint32_t field_1BC;
    sithPlayerInfo* playerinfo;
    uint32_t field_1C4;
    uint32_t field_1C8;
    uint32_t field_1CC;
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
    rdVector3 field_228;
    rdVector3 field_234;
    uint32_t field_240;
    uint32_t field_244;
    uint32_t field_248;
    uint32_t field_24C;
    uint32_t field_250;
    uint32_t curframe;
    uint32_t field_258;
    uint32_t goalframe;
    uint32_t field_260;
    uint32_t field_264;
    rdVector3 field_268;
    void* ai;
    void* actor;
    char template_name[32];
    sithCog* class_cog;
    sithCog* capture_cog;
    void* saberInfo;
    uint32_t jkFlags;
    void* userdata;
} sithThing;

static int (__cdecl *sithThing_DoesRdThingInit)(sithThing *thing) = (void*)0x4CD190;
static int (__cdecl *sithThing_sub_4CD8A0)(sithThing *thing, sithThing *a2) = (void*)0x4CD8A0;
static signed int (*sithThing_ParseArgs)(char **a1, sithThing *thing) = (void*)0x004CEB90;

#endif // _SITHTHING_H
