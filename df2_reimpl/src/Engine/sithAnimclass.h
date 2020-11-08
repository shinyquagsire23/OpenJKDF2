#ifndef _SITHANIMCLASS_H
#define _SITHANIMCLASS_H

enum SITH_ANIM
{
    SITH_ANIM_0      = 0,
    SITH_ANIM_STAND  = 1,
    SITH_ANIM_WALK   = 2,
    SITH_ANIM_RUN    = 3,
    SITH_ANIM_WALKBACK  = 4,
    SITH_ANIM_STRAFELEFT  = 5,
    SITH_ANIM_STRAFERIGHT  = 6,
    SITH_ANIM_DEATH  = 7,
    SITH_ANIM_FIRE   = 8,
    SITH_ANIM_FIRE3  = 9,
    SITH_ANIM_FIRE4  = 10,
    SITH_ANIM_DEATH2  = 11,
    SITH_ANIM_HIT    = 12,
    SITH_ANIM_HIT2   = 13,
    SITH_ANIM_RISING  = 14,
    SITH_ANIM_TOSS   = 15,
    SITH_ANIM_PLACE  = 16,
    SITH_ANIM_DROP   = 17,
    SITH_ANIM_FIRE2  = 18,
    SITH_ANIM_FALL   = 19,
    SITH_ANIM_LAND   = 20,
    SITH_ANIM_CROUCHFORWARD  = 21,
    SITH_ANIM_CROUCHBACK  = 22,
    SITH_ANIM_ACTIVATE  = 23,
    SITH_ANIM_MAGIC  = 24,
    SITH_ANIM_CHOKE  = 25,
    SITH_ANIM_LEAP   = 26,
    SITH_ANIM_JUMP   = 27,
    SITH_ANIM_RESERVED  = 28,
    SITH_ANIM_BLOCK  = 29,
    SITH_ANIM_BLOCK2  = 30,
    SITH_ANIM_TURNLEFT  = 31,
    SITH_ANIM_TURNRIGHT  = 32,
    SITH_ANIM_FIDGET  = 33,
    SITH_ANIM_FIDGET2  = 34,
    SITH_ANIM_MAGIC2  = 35,
    SITH_ANIM_MAGIC3  = 36,
    SITH_ANIM_VICTORY  = 37,
    SITH_ANIM_WINDUP  = 38,
    SITH_ANIM_HOLSTER  = 39,
    SITH_ANIM_DRAWFISTS  = 40,
    SITH_ANIM_DRAWGUN  = 41,
    SITH_ANIM_DRAWSABER  = 42
};

typedef struct sithAnimclassEntry
{
    uint32_t keyframe;
    uint32_t flags;
    uint32_t lowPri;
    uint32_t highPri;
} sithAnimclassEntry;

typedef struct sithAnimclassMode
{
    sithAnimclassEntry keyframe[42];
    uint32_t field_2A0;
    uint32_t field_2A4;
    uint32_t field_2A8;
    uint32_t field_2AC;
} sithAnimclassMode;

typedef struct sithAnimclass
{
    char name[32];
    sithAnimclassMode modes[6];
    int bodypart_to_joint[10];
} sithAnimclass;

enum JOINTTYPE
{
    JOINTTYPE_HEAD   = 0,
    JOINTTYPE_NECK   = 1,
    JOINTTYPE_TORSO  = 2,
    JOINTTYPE_PRIMARYWEAP  = 3,
    JOINTTYPE_SECONDARYWEAP  = 4,
    JOINTTYPE_PRIMARYWEAPJOINT  = 5,
    JOINTTYPE_SECONDARYWEAPJOINT  = 6,
};

#endif // _SITHANIMCLASS_H
