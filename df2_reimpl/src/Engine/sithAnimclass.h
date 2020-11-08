#ifndef _SITHANIMCLASS_H
#define _SITHANIMCLASS_H

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
