#ifndef _JKSABER_H
#define _JKSABER_H

#include "types.h"

#define jkSaber_InitializeSaberInfo_ADDR (0x0040B4C0)
#define jkSaber_PolylineRand_ADDR (0x0040B590)
#define jkSaber_Draw_ADDR (0x0040B5E0)
#define jkSaber_UpdateLength_ADDR (0x0040B6D0)
#define jkSaber_UpdateCollision_ADDR (0x0040B860)
#define jkSaber_SpawnSparks_ADDR (0x0040BF40)
#define jkSaber_Enable_ADDR (0x0040BFC0)
#define jkSaber_Disable_ADDR (0x0040C020)

enum JKSABER_SPARKTYPE_E
{
    SPARKTYPE_WALL = 0,
    SPARKTYPE_BLOOD = 1,
    SPARKTYPE_SABER = 2,
};

void jkSaber_InitializeSaberInfo(sithThing *thing, char *material_side_fname, char *material_tip_fname, flex_t base_rad, flex_t tip_rad, flex_t len, sithThing *wall_sparks, sithThing *blood_sparks, sithThing *saber_sparks);
MATH_FUNC void jkSaber_PolylineRand(rdThing *thing);
MATH_FUNC void jkSaber_Draw(rdMatrix34 *posRotMat);
MATH_FUNC void jkSaber_UpdateLength(sithThing *thing);
MATH_FUNC void jkSaber_UpdateCollision(sithThing *player, int joint, int bSecondary);
MATH_FUNC void jkSaber_SpawnSparks(jkPlayerInfo *pPlayerInfo, rdVector3 *pPos, sithSector *psector, int sparkType);
void jkSaber_Enable(sithThing *pThing, flex_t damage, flex_t bladeLength, flex_t stunDelay);
void jkSaber_Disable(sithThing *player);

//static void (*jkSaber_UpdateCollision)(sithThing *player, int joint) = (void*)jkSaber_UpdateCollision_ADDR;

#endif // _JKSABER_H
