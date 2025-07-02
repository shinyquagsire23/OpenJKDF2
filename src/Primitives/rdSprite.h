#ifndef _RDSPRITE_H
#define _RDSPRITE_H

#include "Primitives/rdVector.h"
#include "Primitives/rdMatrix.h"
#include "Raster/rdFace.h"

#define rdSprite_New_ADDR (0x0046C9C0)
#define rdSprite_NewEntry_ADDR (0x0046CA20)
#define rdSprite_Free_ADDR (0x0046CC20)
#define rdSprite_FreeEntry_ADDR (0x0046CC90)
#define rdSprite_Draw_ADDR (0x0046CCF0)

typedef struct rdThing rdThing;
typedef struct rdMaterial rdMaterial;
typedef struct rdSprite
{
    char path[32];
    int type;
    flex_t radius;
    uint32_t anonymous_10;
    uint32_t anonymous_11;
    uint32_t anonymous_12;
    uint32_t anonymous_13;
    uint32_t anonymous_14;
    uint32_t anonymous_15;
    uint32_t anonymous_16;
    uint32_t anonymous_17;
    uint32_t anonymous_18;
    flex_t width;
    flex_t height;
    flex_t halfWidth;
    flex_t halfHeight;
    rdFace face;
    rdVector2* vertexUVs;
    rdVector3 offset;
} rdSprite;

rdSprite* rdSprite_New(int type, char *fpath, char *materialFpath, flex_t width, flex_t height, int geometryMode, int lightMode, int textureMode, flex_t extraLight, rdVector3 *offset);
int rdSprite_NewEntry(rdSprite *sprite, char *spritepath, int type, char *material, flex_t width, flex_t height, rdGeoMode_t geometryMode, rdLightMode_t lightMode, rdTexMode_t textureMode, flex_t extraLight, rdVector3 *offset);
void rdSprite_Free(rdSprite *sprite);
void rdSprite_FreeEntry(rdSprite *sprite);
int rdSprite_Draw(rdThing *thing, rdMatrix34 *mat);

#endif // _RDSPRITE_H
