#ifndef _RDTHING_H
#define _RDTHING_H

#include "Primitives/rdMatrix.h"
#include "Primitives/rdModel3.h"
#include "Primitives/rdPolyLine.h"
#include "Primitives/rdParticle.h"
#include "Primitives/rdSprite.h"
#include "Engine/rdPuppet.h"
#include "Engine/rdCamera.h"
#include "Engine/rdLight.h"
#include "types.h"

#define rdThing_New_ADDR (0x0043E1A0)
#define rdThing_NewEntry_ADDR (0x0043E200)
#define rdThing_Free_ADDR (0x0043E260)
#define rdThing_FreeEntry_ADDR (0x0043E2E0)
#define rdThing_SetModel3_ADDR (0x0043E350)
#define rdThing_SetCamera_ADDR (0x0043E440)
#define rdThing_SetLight_ADDR (0x0043E460)
#define rdThing_SetSprite3_ADDR (0x0043E480)
#define rdThing_SetPolyline_ADDR (0x0043E4A0)
#define rdThing_SetParticleCloud_ADDR (0x0043E4C0)
#define rdThing_Draw_ADDR (0x0043E4E0)
#define rdThing_AccumulateMatrices_ADDR (0x0043E560)

enum RD_THINGTYPE
{
    RD_THINGTYPE_0   = 0,
    RD_THINGTYPE_MODEL  = 1,
    RD_THINGTYPE_CAMERA  = 2,
    RD_THINGTYPE_LIGHT  = 3,
    RD_THINGTYPE_SPRITE3  = 4,
    RD_THINGTYPE_PARTICLECLOUD  = 5,
    RD_THINGTYPE_POLYLINE  = 6
};

typedef struct sithThing sithThing;

typedef struct rdThing
{
    int type;
    union containedObj
    {
        rdModel3* model3;
        rdCamera* camera;
        rdLight* light;
        rdSprite* sprite3;
        rdParticle* particlecloud;
        rdPolyLine* polyline;
    };
    uint32_t geoMode;
    uint32_t lightMode;
    uint32_t texMode;
    rdPuppet* puppet;
    uint32_t field_18;
    uint32_t frameTrue;
    rdMatrix34 *hierarchyNodeMatrices;
    rdVector3* hierarchyNodes2;
    int* amputatedJoints;
    uint32_t gap2C;
    uint32_t geosetSelect;
    uint32_t geometryMode;
    uint32_t lightingMode;
    uint32_t textureMode;
    uint32_t clippingIdk;
    sithThing* parentSithThing;
} rdThing;

rdThing* rdThing_New(sithThing *parent);
int rdThing_NewEntry(rdThing *thing, sithThing *parent);
void rdThing_Free(rdThing *thing);
void rdThing_FreeEntry(rdThing *thing);
int rdThing_SetModel3(rdThing *thing, rdModel3 *model);
int rdThing_SetCamera(rdThing *thing, rdCamera *camera);
int rdThing_SetLight(rdThing *thing, rdLight *light);
int rdThing_SetSprite3(rdThing *thing, rdSprite *sprite);
int rdThing_SetPolyline(rdThing *thing, rdPolyLine *polyline);
int rdThing_SetParticleCloud(rdThing *thing, rdParticle *particle);
void rdThing_Draw(rdThing *thing, rdMatrix34 *m);
void rdThing_AccumulateMatrices(rdThing *thing, rdHierarchyNode *node, rdMatrix34 *acc);

#endif // _RDTHING_H
