#ifndef _RDTHING_H
#define _RDTHING_H

#include "types.h"
#include "globals.h"

#include "Primitives/rdModel3.h"
#include "Primitives/rdPolyline.h"
#include "Primitives/rdParticle.h"
#include "Primitives/rdSprite.h"
#include "Engine/rdPuppet.h"
#include "Engine/rdCamera.h"
#include "Engine/rdLight.h"

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

rdThing* rdThing_New(SithThing *pThing);
int rdThing_NewEntry(rdThing *prdThing, SithThing *pThing);
void rdThing_Free(rdThing *pThing);
void rdThing_FreeEntry(rdThing *pThing);
int rdThing_SetModel3(rdThing *thing, rdModel3 *model);
int rdThing_SetCamera(rdThing *pThing, rdCamera *pCamera);
int rdThing_SetLight(rdThing *pThing, rdLight *pLight);
int rdThing_SetSprite3(rdThing *thing, rdSprite *sprite);
int rdThing_SetPolyline(rdThing *pThing, rdPolyline *pPolyline);
int rdThing_SetParticleCloud(rdThing *pThing, rdParticle *pParticle);
MATH_FUNC int rdThing_Draw(rdThing *pThing, rdMatrix34 *pOrient);
MATH_FUNC FAST_FUNC void rdThing_AccumulateMatrices(rdThing *pThing, rdHierarchyNode *pNode, rdMatrix34 *pPlacement);

#endif // _RDTHING_H
