#ifndef _RDPARTICLE_H
#define _RDPARTICLE_H

#include "Engine/rdMaterial.h"
#include "Primitives/rdVector.h"
#include "Primitives/rdMatrix.h"

#define rdParticle_RegisterLoader_ADDR (0x0046BF70)
#define rdParticle_New_ADDR (0x0046BF80)
#define rdParticle_NewEntry_ADDR (0x0046BFC0)
#define rdParticle_Clone_ADDR (0x0046C090)
#define rdParticle_Free_ADDR (0x0046C110)
#define rdParticle_FreeEntry_ADDR (0x0046C160)
#define rdParticle_Load_ADDR (0x0046C1A0)
#define rdParticle_LoadEntry_ADDR (0x0046C230)
#define rdParticle_Write_ADDR (0x0046C540)
#define rdParticle_Draw_ADDR (0x0046C750)

typedef struct rdThing rdThing;

typedef struct rdParticle
{
    char name[32];
    int lightingMode;
    uint32_t numVertices;
    rdVector3* vertices;
    int* vertexCel;
    flex_t diameter;
    flex_t radius;
    rdMaterial* material;
    flex_t cloudRadius;
    int hasVertices;
    rdVector3 insertOffset;
} rdParticle;

typedef rdParticle* (__cdecl *rdParticleLoader_t)(char*);

void rdParticle_RegisterLoader(rdParticleLoader_t loader);
rdParticle* rdParticle_New(int numVertices, flex_t size, rdMaterial *material, int lightingMode, int allocateVertices);
int rdParticle_NewEntry(rdParticle *particle, int numVertices, flex_t size, rdMaterial *material, int lightingMode, int allocateVertices);
rdParticle* rdParticle_Clone(rdParticle *particle);
void rdParticle_Free(rdParticle *particle);
void rdParticle_FreeEntry(rdParticle *particle);
rdParticle* rdParticle_Load(char *path);
int rdParticle_LoadEntry(char *fpath, rdParticle *particle);
int rdParticle_Write(char *writePath, rdParticle *particle, char *madeBy);
MATH_FUNC int rdParticle_Draw(rdThing *thing, rdMatrix34 *matrix_4_3);

//static void (*rdParticle_Draw)(rdThing *thing, rdMatrix34 *matrix) = (void*)rdParticle_Draw_ADDR;

#endif // _RDPARTICLE_H
