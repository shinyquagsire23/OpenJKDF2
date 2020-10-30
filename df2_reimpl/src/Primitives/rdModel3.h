#ifndef _RDMODEL3_H
#define _RDMODEL3_H

#include "Primitives/rdVector.h"
#include "Primitives/rdFace.h"
#include "Engine/rdMaterial.h"
#include "Primitives/rdMatrix.h"

#define rdModel3_RegisterLoader_ADDR (0x00443DA0)
#define rdModel3_RegisterUnloader_ADDR (0x00443DB0)
#define rdModel3_ClearFrameCounters_ADDR (0x00443DC0)
#define rdModel3_NewEntry_ADDR (0x00443DD0)
#define rdModel3_New_ADDR (0x00443E00)
#define rdModel3_Load_ADDR (0x00443E80)
#define rdModel3_LoadPostProcess_ADDR (0x00444B60)
#define rdModel3_WriteText_ADDR (0x00444B90)
#define rdModel3_Free_ADDR (0x004453C0)
#define rdModel3_FreeEntry_ADDR (0x004453F0)
#define rdModel3_FreeEntryGeometryOnly_ADDR (0x00445560)
#define rdModel3_Validate_ADDR (0x004456B0)
#define rdModel3_CalcBoundingBoxes_ADDR (0x00445750)
#define rdModel3_BuildExpandedRadius_ADDR (0x00445810)
#define rdModel3_CalcFaceNormals_ADDR (0x00445970)
#define rdModel3_CalcVertexNormals_ADDR (0x00445AD0)
#define rdModel3_FindNamedNode_ADDR (0x00445D30)
#define rdModel3_GetMeshMatrix_ADDR (0x00445D80)
#define rdModel3_ReplaceMesh_ADDR (0x00445DD0)
#define rdModel3_Draw_ADDR (0x00445E10)
#define rdModel3_DrawHNode_ADDR (0x00446090)
#define rdModel3_DrawMesh_ADDR (0x00446110)
#define rdModel3_DrawFace_ADDR (0x00446580)

typedef struct rdThing rdThing;
typedef struct rdHierarchyNode rdHierarchyNode;
typedef struct rdMesh rdMesh;

typedef struct rdHierarchyNode
{
    char name[32];
    uint32_t field_20;
    uint32_t field_24;
    uint32_t field_28;
    uint32_t field_2C;
    uint32_t field_30;
    uint32_t field_34;
    uint32_t field_38;
    uint32_t field_3C;
    uint32_t flags;
    uint32_t idx;
    int type;
    rdMesh* mesh;
    rdHierarchyNode* parent;
    uint32_t numChildren;
    rdHierarchyNode* child;
    rdHierarchyNode* nextSibling;
    rdVector3 pivot;
    rdVector3 pos;
    rdVector3 rot;
    rdMatrix34 posRotMatrix;
} rdHierarchyNode;

typedef struct rdGeoset
{
    uint32_t numMeshes;
    rdMesh* meshes;    
} rdGeoset;

typedef struct rdModel3
{
    char filename[32];
    int id;
    rdGeoset geosets[4];
    uint32_t numGeosets;
    rdMaterial** materials;
    uint32_t numMaterials;
    uint32_t field_50;
    uint32_t numHierarchyNodes;
    rdHierarchyNode* hierarchyNodes;
    float radius;
    uint32_t field_60;
    uint32_t field_64;
    uint32_t field_68;
    uint32_t field_6C;
    uint32_t field_70;
    uint32_t field_74;
    rdVector3 insertOffset;
} rdModel3;

typedef struct rdMesh
{
    char name[32];
    int mesh_num;
    int lightingMode;
    int textureMode;
    int sortingMethod;
    rdVector3* vertices;
    rdVector2* vertexUVs;
    float* vertices_i;
    float* vertices_unk;
    rdFace* faces;
    rdVector3* vertexNormals;
    int numVertices;
    int numUVs;
    int numFaces;
    float radius;
    int field_58;
    int field_5C;
    int field_60;
    int field_64;
    int field_68;
    int field_6C;
} rdMesh;

typedef int (__cdecl *model3Loader_t)(char *, rdModel3*);
typedef int (__cdecl *model3Unloader_t)(rdModel3*);

#define dword_73A3D8 (*(int*)0x0073A3D8)
#define localCamera (*(rdVector3*)0x0073A3E0)
// rdVector3[32]
#define aFaceVerts (*(rdVector3*)0x0073A3F0)
#define vertexDst (*(rdMeshinfo*)0x0073A570)
#define curLightingMode (*(int*)0x0073A590)
// rdLight* apGeoLights[64]
#define apGeoLights (*(rdLight*)0x0073A598)

//rdVector3 [64]
#define aLocalLightPos (*(rdVector3*)0x0073A698)
#define meshFrustrumCull (*(int*)0x0073A998)
#define curSortingMethod (*(int*)0x0073A99C)
#define aView (*(rdVector3*)0x0073A9A0)

// rdMesh *pCurMesh
#define pCurMesh (*(void**)0x0073C1A0)
#define thingFrustrumCull (*(int*)0x0073C1A4)
#define vertexSrc (*(rdMeshinfo*)0x0073C1A8)

#define pCurModel3 (*(rdModel3**)0x0073C1C8)
#define rdModel3_sortingMethod (*(int*)0x0073C1CC)
#define curTextureMode (*(int*)0x0073C1D0)

// rdLight*[64]
#define apMeshLights (*(rdLight**)0x0073C1D8)
#define pCurThing (*(rdThing**)0x0073C2D8)
#define rdModel3_textureMode (*(int*)0x0073C2DC)
#define rdModel3_lightingMode (*(int*)0x0073C2E0)
#define rdModel3_numDrawnModels (*(int*)0x0073C2E4)
#define pModel3Loader (*(model3Loader_t*)0x0073C2E8)
#define pModel3Unloader (*(model3Unloader_t*)0x0073C2EC)
#define rdModel3_numGeoLights (*(int*)0x0073C2F0)
#define rdModel3_numMeshLights (*(int*)0x0073C2F4)
#define rdModel3_fRadius (*(float*)0x0073C2F8)

void rdModel3_RegisterLoader(model3Loader_t loader);
void rdModel3_RegisterUnloader(model3Unloader_t unloader);
void rdModel3_ClearFrameCounters();
int rdModel3_NewEntry(rdModel3 *model);
rdModel3* rdModel3_New(char *path);
void rdModel3_Free(rdModel3 *model);
int rdModel3_Load(char *model_fpath, rdModel3 *model);

//static int (__cdecl *rdModel3_Load)(char *model_fpath, rdModel3 *model) = (void*)rdModel3_Load_ADDR;
static void (__cdecl *rdModel3_FreeEntry)(rdModel3 *model) = (void*)rdModel3_FreeEntry_ADDR;
static void (*rdModel3_Draw)(rdThing *thing, rdMatrix34 *matrix) = (void*)rdModel3_Draw_ADDR;

#endif // _RDMODEL3_H
