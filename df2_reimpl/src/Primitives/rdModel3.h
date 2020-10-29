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
#define rdModel3_Load_ADDR (0x00443E00)
#define rdModel3_LoadEntryText_ADDR (0x00443E80)
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
    void* mesh; // rdMesh
    rdHierarchyNode* parent;
    uint32_t numChildren;
    rdHierarchyNode* child;
    rdHierarchyNode* nextSibling;
    rdVector3 pivot;
    rdVector3 pos;
    rdVector3 rot;
    rdMatrix34 posRotMatrix;
} rdHierarchyNode;

typedef struct rdModel3
{
    char filename[32];
    int id;
    uint32_t num_meshes;
    void* meshes_alloc; // rdMesh*
    uint32_t sortingMethod;
    uint32_t field_30;
    uint32_t field_34;
    uint32_t field_38;
    uint32_t field_3C;
    uint32_t field_40;
    uint32_t num_geosets;
    rdMaterial* materials_alloc;
    uint32_t num_materials;
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
    rdVector3 insert_offset;
} rdModel3;

static void (*rdModel3_ClearFrameCounters)(void) = (void*)rdModel3_ClearFrameCounters_ADDR;
static void (*rdModel3_Draw)(rdThing *thing, rdMatrix34 *matrix) = (void*)rdModel3_Draw_ADDR;

#endif // _RDMODEL3_H
