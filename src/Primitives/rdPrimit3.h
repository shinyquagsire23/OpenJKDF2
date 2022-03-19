#ifndef _RDPRIMIT3_H
#define _RDPRIMIT3_H

#include "Engine/rdCamera.h"
#include "Primitives/rdModel3.h"
#include "Primitives/rdFace.h"
#include "Primitives/rdVector.h"
#include "Engine/rdCache.h"

#define rdPrimit3_ClearFrameCounters_ADDR (0x00446F50)
#define rdPrimit3_GetScreenCoord_ADDR (0x00446F60)
#define rdPrimit3_DrawPoint_ADDR (0x00446FF0)
#define rdPrimit3_DrawLine_ADDR (0x004470C0)
#define rdPrimit3_DrawCircle_ADDR (0x004471E0)
#define rdPrimit3_BuildVertexLst_ADDR (0x004472B0)
#define rdPrimit3_ClipVertexLst_ADDR (0x00447860)
#define rdPrimit3_ClipFace_ADDR (0x00447A60)
#define rdPrimit3_NoClipFace_ADDR (0x00448160)


void rdPrimit3_ClearFrameCounters(void);
void rdPrimit3_ClipFace(rdClipFrustum *clipFrustum, signed int clipType, signed int clipSubtype, int sortingMethod, rdVertexIdxInfo *idxInfo, rdMeshinfo *mesh_out, rdVector2 *idkIn);
//void rdPrimit3_NoClipFace(int geometryMode, signed int lightingMode, int textureMode, rdMeshinfo *_vertexSrc, rdMeshinfo *_vertexDst, rdVector2 *clipIdk);
void rdPrimit3_NoClipFace(int clipType, signed int clipSubtype, int sortingMethod, rdMeshinfo *vertexSrc, rdMeshinfo *vertexDst, rdVector2 *idkIn);
int rdPrimit3_GetScreenCoord(rdVector3 *vec, rdScreenPoint *screenpt);
void rdPrimit3_DrawCircle(rdVector3 *pVecPos, float xOffs, float radius, int color16, int mask);

static void (__cdecl *_rdPrimit3_ClipFace)(rdClipFrustum *a1, signed int a2, signed int a3, int textureMode, rdVertexIdxInfo *idxInfo, rdMeshinfo *mesh_out, rdVector2 *a7) = (void*)rdPrimit3_ClipFace_ADDR;
//static void (__cdecl *rdPrimit3_NoClipFace)(int a1, signed int lightingMode, int textureMode, rdMeshinfo *a4, rdMeshinfo *a5, rdVector2 *a6) = (void*)rdPrimit3_NoClipFace_ADDR;

//static int (*rdPrimit3_GetScreenCoord)(rdVector3 *vec, rdScreenPoint *a2) = (void*)rdPrimit3_GetScreenCoord_ADDR;

#endif // _RDPRIMIT3_H
