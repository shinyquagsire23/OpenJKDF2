#ifndef _RDCLIP_H
#define _RDCLIP_H

#include "types.h"
#include "globals.h"

#define rdClip_Line2_ADDR (0x0046D6F0)
#define rdClip_CalcOutcode2_ADDR (0x0046DA10)
#define rdClip_Point3_ADDR (0x0046DA50)
#define rdClip_Line3Project_ADDR (0x0046DB10)
#define rdClip_Line3Ortho_ADDR (0x0046E480)
#define rdClip_Line3_ADDR (0x0046E9D0)
#define rdClip_Face3W_ADDR (0x0046EAF0)
#define rdClip_Face3WOrtho_ADDR (0x0046F420)
#define rdClip_Face3S_ADDR (0x0046FAE0)
#define rdClip_Face3SOrtho_ADDR (0x00470410)
#define rdClip_Face3GS_ADDR (0x00470AD0)
#define rdClip_Face3GSOrtho_ADDR (0x004716F0)
#define rdClip_Face3T_ADDR (0x00472090)
#define rdClip_Face3TOrtho_ADDR (0x00472DC0)
#define rdClip_Face3GT_ADDR (0x00473880)
#define rdClip_Face3GTOrtho_ADDR (0x004748D0)
#define rdClip_SphereInFrustrum_ADDR (0x004756E0)

int rdClip_Line2(rdCanvas *canvas, signed int *pX1, signed int *pY1, signed int *pX2, signed int *pY2);
int rdClip_CalcOutcode2(rdCanvas *canvas, int x, int y);
int rdClip_Point3(rdClipFrustum *clipFrustum, rdVector3 *point);
int rdClip_Line3Project(rdClipFrustum *clipFrustum, rdVector3 *point1, rdVector3 *point2, int *out1, int *out2);
int rdClip_Line3Ortho(rdClipFrustum *clipFrustum, rdVector3 *point1, rdVector3 *point2, int *out1, int *out2);
int rdClip_Line3(rdClipFrustum *clipFrustum, rdVector3 *point1, rdVector3 *point2, rdVector3 *pointOut1, rdVector3 *pointOut2, int *out1, int *out2);

int rdClip_SphereInFrustrum(rdClipFrustum *frust, rdVector3 *pos, flex_t rad);

int rdClip_Face3W(rdClipFrustum *frustum, rdVector3 *vertices, int numVertices);
int rdClip_Face3GT(rdClipFrustum *frustum, rdVector3 *vertices, rdVector2 *uvs, flex_t *a4, int numVertices);
int rdClip_Face3S(rdClipFrustum *frustum, rdVector3 *vertices, int numVertices);
int rdClip_Face3GS(rdClipFrustum *frustum, rdVector3 *vertices, flex_t *a3, int numVertices);
int rdClip_Face3T(rdClipFrustum *frustum, rdVector3 *vertices, rdVector2 *uvs, int numVertices);

int rdClip_Face3GSRGB(rdClipFrustum *frustum, rdVector3 *vertices, flex_t *pR, flex_t *pG, flex_t *pB, int numVertices);
int rdClip_Face3GTRGB(rdClipFrustum *frustum, rdVector3 *vertices, rdVector2 *uvs, flex_t *pR, flex_t *pG, flex_t *pB, int numVertices);

//static int (__cdecl *rdClip_SphereInFrustrum)(rdClipFrustum *frust, rdVector3 *pos, flex_t rad) = (void*)rdClip_SphereInFrustrum_ADDR;
//static int (*rdClip_Face3SOrtho)(rdClipFrustum *frustum, rdVector3 *vertices, int numVertices) = (void*)rdClip_Face3SOrtho_ADDR;
//static int (*rdClip_Face3WOrtho)(rdClipFrustum *frustum, rdVector3 *vertices, int numVertices) = (void*)rdClip_Face3WOrtho_ADDR;
//static int (*rdClip_Face3GSOrtho)(rdClipFrustum *frustum, rdVector3 *vertices, flex_t *a3, int numVertices) = (void*)rdClip_Face3GSOrtho_ADDR;
//static int (*rdClip_Face3TOrtho)(rdClipFrustum *frustum, rdVector3 *vertices, rdVector2 *uvs, int numVertices) = (void*)rdClip_Face3TOrtho_ADDR;
//static int (*rdClip_Face3GTOrtho)(rdClipFrustum *frustum, rdVector3 *vertices, rdVector2 *uvs, flex_t *a4, int numVertices) = (void*)rdClip_Face3GTOrtho_ADDR;

//static int (*_rdClip_Face3T)(rdClipFrustum *frustum, rdVector3 *vertices, rdVector2 *uvs, int numVertices) = (void*)rdClip_Face3T_ADDR;
//static int (*_rdClip_Face3GT)(rdClipFrustum *frustum, rdVector3 *vertices, rdVector2 *uvs, flex_t *a4, int numVertices) = (void*)rdClip_Face3GT_ADDR;
//static int (*_rdClip_Face3S)(rdClipFrustum *frustum, rdVector3 *vertices, int numVertices) = (void*)rdClip_Face3S_ADDR;
//static int (*_rdClip_Face3W)(rdClipFrustum *frustum, rdVector3 *vertices, int numVertices) = (void*)rdClip_Face3W_ADDR;
//static int (*_rdClip_Face3GS)(rdClipFrustum *frustum, rdVector3 *vertices, flex_t *a3, int numVertices) = (void*)rdClip_Face3GS_ADDR;

// TODO: Decompile these
#define rdClip_Face3SOrtho rdClip_Face3S
#define rdClip_Face3WOrtho rdClip_Face3W
#define rdClip_Face3GSOrtho rdClip_Face3GS
#define rdClip_Face3TOrtho rdClip_Face3T
#define rdClip_Face3GTOrtho rdClip_Face3GT

#endif // _RDCLIP_H
