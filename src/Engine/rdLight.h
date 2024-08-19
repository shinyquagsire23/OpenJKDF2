#ifndef _RDLIGHT_H
#define _RDLIGHT_H

#include "types.h"

#include "Primitives/rdVector.h"
#include "Primitives/rdModel3.h"

#define rdLight_New_ADDR (0x0044B650)
#define rdLight_NewEntry_ADDR (0x0044B6A0)
#define rdLight_Free_ADDR (0x0044B6E0)
#define rdLight_FreeEntry_ADDR (0x0044B700)
#define rdLight_CalcVertexIntensities_ADDR (0x0044B710)
#define rdLight_CalcDistVertexIntensities_ADDR (0x0044B880) // inlined/unused
#define rdLight_CalcFaceIntensity_ADDR (0x0044B960)
#define rdLight_CalcDistFaceIntensity_ADDR (0x0044BAA0) // inlined/unused

rdLight *rdLight_New();
int rdLight_NewEntry(rdLight *light);
void rdLight_Free(rdLight *light);
void rdLight_FreeEntry(rdLight *light);
#ifdef JKM_LIGHTING
void rdLight_SetAngles(rdLight *pLight, float angleX, float angleY);
#endif

double rdLight_CalcVertexIntensities(rdLight **meshLights, rdVector3 *localLightPoses, 
#ifdef JKM_LIGHTING
    rdVector3 *localLightDirs, 
#endif
    int numLights, rdVector3 *verticesEnd, rdVector3 *vertices, float *vertices_i_end, float *vertices_i,
#ifdef RGB_THING_LIGHTS
	float* vertices_r, float* vertices_g, float* vertices_b,
	rdAmbient* ambient, rdMatrix34* mat,
#endif
	int numVertices, float scalar);
float rdLight_CalcFaceIntensity(rdLight **meshLights, rdVector3 *localLightPoses, int numLights, rdFace *face, rdVector3 *faceNormal, rdVector3 *vertices, float a7);

void rdLight_CalcDistVertexIntensities();
void rdLight_CalcDistFaceIntensity();

#ifdef RGB_AMBIENT
void rdAmbient_Zero(rdAmbient* ambient);
void rdAmbient_Acc(rdAmbient* ambient, rdVector3* color, rdVector3* dir);
void rdAmbient_Scale(rdAmbient* ambient, float scale);
void rdAmbient_Copy(rdAmbient* outAmbient, const rdAmbient* ambient);
void rdAmbient_CalculateVertexColor(rdAmbient* ambient, rdVector3* normal, rdVector3* outColor);
#endif

#endif // _RDLIGHT_H
