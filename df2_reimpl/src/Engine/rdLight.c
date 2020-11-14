#include "rdLight.h"

#include "jk.h"

#include "Primitives/rdMath.h"
#include "Engine/rdroid.h"

rdLight *rdLight_New()
{
    rdLight *light;

    light = (rdLight*)rdroid_pHS->alloc(sizeof(rdLight));
    if (!light)
    return 0;

    rdLight_NewEntry(light);

    return light;
}

int rdLight_NewEntry(rdLight *light)
{
    light->dword4 = 2;
    light->active = 1;
    light->direction.x = 0.0;
    light->direction.y = 0.0;
    light->direction.z = 0.0;
    light->intensity = 1.0;
    light->color = 0xFFFFFF;
    light->dword20 = 0;
    light->dword24 = 0;
    return 1;
}

void rdLight_Free(rdLight *light)
{
    if (light)
        rdroid_pHS->free(light);
}

void rdLight_FreeEntry(rdLight *light)
{
}

void rdLight_CalcVertexIntensities(rdLight **meshLights, rdVector3 *localLightPoses, int numLights, rdVector3 *verticesEnd, rdVector3 *vertices, float *vertices_i_end, float *vertices_i, int numVertices, float scalar)
{
    int vertexLightsSize;
    rdVector3* vertexIter;
    rdLight **meshLightIter;
    float len;
    float lightMagnitude;
    rdLight *light;
    rdVector3 diff;
    rdVector3 *vertexNormals;
    float *outLights;
    float *idkIter;
    int i, j;

    if (!numVertices)
        return;

    // TODO: this was inlined from another (uncalled) function
    vertexNormals = verticesEnd;
    idkIter = vertices_i_end;
    outLights = vertices_i;
    vertexIter = vertices;
    for (j = numVertices; j != 1; --j)
    {
        *outLights = *idkIter;
        meshLightIter = meshLights;
        for (i = 0; i < numLights; i++)
        {
            diff.x = localLightPoses[i].x - vertexIter->x;
            diff.y = localLightPoses[i].y - vertexIter->y;
            diff.z = localLightPoses[i].z - vertexIter->z;
            light = *meshLightIter;
            len = rdVector_Len3(&diff);
            if ( len < (*meshLightIter)->falloffMin )
            {
                rdVector_Normalize3Acc(&diff);
                lightMagnitude = rdVector_Dot3(vertexNormals, &diff);
                if ( lightMagnitude > 0.0 )
                    *outLights += (light->intensity - len * scalar) * lightMagnitude;
            }
            if ( *outLights >= 1.0 )
                break;
            ++meshLightIter;
        }

        ++vertexIter;
        ++outLights;
        ++idkIter;
        ++vertexNormals;
    }
}

float rdLight_CalcFaceIntensity(rdLight **meshLights, rdVector3 *localLightPoses, int numLights, rdFace *face, rdVector3 *faceNormal, rdVector3 *vertices, float a7)
{
  rdVector3 *lightPosIter; // esi
  rdLight *meshLight; // ebx
  int *v9; // eax
  float v10; // st7
  float v11; // st7
  float intensity; // [esp+10h] [ebp-14h]
  int v15; // [esp+14h] [ebp-10h]
  rdVector3 diff; // [esp+18h] [ebp-Ch]
  float meshLightsa; // [esp+28h] [ebp+4h]
  rdLight **meshLightIter; // [esp+2Ch] [ebp+8h]

  intensity = 0.0;
  lightPosIter = localLightPoses;
  meshLightIter = meshLights;
  for (v15 = 0; v15 < numLights; v15++)
  {
      meshLight = *meshLightIter;
      if ( (*meshLightIter)->active )
      {
        v9 = face->vertexPosIdx;
        diff.x = lightPosIter->x - vertices[*v9].x;
        diff.y = lightPosIter->y - vertices[*v9].y;
        diff.z = lightPosIter->z - vertices[*v9].z;
        v10 = rdMath_DistancePointToPlane(lightPosIter, faceNormal, &vertices[*v9]);
        meshLightsa = v10;
        if ( v10 < meshLight->falloffMin )
        {
          rdVector_Normalize3Acc(&diff);
          v11 = rdVector_Dot3(faceNormal, &diff);
          if ( v11 > 0.0 )
            intensity += (meshLight->intensity - meshLightsa * a7) * v11;
        }
      }
      if ( intensity >= 1.0 )
        break;
      ++lightPosIter;
      ++meshLightIter;
  }
  return intensity;
}

// TODO? unused
void rdLight_CalcDistVertexIntensities(){}
void rdLight_CalcDistFaceIntensity(){}
