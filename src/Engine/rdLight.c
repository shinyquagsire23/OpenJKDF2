#include "rdLight.h"

#include "jk.h"

#include "Primitives/rdMath.h"
#include "Engine/rdroid.h"
#include "General/stdMath.h"

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
    light->type = 2;
    light->active = 1;
    light->direction.x = 0.0;
    light->direction.y = 0.0;
    light->direction.z = 0.0;
    light->intensity = 1.0;
    light->color = 0xFFFFFF;
#ifdef JKM_LIGHTING
    light->angleX = 0.0;
    light->cosAngleX = 0.0;
    light->angleY = 0.0;
    light->cosAngleY = 0.0;
#else
    light->dword20 = 0;
    light->dword24 = 0;
#endif
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

#ifdef JKM_LIGHTING
void rdLight_SetAngles(rdLight *pLight, flex_t angleX, flex_t angleY)
{
    flex_t local_4;
    
    local_4 = 0.0;
    pLight->angleX = angleX;
    pLight->angleY = angleY;

    stdMath_SinCos(angleX, &local_4, &pLight->cosAngleX);
    stdMath_SinCos(angleY, &local_4, &pLight->cosAngleY);

    // Grim Fandango added: divide safety
    double denom = (pLight->cosAngleX - pLight->cosAngleY);
    if (denom != 0.0) {
        pLight->lux = 1.0 / denom;
    }
    return;
}
#endif

double rdLight_CalcVertexIntensities(rdLight **meshLights, rdVector3 *localLightPoses, 
#ifdef JKM_LIGHTING
    rdVector3 *localLightDirs, 
#endif
    int numLights, rdVector3 *verticesEnd, rdVector3 *vertices, flex_t *vertices_i_end, flex_t *vertices_i, int numVertices, flex_t scalar)
{
#ifndef JKM_LIGHTING
    int vertexLightsSize;
    rdVector3* vertexIter;
    rdLight **meshLightIter;
    flex_t len;
    flex_t lightMagnitude;
    rdLight *light;
    rdVector3 diff;
    rdVector3 *vertexNormals;
    flex_t *outLights;
    flex_t *idkIter;
    int i, j;

    if (!numVertices)
        return 0.0;

    // TODO: this was inlined from another (uncalled) function
    vertexNormals = verticesEnd;
    idkIter = vertices_i_end;
    outLights = vertices_i;
    vertexIter = vertices;
    for (j = 0; j < numVertices; j++)
    {
        *outLights = *idkIter;
        meshLightIter = meshLights;
        for (i = 0; i < numLights; i++)
        {
            rdVector_Sub3(&diff, &localLightPoses[i], vertexIter);
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
    return 0.0;

#else
    if (!localLightDirs || !Main_bMotsCompat)
    {
        int vertexLightsSize;
        rdVector3* vertexIter;
        rdLight **meshLightIter;
        flex_t len;
        flex_t lightMagnitude;
        rdLight *light;
        rdVector3 diff;
        rdVector3 *vertexNormals;
        flex_t *outLights;
        flex_t *idkIter;
        int i, j;

        if (!numVertices)
            return 0.0;

        // TODO: this was inlined from another (uncalled) function
        vertexNormals = verticesEnd;
        idkIter = vertices_i_end;
        outLights = vertices_i;
        vertexIter = vertices;
        for (j = 0; j < numVertices; j++)
        {
            *outLights = *idkIter;
            meshLightIter = meshLights;
            for (i = 0; i < numLights; i++)
            {
                rdVector_Sub3(&diff, &localLightPoses[i], vertexIter);
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
        return 0.0;
    }

    flex_t fVar1;
    rdLight *light;
    flex_t lightMagnitude;
    rdVector3 *vertexNormals;
    rdVector3 *lightDirIter;
    flex_t fVar8;
    rdVector3 *vertexIter;
    flex_t local_28;
    rdVector3 diff;
    rdLight** meshLightIter;
    flex_t* outLights;
    
    local_28 = 0.0;
    if (numVertices == 0) return 0.0;
    
    outLights = vertices_i;
    vertexIter = vertices;
    vertexNormals = verticesEnd;
    for (int vertIdx = 0; vertIdx < numVertices; vertIdx++)
    {
        *outLights = *vertices_i_end;

        meshLightIter = meshLights;
        verticesEnd = localLightPoses;
        lightDirIter = localLightDirs;
        
        for (int i = 0; i < numLights; i++)
        {
            rdVector_Sub3(&diff, verticesEnd, vertexIter);
            light = *meshLightIter;
            if ((light->falloffMin * light->falloffMin) > rdVector_Dot3(&diff, &diff))
            {
                fVar8 = rdVector_Normalize3Acc(&diff);
                if (light->type < 3) 
                {
                    lightMagnitude = rdVector_Dot3(vertexNormals, &diff);
                    if (lightMagnitude > 0.0) 
                    {
                        *outLights += (light->intensity - fVar8 * scalar) * lightMagnitude;
                    }
                }
                else 
                {
                    lightMagnitude = rdVector_Dot3(lightDirIter, &diff);
                    if (lightMagnitude > light->cosAngleY)
                    {
                        fVar1 = light->intensity;
                        if (lightMagnitude < light->cosAngleX)
                        {
                            fVar1 = (1.0 - (light->cosAngleX - lightMagnitude) * light->lux) * fVar1;
                        }
                        *outLights += (fVar1 - fVar8 * scalar) * rdVector_Dot3(vertexNormals, lightDirIter);
                    }
                }
            }

            if (*outLights > 1.0) {
                *outLights = 1.0;
            }
            if (*outLights == 1.0) break;
            meshLightIter++;
            verticesEnd++;
            lightDirIter++;
        }
    
        local_28 += *outLights;
        vertexNormals++;
        vertexIter++;
        outLights++;
    } 
    return (double)(local_28 / (flex_t)numVertices);
#endif
}

flex_t rdLight_CalcFaceIntensity(rdLight **meshLights, rdVector3 *localLightPoses, int numLights, rdFace *face, rdVector3 *faceNormal, rdVector3 *vertices, flex_t a7)
{
  rdVector3 *lightPosIter; // esi
  rdLight *meshLight; // ebx
  int *v9; // eax
  flex_t v10; // st7
  flex_t v11; // st7
  flex_t intensity; // [esp+10h] [ebp-14h]
  int v15; // [esp+14h] [ebp-10h]
  rdVector3 diff; // [esp+18h] [ebp-Ch]
  flex_t meshLightsa; // [esp+28h] [ebp+4h]
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
        rdVector_Sub3(&diff, lightPosIter, &vertices[*v9]);
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
