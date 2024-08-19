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
#ifdef RGB_THING_LIGHTS
	rdVector_Set3(&light->color, 1.0f, 1.0f, 1.0f);
#else
	light->color = 0xFFFFFF;
#endif
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
void rdLight_SetAngles(rdLight *pLight, float angleX, float angleY)
{
    float local_4;
    
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
    int numLights, rdVector3 *verticesEnd, rdVector3 *vertices, float *vertices_i_end, float *vertices_i,
#ifdef RGB_THING_LIGHTS
	float* vertices_r, float* vertices_g, float* vertices_b,
	rdAmbient* ambient, rdMatrix34* mat,
 #endif
	int numVertices, float scalar)
{
#ifndef JKM_LIGHTING
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
        float len;
        float lightMagnitude;
        rdLight *light;
        rdVector3 diff;
        rdVector3 *vertexNormals;
        float *outLights;
#ifdef RGB_THING_LIGHTS
		float* outLightsR;
		float* outLightsG;
		float* outLightsB;
#endif
        float *idkIter;
        int i, j;

        if (!numVertices)
            return 0.0;

        // TODO: this was inlined from another (uncalled) function
        vertexNormals = verticesEnd;
        idkIter = vertices_i_end;
        outLights = vertices_i;
#ifdef RGB_THING_LIGHTS
		outLightsR = vertices_r;
		outLightsG = vertices_g;
		outLightsB = vertices_b;
#endif
        vertexIter = vertices;
        for (j = 0; j < numVertices; j++)
        {
            *outLights = *idkIter;
		#ifdef RGB_THING_LIGHTS
			if (outLightsR) *outLightsR = *idkIter;
			if (outLightsG) *outLightsG = *idkIter;
			if (outLightsB) *outLightsB = *idkIter;

#ifdef RGB_AMBIENT
			// unfortunately the ambient cube is in world space, so we need to
			// transform the normal to world rather than ambient to local
			rdVector3 worldNormal;
			rdMatrix_TransformVector34(&worldNormal, vertexNormals, mat);

			rdVector3 ambientColor;
			rdAmbient_CalculateVertexColor(ambient, &worldNormal, &ambientColor);
			
			if (outLightsR) *outLightsR += ambientColor.x;
			if (outLightsG) *outLightsG += ambientColor.y;
			if (outLightsB) *outLightsB += ambientColor.z;
#endif
		#endif
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
					{
						float intensity = (light->intensity - len * scalar) * lightMagnitude;
                        *outLights += intensity;
					#ifdef RGB_THING_LIGHTS
						if(outLightsR) *outLightsR += intensity * light->color.x;
						if(outLightsG) *outLightsG += intensity * light->color.y;
						if(outLightsB) *outLightsB += intensity * light->color.z;
					#endif
					}
                }
                if ( *outLights >= 1.0
			#ifdef RGB_THING_LIGHTS
				&&* outLightsR >= 1.0 && *outLightsR >= 1.0 && *outLightsB >= 1.0
			#endif
				)
                    break;
                ++meshLightIter;
            }

            ++vertexIter;
            ++outLights;
#ifdef RGB_THING_LIGHTS
			if (outLightsR) ++outLightsR;
			if (outLightsG) ++outLightsG;
			if (outLightsB) ++outLightsB;
#endif
            ++idkIter;
            ++vertexNormals;
        }
        return 0.0;
    }

    float fVar1;
    rdLight *light;
    float lightMagnitude;
    rdVector3 *vertexNormals;
    rdVector3 *lightDirIter;
    float fVar8;
    rdVector3 *vertexIter;
    float local_28;
    rdVector3 diff;
    rdLight** meshLightIter;
    float* outLights;
#ifdef RGB_THING_LIGHTS
	float* outLightsR;
	float* outLightsG;
	float* outLightsB;
#endif
    
    local_28 = 0.0;
    if (numVertices == 0) return 0.0;
    
    outLights = vertices_i;
#ifdef RGB_THING_LIGHTS
	outLightsR = vertices_r;
	outLightsG = vertices_g;
	outLightsB = vertices_b;
#endif
    vertexIter = vertices;
    vertexNormals = verticesEnd;
    for (int vertIdx = 0; vertIdx < numVertices; vertIdx++)
    {
        *outLights = *vertices_i_end;
#ifdef RGB_THING_LIGHTS
		if (vertices_r) *outLightsR = *vertices_i_end;
		if (vertices_g) *outLightsG = *vertices_i_end;
		if (vertices_b) *outLightsB = *vertices_i_end;

#ifdef RGB_AMBIENT
		rdVector3 worldNormal;
		rdMatrix_TransformVector34(&worldNormal, vertexNormals, mat);

		rdVector3 ambientColor;
		rdAmbient_CalculateVertexColor(ambient, &worldNormal, &ambientColor);

		if (outLightsR) *outLightsR += ambientColor.x;
		if (outLightsG) *outLightsG += ambientColor.y;
		if (outLightsB) *outLightsB += ambientColor.z;
#endif
#endif
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
						float intensity = (light->intensity - fVar8 * scalar) * lightMagnitude;
                        *outLights += intensity;
#ifdef RGB_THING_LIGHTS
						if (vertices_r) *outLightsR += intensity * light->color.x;
						if (vertices_g) *outLightsG += intensity * light->color.y;
						if (vertices_b) *outLightsB += intensity * light->color.z;
#endif
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
						float intensity = (fVar1 - fVar8 * scalar) * rdVector_Dot3(vertexNormals, lightDirIter);
                        *outLights += intensity;
#ifdef RGB_THING_LIGHTS
						if (vertices_r) *outLightsR += intensity * light->color.x;
						if (vertices_g) *outLightsG += intensity * light->color.y;
						if (vertices_b) *outLightsB += intensity * light->color.z;
#endif
                    }
                }
            }

#ifdef RGB_THING_LIGHTS
			if (*outLights > 1.0) *outLights = 1.0;
			if (*vertices_r > 1.0) *outLightsR = 1.0;
			if (*vertices_g > 1.0) *outLightsG = 1.0;
			if (*vertices_b > 1.0) *outLightsB = 1.0;
			if (*outLights == 1.0 && *outLightsR == 1.0 && *outLightsR == 1.0 && *outLightsB == 1.0) break;
#else
            if (*outLights > 1.0) {
                *outLights = 1.0;
            }
            if (*outLights == 1.0) break;
#endif
            meshLightIter++;
            verticesEnd++;
            lightDirIter++;
        }
    
        local_28 += *outLights;
        vertexNormals++;
        vertexIter++;
        outLights++;
#ifdef RGB_THING_LIGHTS
		if (vertices_r) ++outLightsR;
		if (vertices_g) ++outLightsG;
		if (vertices_b) ++outLightsB;
#endif
    } 
    return (double)(local_28 / (float)numVertices);
#endif
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

#ifdef RGB_AMBIENT
void rdAmbient_Zero(rdAmbient* ambient)
{
	memset(ambient, 0, sizeof(rdAmbient));
}

void rdAmbient_Acc(rdAmbient* ambient, rdVector3* color, rdVector3* dir)
{
	rdVector_Add3Acc(&ambient->colors[dir->x < 0.0f ? 1 : 0], color);
	rdVector_Add3Acc(&ambient->colors[dir->y < 0.0f ? 3 : 2], color);
	rdVector_Add3Acc(&ambient->colors[dir->z < 0.0f ? 5 : 4], color);
	//rdVector_MultAcc3(&ambient->colors[dir->x < 0.0f ? 1 : 0], color, dir->x * dir->x);
	//rdVector_MultAcc3(&ambient->colors[dir->y < 0.0f ? 3 : 2], color, dir->y * dir->y);
	//rdVector_MultAcc3(&ambient->colors[dir->z < 0.0f ? 5 : 4], color, dir->z * dir->z);
}

void rdAmbient_Scale(rdAmbient* ambient, float scale)
{
	for(int i = 0; i < 6; ++i)
		rdVector_Scale3Acc(&ambient->colors[i], scale);
}

void rdAmbient_Copy(rdAmbient* outAmbient, const rdAmbient* ambient)
{
	memcpy(outAmbient, ambient, sizeof(rdAmbient));
}

void rdAmbient_CalculateVertexColor(rdAmbient* ambient, rdVector3* normal, rdVector3* outColor)
{
	rdVector_Zero3(outColor);
	rdVector_MultAcc3(outColor, &ambient->colors[normal->x < 0.0f ? 1 : 0], normal->x * normal->x);
	rdVector_MultAcc3(outColor, &ambient->colors[normal->y < 0.0f ? 3 : 2], normal->y * normal->y);
	rdVector_MultAcc3(outColor, &ambient->colors[normal->z < 0.0f ? 5 : 4], normal->z * normal->z);
}
#endif