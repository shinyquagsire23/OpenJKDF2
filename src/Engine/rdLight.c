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

#ifdef SPECULAR_LIGHTING
float rdLight_Specular(const rdVector3* lightDir, const rdVector3* viewDir, const rdVector3* normal)
{
	rdVector3 h;
	rdVector_Add3(&h, lightDir, viewDir);
	rdVector_Normalize3Acc(&h);

	float brdf = stdMath_Clamp(rdVector_Dot3(&h, normal), 0.0f, 1.0f);
	brdf *= brdf; // x2
	brdf *= brdf; // x4
	brdf *= brdf; // x8
	return brdf;
}

float rdLight_Fresnel(const rdVector3* viewDir, const rdVector3* normal, float f0)
{
	//return f0 + (1.0f - f0) * powf(stdMath_Fabs(1.0f - rdVector_Dot3(normal, viewDir)), 5.0f);
	float fresnel = stdMath_Fabs(1.0f - rdVector_Dot3(normal, viewDir));
	fresnel *= fresnel;
	fresnel *= fresnel;
	return f0 + (1.0f - f0) * fresnel;
}
#endif

#ifdef HALF_LAMBERT
float rdLight_HalfLambert(float NdotL)
{
	NdotL = NdotL * 0.5f + 0.5f;
	return NdotL * NdotL;
}
#endif

double rdLight_CalcVertexIntensities(rdLight **meshLights, rdVector3 *localLightPoses, 
#ifdef JKM_LIGHTING
    rdVector3 *localLightDirs, 
#endif
    int numLights, rdVector3 *verticesEnd, rdVector3 *vertices, float *vertices_i_end, float *vertices_i,
#ifdef RGB_THING_LIGHTS
	float* vertices_r, float* vertices_g, float* vertices_b,
#endif
#ifdef RGB_AMBIENT
	rdAmbient* ambient,
 #endif
 #ifdef SPECULAR_LIGHTING
	rdVector3* localCamera,
	int bApplySpecular,
 #endif
	int numVertices, float scalar)
{
#ifdef SPECULAR_LIGHTING
	float c_d = 1.0f;
	float c_s = 0.0f;
	if (bApplySpecular)
	{
		c_d = 0.3f;
		c_s = 0.7f;
	}
#endif

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
#ifdef SPECULAR_LIGHTING
			rdVector3 localViewDir;
			if (bApplySpecular)
			{
				rdVector_Sub3(&localViewDir, localCamera, vertexIter);
				rdVector_Normalize3Acc(&localViewDir);
			}
#endif
            *outLights = *idkIter;
#ifdef RGB_THING_LIGHTS
			if (outLightsR) *outLightsR = *idkIter;
			if (outLightsG) *outLightsG = *idkIter;
			if (outLightsB) *outLightsB = *idkIter;

	#ifdef RGB_AMBIENT
			rdVector3 ambientColor;
			rdAmbient_CalculateVertexColor(ambient, vertexNormals, &ambientColor);

#ifdef SPECULAR_LIGHTING
			if (bApplySpecular)
				rdVector_Scale3Acc(&ambientColor, c_d);
#endif

			if (outLightsR) *outLightsR += ambientColor.x;
			if (outLightsG) *outLightsG += ambientColor.y;
			if (outLightsB) *outLightsB += ambientColor.z;
			
		#if defined(SPECULAR_LIGHTING) && !defined(RENDER_DROID2)
			if (bApplySpecular)
			{
				float brdf = rdLight_Specular(&ambient->dominantDir, &localViewDir, vertexNormals);
				// add some view based fresnel
				brdf += rdLight_Fresnel(&localViewDir, vertexNormals, 0.0f);
				brdf *= c_s;

				rdVector3 wi;
				rdVector_Neg3(&wi, &ambient->dominantDir);

				rdVector3 reflDir;
				rdVector_Reflect3(&reflDir, &wi, vertexNormals);
				rdAmbient_CalculateVertexColor(ambient, &reflDir, &ambientColor);

				if (outLightsR) *outLightsR += ambientColor.x * brdf;
				if (outLightsG) *outLightsG += ambientColor.y * brdf;
				if (outLightsB) *outLightsB += ambientColor.z * brdf;
			}
		#endif
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
				#ifdef HALF_LAMBERT
					lightMagnitude = rdLight_HalfLambert(lightMagnitude);
				#endif
                    if ( lightMagnitude > 0.0 )
					{
						float intensity = (light->intensity - len * scalar) * lightMagnitude;
						float diffuseIntensity = intensity;
#ifdef SPECULAR_LIGHTING
						diffuseIntensity *= c_d;
#endif
						*outLights += diffuseIntensity;
					#ifdef RGB_THING_LIGHTS
						if(outLightsR) *outLightsR += diffuseIntensity * light->color.x;
						if(outLightsG) *outLightsG += diffuseIntensity * light->color.y;
						if(outLightsB) *outLightsB += diffuseIntensity * light->color.z;
					#endif
					
				#ifdef SPECULAR_LIGHTING
						if (bApplySpecular)
						{
							intensity *= c_s * rdLight_Specular(&diff, &localViewDir, vertexNormals);
						}
                        *outLights += intensity;
					#ifdef RGB_THING_LIGHTS
						if (vertices_r) *outLightsR += intensity * light->color.x;
						if (vertices_g) *outLightsG += intensity * light->color.y;
						if (vertices_b) *outLightsB += intensity * light->color.z;
					#endif
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

#ifdef SPECULAR_LIGHTING
		rdVector3 localViewDir;
		if (bApplySpecular)
		{
			rdVector_Sub3(&localViewDir, localCamera, vertexIter);
			rdVector_Normalize3Acc(&localViewDir);
		}
#endif

#ifdef RGB_THING_LIGHTS
		if (vertices_r) *outLightsR = *vertices_i_end;
		if (vertices_g) *outLightsG = *vertices_i_end;
		if (vertices_b) *outLightsB = *vertices_i_end;

#ifdef RGB_AMBIENT
		rdVector3 ambientColor;
		rdAmbient_CalculateVertexColor(ambient, vertexNormals, &ambientColor);
#if defined(SPECULAR_LIGHTING) && !defined(RENDER_DROID2)
		if (bApplySpecular)
			rdVector_Scale3Acc(&ambientColor, c_d);
#endif

		if (outLightsR) *outLightsR += ambientColor.x;
		if (outLightsG) *outLightsG += ambientColor.y;
		if (outLightsB) *outLightsB += ambientColor.z;

	#if defined(SPECULAR_LIGHTING) && !defined(RENDER_DROID2)
		if (bApplySpecular)
		{
			float brdf = rdLight_Specular(&ambient->dominantDir, &localViewDir, vertexNormals);
			// add some view based fresnel
			brdf += rdLight_Fresnel(&localViewDir, vertexNormals, 0.0f);
			brdf *= c_s;

			rdVector3 wi;
			rdVector_Neg3(&wi, &ambient->dominantDir);

			rdVector3 reflDir;
			rdVector_Reflect3(&reflDir, &wi, vertexNormals);
			rdAmbient_CalculateVertexColor(ambient, &reflDir, &ambientColor);

			if (outLightsR) *outLightsR += ambientColor.x * brdf;
			if (outLightsG) *outLightsG += ambientColor.y * brdf;
			if (outLightsB) *outLightsB += ambientColor.z * brdf;
		}
	#endif
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
#ifdef HALF_LAMBERT
					lightMagnitude = rdLight_HalfLambert(lightMagnitude);
#endif
					if (lightMagnitude > 0.0) 
                    {
						float intensity = (light->intensity - fVar8 * scalar) * lightMagnitude;
						float diffuseIntensity = intensity;
					#ifdef SPECULAR_LIGHTING
						diffuseIntensity *= c_d;
					#endif
                        *outLights += diffuseIntensity;
					#ifdef RGB_THING_LIGHTS
						if (vertices_r) *outLightsR += diffuseIntensity * light->color.x;
						if (vertices_g) *outLightsG += diffuseIntensity * light->color.y;
						if (vertices_b) *outLightsB += diffuseIntensity * light->color.z;
					#endif

				#ifdef SPECULAR_LIGHTING
						if (bApplySpecular)
						{
							intensity *= c_s * rdLight_Specular(&diff, &localViewDir, vertexNormals);
							*outLights += intensity;
						#ifdef RGB_THING_LIGHTS
							if (vertices_r) *outLightsR += intensity * light->color.x;
							if (vertices_g) *outLightsG += intensity * light->color.y;
							if (vertices_b) *outLightsB += intensity * light->color.z;
						#endif
					}
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
						float diffuseIntensity = intensity;
#ifdef SPECULAR_LIGHTING
						diffuseIntensity *= c_d;
#endif
                        *outLights += diffuseIntensity;
#ifdef RGB_THING_LIGHTS
						if (vertices_r) *outLightsR += diffuseIntensity * light->color.x;
						if (vertices_g) *outLightsG += diffuseIntensity * light->color.y;
						if (vertices_b) *outLightsB += diffuseIntensity * light->color.z;
#endif

#ifdef SPECULAR_LIGHTING
						if (bApplySpecular)
						{
							intensity *= c_s * rdLight_Specular(&diff, &localViewDir, vertexNormals);
							*outLights += intensity;
#ifdef RGB_THING_LIGHTS
							if (vertices_r) *outLightsR += intensity * light->color.x;
							if (vertices_g) *outLightsG += intensity * light->color.y;
							if (vertices_b) *outLightsB += intensity * light->color.z;
#endif
						}
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

// pre-baked spherical gaussian axis and sharpness
rdVector4 rdLight_sgBasis[8] =
{
	{ 0.752576709,  0.000000000, -0.658504605, 4.93992233},
	{-0.625373423,  0.572653592, -0.530071616, 4.93992233},
	{ 0.0818622485,-0.932739854, -0.351133764, 4.93992233},
	{ 0.603548527,  0.787615955, -0.124057360, 4.93992233},
	{-0.977106333, -0.172848180,  0.124042749, 4.93992233},
	{ 0.790152431, -0.502328515,  0.351176947, 4.93992233},
	{-0.220158905,  0.818896949,  0.530035675, 4.93992233},
	{-0.346642911, -0.667932153,  0.658563018, 4.93992233}
};

int rdLight_basisInit = 0;

void rdLight_InitSGBasis()
{
/*	if (rdLight_basisInit)
		return;

	uint32_t N = 8;

	rdVector3 means[8];
	float inc = M_PI * (3.0f - stdMath_Sqrt(5.0f));
	float off = 2.0f / N;
	for (uint32_t k = 0; k < N; ++k)
	{
		float y = k * off - 1.0f + (off / 2.0f);
		float r = stdMath_Sqrt(1.0f - y * y);
		float phi = k * inc;
		stdMath_SinCos(phi * 180.0f / M_PI, &means[k].y, &means[k].x);
		means[k].z = y;
	}

	for (uint32_t i = 0; i < N; ++i)
		rdVector_Normalize3((rdVector3*)&rdLight_sgBasis[i], &means[i]);

	float minDP = 1.0f;
	for (uint32_t i = 1; i < N; ++i)
	{
		rdVector3 h;
		rdVector_Add3(&h, (rdVector3*)&rdLight_sgBasis[i], (rdVector3*)&rdLight_sgBasis[0]);
		rdVector_Normalize3Acc(&h);
		minDP = fmin(minDP, rdVector_Dot3(&h, (rdVector3*)&rdLight_sgBasis[0]));
	}

	float sharpness = (logf(0.65f) * N) / (minDP - 1.0001f);
	for (uint32_t i = 0; i < N; ++i)
		rdLight_sgBasis[i].w = sharpness;*/
}

void rdAmbient_Zero(rdAmbient* ambient)
{
	memset(ambient, 0, sizeof(rdAmbient));
}

int rdAmbient_Compare(const rdAmbient* a, const rdAmbient* b)
{
	return memcmp(a, b, sizeof(rdAmbient));
}

void rdAmbient_Acc(rdAmbient* ambient, rdVector3* color, rdVector3* dir)
{
#ifndef RENDER_DROID2
	static const float c = 0.282094792;
	static const float k = 0.488602512;
	//static const float c = 0.886227;
	//static const float k = 1.02333;
	
	rdVector4 shR, shG, shB;
	shR.x = shG.x = shB.x = c;
	shR.y = shG.y = shB.y = -k * dir->y;
	shR.z = shG.z = shB.z =  k * dir->z;
	shR.w = shG.w = shB.w = -k * dir->x;

	rdVector_Scale4Acc(&shR, color->x);
	rdVector_Scale4Acc(&shG, color->y);
	rdVector_Scale4Acc(&shB, color->z);

	rdVector_Add4Acc(&ambient->r, &shR);
	rdVector_Add4Acc(&ambient->g, &shG);
	rdVector_Add4Acc(&ambient->b, &shB);
#else
	rdLight_InitSGBasis();
	for (uint32_t sg = 0; sg < 8; ++sg)
	{
		rdVector4 sg1 = rdLight_sgBasis[sg];
		rdVector4 sg2;
		rdVector_Set4(&sg2, dir->x, dir->y, dir->z, 0.0f);
		if (rdVector_Dot3((rdVector3*)dir, (rdVector3*)&sg1) > 0.0f)
		{
			float dp = rdVector_Dot3((rdVector3*)&sg1, (rdVector3*)&sg2);
			float factor = (dp - 1.0f) * sg1.w;
			float wgt = exp(factor);
			rdVector_MultAcc3(&ambient->sgs[sg], color, wgt);
		}
	}
#endif
}

void rdAmbient_Scale(rdAmbient* ambient, float scale)
{
#ifndef RENDER_DROID2
	rdVector_Scale4Acc(&ambient->r, scale);
	rdVector_Scale4Acc(&ambient->g, scale);
	rdVector_Scale4Acc(&ambient->b, scale);
#else
	for(int i = 0; i < 8; ++i)
		rdVector_Scale3Acc(&ambient->sgs[i], scale);
#endif
}

void rdAmbient_Copy(rdAmbient* outAmbient, const rdAmbient* ambient)
{
	memcpy(outAmbient, ambient, sizeof(rdAmbient));
}

void rdAmbient_CalculateVertexColor(rdAmbient* ambient, rdVector3* normal, rdVector3* outColor)
{
	rdVector_Zero3(outColor);

#ifndef RENDER_DROID2
	static const float c = 0.282094792;
	static const float k = 0.488602512;

	rdVector4 shN;
	shN.x =  c;
	shN.y = -k * normal->y;
	shN.z =  k * normal->z;
	shN.w = -k * normal->x;

	outColor->x = fmax(0.0f, rdVector_Dot4(&shN, &ambient->r)) / M_PI;
	outColor->y = fmax(0.0f, rdVector_Dot4(&shN, &ambient->g)) / M_PI;
	outColor->z = fmax(0.0f, rdVector_Dot4(&shN, &ambient->b)) / M_PI;
#else
	rdLight_InitSGBasis();
	// todo?
#endif
}

void rdAmbient_UpdateDominantDirection(rdAmbient* ambient)
{
#ifndef RENDER_DROID2
	ambient->dominantDir.x = ambient->r.y * 0.33f + ambient->g.y * 0.59f + ambient->b.y * 0.11f;
	ambient->dominantDir.y = ambient->r.z * 0.33f + ambient->g.z * 0.59f + ambient->b.z * 0.11f;
	ambient->dominantDir.z = ambient->r.w * 0.33f + ambient->g.w * 0.59f + ambient->b.w * 0.11f;
	rdVector_Set3(&ambient->dominantDir, -ambient->dominantDir.z, -ambient->dominantDir.x, ambient->dominantDir.y);
	rdVector_Normalize3Acc(&ambient->dominantDir);
#endif
}

#endif