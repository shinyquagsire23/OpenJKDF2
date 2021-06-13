#include "sithRender.h"

#include <math.h>
#include <float.h>

#include "Cog/sithCog.h"
#include "Engine/sith.h"
#include "Engine/sithMaterial.h"
#include "Engine/sithModel.h"
#include "Engine/sithKeyFrame.h"
#include "Engine/rdMaterial.h"
#include "Engine/rdKeyframe.h"
#include "Engine/rdColormap.h"
#include "Engine/rdroid.h"
#include "Engine/sithTime.h"
#include "Engine/sithCamera.h"
#include "Engine/sithAdjoin.h"
#include "Engine/rdCache.h"
#include "Engine/rdClip.h"
#include "Engine/rdCamera.h"
#include "General/stdMath.h"
#include "Primitives/rdFace.h"
#include "Primitives/rdModel3.h"
#include "Primitives/rdPrimit3.h"
#include "World/jkPlayer.h"
#include "World/sithPlayer.h"
#include "World/sithSector.h"
#include "World/sithWorld.h"
#include "Win95/std3D.h"

int sithRender_Startup()
{
    rdMaterial_RegisterLoader(sithMaterial_LoadEntry);
    rdModel3_RegisterLoader(sithModel_LoadEntry);
    rdKeyframe_RegisterLoader(sithKeyFrame_LoadEntry);
    sithRender_flag = 0;
    sithRender_weaponRenderHandle = 0;

    return 1;
}

int sithRender_Open()
{
    sithRender_geoMode = 4;
    sithRender_lightMode = 3;
    sithRender_texMode = 1;

    for (int i = 0; i < SITHREND_NUM_LIGHTS; i++)
    {
        rdLight_NewEntry(&sithRender_aLights[i]);
    }

    rdColormap_SetCurrent(sithWorld_pCurWorld->colormaps);
    rdColormap_SetIdentity(sithWorld_pCurWorld->colormaps);

    sithSector_SetSkyParams(sithWorld_pCurWorld->horizontalPixelsPerRev, sithWorld_pCurWorld->horizontalDistance, sithWorld_pCurWorld->ceilingSky);

    sithRender_lightingIRMode = 0; 
    sithRender_needsAspectReset = 0;
    return 1;
}

void sithRender_Close()
{
    sithSector_Close();
}

void sithRender_Shutdown()
{
    ;
}

void sithRender_SetSomeRenderflag(int flag)
{
    sithRender_flag = flag;
}

int sithRender_GetSomeRenderFlag()
{
    return sithRender_flag;
}

void sithRender_EnableIRMode(float a, float b)
{
    sithRender_lightingIRMode = 1;
    if ( a < 0.0 )
    {
        sithRender_f_83198C = 0.0;
    }
    else if ( a > 1.0 )
    {
        sithRender_f_83198C = 1.0;
    }
    else
    {
        sithRender_f_83198C = a;
    }
    if ( b < 0.0 )
    {
        sithRender_f_831990 = 0.0;
    }
    else if ( b > 1.0 )
    {
        sithRender_f_831990 = 1.0;
    }
    else
    {
        sithRender_f_831990 = b;
    }
}

void sithRender_DisableIRMode()
{
    sithRender_lightingIRMode = 0;
}

void sithRender_SetGeoMode(int val)
{
    sithRender_geoMode = val;
}

void sithRender_SetLightMode(int a1)
{
    sithRender_lightMode = a1;
}

void sithRender_SetTexMode(int a1)
{
    sithRender_texMode = a1;
}

void sithRender_SetPalette(const void *palette)
{
    rdColormap_SetCurrent(sithWorld_pCurWorld->colormaps);
    rdColormap_SetIdentity(sithWorld_pCurWorld->colormaps);
    if ( rdroid_curAcceleration > 0 )
    {
        sithMaterial_UnloadAll();
        std3D_UnloadAllTextures();
        std3D_SetCurrentPalette((rdColor24 *)palette, 90);
    }
}

void sithRender_Draw()
{
    sithSector **v1; // ebx
    sithSector *v2; // edi
    sithAdjoin *i; // esi
    sithSector *v4; // eax
    float a2; // [esp+0h] [ebp-28h]
    float v7; // [esp+8h] [ebp-20h]
    float v9; // [esp+8h] [ebp-20h]
    float a3; // [esp+1Ch] [ebp-Ch] BYREF
    unsigned int v11; // [esp+20h] [ebp-8h]
    float a4; // [esp+24h] [ebp-4h] BYREF

    //printf("%x %x %x\n", sithRender_texMode, rdroid_curTextureMode, sithRender_lightMode);

    sithSector_UpdateSky();
    if ( sithRender_geoMode )
    {
        rdSetGeometryMode(sithRender_geoMode);
        if ( sithRender_lightingIRMode )
            rdSetLightingMode(2);
        else
            rdSetLightingMode(sithRender_lightMode);
        rdSetTextureMode(sithRender_texMode);
        rdSetRenderOptions(rdGetRenderOptions() | 2);

        sithPlayer_SetScreenTint(sithCamera_currentCamera->sector->tint.x, sithCamera_currentCamera->sector->tint.y, sithCamera_currentCamera->sector->tint.z);

        if ( (sithCamera_currentCamera->sector->flags & 2) != 0 )
        {
            float fov = sithCamera_currentCamera->fov;
            float aspect = sithCamera_currentCamera->aspectRatio;

#ifdef QOL_IMPROVEMENTS
            fov = jkPlayer_fov;
            aspect = sith_lastAspect;
#endif
            stdMath_SinCos(sithTime_curSeconds * 70.0, &a3, &a4);
            rdCamera_SetFOV(&sithCamera_currentCamera->rdCam, a3 + fov);
            stdMath_SinCos(sithTime_curSeconds * 100.0, &a3, &a4);
            rdCamera_SetAspectRatio(&sithCamera_currentCamera->rdCam, a3 * 0.016666668 + aspect);
            sithRender_needsAspectReset = 1;
        }
        else if ( sithRender_needsAspectReset )
        {
            rdCamera_SetFOV(&sithCamera_currentCamera->rdCam, sithCamera_currentCamera->fov);
            rdCamera_SetAspectRatio(&sithCamera_currentCamera->rdCam, sithCamera_currentCamera->aspectRatio);
            sithRender_needsAspectReset = 0;
        }
        rdSetSortingMethod(0);
        rdSetMipDistances(&sithWorld_pCurWorld->mipmapDistance);
        rdSetCullFlags(1);
        sithRender_numSectors = 0;
        sithRender_numSectors2 = 0;
        sithRender_numLights = 0;
        sithRender_numClipFrustums = 0;
        sithRender_numSurfaces = 0;
        sithRender_82F4B4 = 0;
        sithRender_surfacesDrawn = 0;
        sithRender_831984 = 0;
        sithRender_831980 = 0;
        rdCamera_ClearLights(rdCamera_pCurCamera);
        sithRender_Clip(sithCamera_currentCamera->sector, rdCamera_pCurCamera->cameraClipFrustum, 0.0);
        v11 = 0;
        if ( sithRender_numSectors )
        {
            v1 = sithRender_aSectors;
            do
            {
                v2 = *v1;
                for ( i = (*v1)->adjoins; i; i = i->next )
                {
                    v4 = i->sector;
                    if ( v4->field_8C != sithRender_8EE678 && (i->flags & 1) != 0 )
                    {
                        v9 = i->dist;
                        v4->clipFrustum = v2->clipFrustum;
                        sithRender_UpdateLights(v4, 0.0, v9);
                    }
                }
                ++v1;
                ++v11;
            }
            while ( v11 < sithRender_numSectors );
        }
        if ( (sithRender_flag & 2) != 0 )
            sithRender_RenderDynamicLights();
        sithRender_RenderLevelGeometry();
        if ( sithRender_numSectors2 )
            sithRender_RenderThings();
        if ( sithRender_numSurfaces )
            sithRender_RenderAlphaSurfaces();
        rdSetCullFlags(3);
    }
}

void sithRender_Clip(sithSector *sector, rdClipFrustum *frustumArg, float a3)
{
    //sithRender_Clip_(sector, frustumArg, a3);
    //return;    
    
    int v5; // ecx
    rdClipFrustum *frustum; // edx
    sithThing *thing; // esi
    unsigned int lightIdx; // ecx
    sithAdjoin *adjoinIter; // ebx
    sithSurface *adjoinSurface; // esi
    rdMaterial *adjoinMat; // eax
    rdVector3 *v20; // eax
    int v25; // eax
    unsigned int v27; // edi
    rdClipFrustum *v31; // ecx
    rdClipFrustum outClip; // [esp+Ch] [ebp-74h] BYREF
    rdVector3 vertex_out; // [esp+40h] [ebp-40h] BYREF
    int v45; // [esp+4Ch] [ebp-34h]
    rdTexinfo *v51; // [esp+64h] [ebp-1Ch]

    if ( sector->field_8C == sithRender_8EE678 )
    {
        sector->clipFrustum = rdCamera_pCurCamera->cameraClipFrustum;
    }
    else
    {
        sector->field_8C = sithRender_8EE678;
        if (sithRender_numSectors >= 0x80)
            return;

        sithRender_aSectors[sithRender_numSectors++] = sector;
        if ( (sector->flags & SITH_SF_AUTOMAPVISIBLE) == 0 )
        {
            sector->flags |= SITH_SF_AUTOMAPVISIBLE;
            if ( (sector->flags & SITH_SF_COGLINKED) != 0 )
                sithCog_SendMessageFromSector(sector, 0, SITH_MESSAGE_SIGHTED);
        }
        frustum = &sithRender_clipFrustums[sithRender_numClipFrustums++];
        _memcpy(frustum, frustumArg, sizeof(rdClipFrustum));
        thing = sector->thingsList;
        sector->clipFrustum = frustum;
        lightIdx = sithRender_numLights;
        while ( thing )
        {
            if ( lightIdx >= 0x20 )
                break;

            if ((thing->thingflags & SITH_TF_LIGHT)
                 && !(thing->thingflags & (SITH_TF_DISABLED|SITH_TF_10|SITH_TF_WILLBEREMOVED)))
            {
                if ( thing->light > 0.0 )
                {
                    sithRender_aLights[lightIdx].intensity = thing->light;
                    rdCamera_AddLight(rdCamera_pCurCamera, &sithRender_aLights[lightIdx], &thing->position);
                    lightIdx = ++sithRender_numLights;
                }

                if ( (thing->thingType == THINGTYPE_ACTOR || thing->thingType == THINGTYPE_PLAYER) && lightIdx < 0x20 )
                {
                    if ( (thing->actorParams.typeflags & THING_TYPEFLAGS_DAMAGE) != 0 && thing->actorParams.lightIntensity > 0.0 )
                    {
                        rdMatrix_TransformPoint34(&vertex_out, &thing->actorParams.lightOffset, &thing->lookOrientation);
                        vertex_out.x = thing->position.x + vertex_out.x;
                        vertex_out.y = thing->position.y + vertex_out.y;
                        vertex_out.z = thing->position.z + vertex_out.z;
                        sithRender_aLights[sithRender_numLights].intensity = thing->actorParams.lightIntensity;
                        rdCamera_AddLight(rdCamera_pCurCamera, &sithRender_aLights[sithRender_numLights], &vertex_out);
                        lightIdx = ++sithRender_numLights;
                    }
                    if ( thing->actorParams.timeLeftLengthChange > 0.0 )
                    {
                        sithRender_aLights[lightIdx].intensity = thing->actorParams.timeLeftLengthChange;
                        rdCamera_AddLight(rdCamera_pCurCamera, &sithRender_aLights[lightIdx], &thing->actorParams.saberBladePos);
                        lightIdx = ++sithRender_numLights;
                    }
                }
            }
            thing = thing->nextThing;
        }
        sithRender_aSectors2[sithRender_numSectors2++] = sector;
    }

    adjoinIter = sector->adjoins;
    v45 = sector->field_90;
    sithRender_idxInfo.vertices = sithWorld_pCurWorld->verticesTransformed;
    sithRender_idxInfo.extraUV = sithWorld_pCurWorld->vertexUVs;
    sector->field_90 = 1;
    sithRender_idxInfo.field_14 = sithWorld_pCurWorld->alloc_unk94;
    while ( adjoinIter )
    {
        if (adjoinIter->sector->field_90 )
        {
            adjoinIter = adjoinIter->next;
            continue;
        }

        adjoinSurface = adjoinIter->surface;
        adjoinMat = adjoinSurface->surfaceInfo.face.material;
        if ( adjoinMat )
        {
            int v19 = adjoinSurface->surfaceInfo.face.wallCel;
            if ( v19 == -1 )
                v19 = adjoinMat->celIdx;
            v51 = adjoinMat->texinfos[v19];
        }
        v20 = &sithWorld_pCurWorld->vertices[*adjoinSurface->surfaceInfo.face.vertexPosIdx];
        float dist = (sithCamera_currentCamera->vec3_1.y - v20->y) * adjoinSurface->surfaceInfo.face.normal.y
                   + (sithCamera_currentCamera->vec3_1.z - v20->z) * adjoinSurface->surfaceInfo.face.normal.z
                   + (sithCamera_currentCamera->vec3_1.x - v20->x) * adjoinSurface->surfaceInfo.face.normal.x;
        if ( dist > 0.0 || (dist == 0.0 && sector == sithCamera_currentCamera->sector))
        {
            if ( adjoinSurface->field_4 != sithRender_8EE678 )
            {
                for (int i = 0; i < adjoinSurface->surfaceInfo.face.numVertices; i++)
                {
                    v25 = adjoinSurface->surfaceInfo.face.vertexPosIdx[i];
                    if ( sithWorld_pCurWorld->alloc_unk98[v25] != sithRender_8EE678 )
                    {
                        rdMatrix_TransformPoint34(&sithWorld_pCurWorld->verticesTransformed[v25], &sithWorld_pCurWorld->vertices[v25], &rdCamera_pCurCamera->view_matrix);
                        sithWorld_pCurWorld->alloc_unk98[v25] = sithRender_8EE678;
                    }
                }
                adjoinSurface->field_4 = sithRender_8EE678;
            }
            sithRender_idxInfo.numVertices = adjoinSurface->surfaceInfo.face.numVertices;
            sithRender_idxInfo.vertexPosIdx = adjoinSurface->surfaceInfo.face.vertexPosIdx;
            meshinfo_out.verticesProjected = vertices_tmp;
            sithRender_idxInfo.vertexUVIdx = adjoinSurface->surfaceInfo.face.vertexUVIdx;

            rdPrimit3_ClipFace(frustumArg, 2, 1, 0, &sithRender_idxInfo, &meshinfo_out, &adjoinSurface->surfaceInfo.face.clipIdk);

            if ( ((unsigned int)meshinfo_out.numVertices >= 3u || (rdClip_faceStatus & 0x40) != 0)
              && ((rdClip_faceStatus & 0x41) != 0
               || (adjoinIter->flags & 1) != 0
               && (!adjoinSurface->surfaceInfo.face.material
                || !adjoinSurface->surfaceInfo.face.geometryMode
                || (adjoinSurface->surfaceInfo.face.type & 2) != 0
                || (v51->header.texture_type & 8) != 0 && (v51->texture_ptr->alpha_en & 1) != 0)) )
            {
                rdCamera_pCurCamera->projectLst(vertices_tmp_projected, vertices_tmp, meshinfo_out.numVertices);
                
                // no frustum culling
                if ((rdClip_faceStatus & 0x41) != 0 )
                {
                    v31 = frustumArg;
                }
                else
                {
                    float minX = FLT_MAX;
                    float minY = FLT_MAX;
                    float maxX = -FLT_MAX;
                    float maxY = -FLT_MAX;
                    for (int i = 0; i < meshinfo_out.numVertices; i++)
                    {
                        float v34 = vertices_tmp_projected[i].x;
                        float v57 = vertices_tmp_projected[i].y;
                        if (v34 < minX)
                            minX = v34;
                        if (v34 > maxX)
                            maxX = v34;

                        if (v57 < minY)
                            minY = v57;
                        if (v57 > maxY)
                            maxY = v57;
                    }

                    float v49 = ceilf(maxY);
                    float v48 = ceilf(maxX);
                    float v47 = ceilf(minY);
                    float v46 = ceilf(minX);

                    rdCamera_BuildClipFrustum(rdCamera_pCurCamera, &outClip, (int)(v46 - -0.5), (int)(v47 - -0.5), (int)v48, (int)v49);
                    v31 = &outClip;
                }
                
                float a3a = adjoinIter->dist + adjoinIter->mirror->dist + a3;
                if (!(sithRender_flag & 4) || a3a < sithRender_f_82F4B0 ) // wtf is with this float?
                    sithRender_Clip(adjoinIter->sector, v31, a3a);
            }
        }
        adjoinIter = adjoinIter->next;
    }
    sector->field_90 = v45;
}

void sithRender_RenderLevelGeometry()
{
    rdVector2 *vertices_uvs; // edx
    sithWorld *level; // edx
    rdVector3 *vertices_alloc; // esi
    rdTexinfo *v10; // ecx
    int v18; // ebx
    int v19; // ebp
    rdProcEntry *v20; // esi
    int v21; // eax
    int v22; // eax
    int v23; // ecx
    int v24; // eax
    float *v25; // ecx
    int v26; // eax
    signed int v27; // edx
    unsigned int v28; // ebp
    float v29; // ecx
    int v30; // eax
    float *v31; // eax
    unsigned int v32; // ecx
    float *v33; // edx
    double v34; // st7
    float v35; // eax
    int v36; // edx
    rdMaterial *v37; // ecx
    int v38; // ecx
    char v39; // al
    rdProcEntry *procEntry; // esi
    int v41; // eax
    int v42; // eax
    int v43; // ecx
    int v44; // eax
    rdVector2 *v45; // ecx
    rdClipFrustum *v46; // edx
    signed int v47; // eax
    unsigned int num_vertices; // ebp
    float v49; // edx
    int v50; // eax
    float *v51; // eax
    unsigned int v52; // ecx
    float *v53; // edx
    double v54; // st7
    int surfaceFlags; // eax
    float v56; // eax
    int v57; // edx
    rdMaterial *v58; // ecx
    int v59; // ecx
    char rend_flags; // al
    unsigned int v61; // esi
    sithThing *i; // esi
    int v63; // eax
    int v64; // [esp-10h] [ebp-74h]
    sithSurface *v65; // [esp+10h] [ebp-54h]
    float v66; // [esp+14h] [ebp-50h]
    float v67; // [esp+14h] [ebp-50h]
    BOOL v68; // [esp+18h] [ebp-4Ch]
    sithSector *level_idk; // [esp+1Ch] [ebp-48h]
    float a2; // [esp+20h] [ebp-44h]
    int v71; // [esp+24h] [ebp-40h]
    int v72; // [esp+28h] [ebp-3Ch]
    rdTexinfo *v73; // [esp+2Ch] [ebp-38h]
    int v74; // [esp+30h] [ebp-34h]
    int v75; // [esp+34h] [ebp-30h]
    signed int v76; // [esp+38h] [ebp-2Ch]
    rdClipFrustum *v77; // [esp+3Ch] [ebp-28h]
    int v78[3]; // [esp+40h] [ebp-24h] BYREF
    int v79[3]; // [esp+4Ch] [ebp-18h] BYREF
    float v80[3]; // [esp+58h] [ebp-Ch] BYREF

    if ( rdroid_curAcceleration )
    {
        rdSetZBufferMethod(2);
    }
    else
    {
        rdSetZBufferMethod(1);
        if ( (sithRender_flag & 0x20) != 0 )
            rdSetOcclusionMethod(0);
        else
            rdSetOcclusionMethod(1);
    }
    rdSetSortingMethod(0);
    v72 = 0;
    vertices_uvs = sithWorld_pCurWorld->vertexUVs;
    sithRender_idxInfo.vertices = sithWorld_pCurWorld->verticesTransformed;
    sithRender_idxInfo.field_14 = sithWorld_pCurWorld->alloc_unk94;
    sithRender_idxInfo.extraUV = vertices_uvs;
    v77 = rdCamera_pCurCamera->cameraClipFrustum;

    if ( sithRender_numSectors )
    {
        while ( 1 )
        {
            level_idk = sithRender_aSectors[v72];
            if ( sithRender_lightingIRMode )
            {
                a2 = sithRender_f_83198C;
                rdCamera_SetAmbientLight(rdCamera_pCurCamera, sithRender_f_83198C);
            }
            else
            {
                float baseLight = level_idk->ambientLight + level_idk->extraLight;
                if ( baseLight < 0.0 )
                {
                    a2 = 0.0;
                    rdCamera_SetAmbientLight(rdCamera_pCurCamera, 0.0);
                }
                else if ( baseLight > 1.0 )
                {
                    a2 = 1.0;
                    rdCamera_SetAmbientLight(rdCamera_pCurCamera, 1.0);
                }
                else
                {
                    a2 = baseLight;
                    rdCamera_SetAmbientLight(rdCamera_pCurCamera, a2);
                }
            }
            rdColormap_SetCurrent(level_idk->colormap);
            v68 = level_idk->colormap == sithWorld_pCurWorld->colormaps;
            rdSetProcFaceUserData(level_idk->id);
            v65 = level_idk->surfaces;
            v75 = 0;
            if ( level_idk->numSurfaces )
                break;
LABEL_151:
            rdSetProcFaceUserData(level_idk->id | 0x10000);
            for ( i = level_idk->thingsList; i; i = i->nextThing )
            {
                if ( (i->thingflags & SITH_TF_LEVELGEO) != 0
                  && (i->thingflags & (SITH_TF_DISABLED|SITH_TF_10|SITH_TF_WILLBEREMOVED)) == 0
                  && ((sithCamera_currentCamera->cameraPerspective & 0xFC) != 0 || i != sithCamera_currentCamera->primaryFocus)
                  && i->rdthing.type == RD_THINGTYPE_MODEL )
                {
                    rdMatrix_TransformPoint34(&i->screenPos, &i->position, &rdCamera_pCurCamera->view_matrix);
                    v63 = rdClip_SphereInFrustrum(level_idk->clipFrustum, &i->screenPos, i->rdthing.model3->radius);
                    i->rdthing.clippingIdk = v63;
                    if ( v63 != 2 )
                    {
                        if ( a2 >= 1.0 )
                            i->rdthing.lightMode = 0;
                        if ( sithRender_RenderPov(i) )
                            ++sithRender_831980;
                    }
                }
            }
            ++sithRender_surfacesDrawn;
            if ( ++v72 >= sithRender_numSectors )
                goto LABEL_164;
        }
        level = sithWorld_pCurWorld;
        while ( 1 )
        {
            if ( !v65->surfaceInfo.face.geometryMode )
                goto LABEL_150;
            vertices_alloc = level->vertices;
            if ( (sithCamera_currentCamera->vec3_1.z - vertices_alloc[*v65->surfaceInfo.face.vertexPosIdx].z) * v65->surfaceInfo.face.normal.z
               + (sithCamera_currentCamera->vec3_1.y - vertices_alloc[*v65->surfaceInfo.face.vertexPosIdx].y) * v65->surfaceInfo.face.normal.y
               + (sithCamera_currentCamera->vec3_1.x - vertices_alloc[*v65->surfaceInfo.face.vertexPosIdx].x) * v65->surfaceInfo.face.normal.x <= 0.0 )
                goto LABEL_150;
            rdMaterial* surfaceMat = v65->surfaceInfo.face.material;
            if ( surfaceMat )
            {
                if ( v65->surfaceInfo.face.wallCel == -1 )
                    v10 = surfaceMat->texinfos[surfaceMat->celIdx];
                else
                    v10 = surfaceMat->texinfos[v65->surfaceInfo.face.wallCel];
                v73 = v10;
            }
            else
            {
                v10 = v73;
            }

            if ( v65->adjoin && surfaceMat && ((v65->surfaceInfo.face.type & 2) != 0 || (v10->header.texture_type & 8) != 0 && (v10->texture_ptr->alpha_en & 1) != 0) )
            {
                if (sithRender_numSurfaces < 32)
                {
                    sithRender_aSurfaces[sithRender_numSurfaces++] = v65;
                }
                goto LABEL_150;
            }
            if ( v65->field_4 != sithRender_8EE678 )
            {
                for (int j = 0; j < v65->surfaceInfo.face.numVertices; j++)
                {
                    int idx = v65->surfaceInfo.face.vertexPosIdx[j];
                    if ( level->alloc_unk98[idx] != sithRender_8EE678 )
                    {
                        rdMatrix_TransformPoint34(&level->verticesTransformed[idx], &level->vertices[idx], &rdCamera_pCurCamera->view_matrix);
                        level = sithWorld_pCurWorld;
                        level->alloc_unk98[idx] = sithRender_8EE678;
                    }
                }
                v65->field_4 = sithRender_8EE678;
            }
            if ( (sithRender_flag & 8) == 0 )
                break;

            if ( v65->surfaceInfo.face.numVertices <= 3 || (v65->surfaceFlags & (SURFACEFLAGS_400|SURFACEFLAGS_200)) != 0 || !v65->surfaceInfo.face.lightingMode )
                break;
            v74 = 0;
            v76 = v65->surfaceInfo.face.numVertices - 2;
            if (v76 > 0)
            {
                v18 = v65->surfaceInfo.face.numVertices - 1;
                v71 = 1;
                v19 = 0;
                while ( 2 )
                {
                    v20 = rdCache_GetProcEntry();
                    if ( !v20 )
                        goto LABEL_92;
                    v21 = v65->surfaceInfo.face.geometryMode;
                    if ( v21 >= sithRender_geoMode )
                        v21 = sithRender_geoMode;
                    v20->geometryMode = v21;
                    v22 = v65->surfaceInfo.face.lightingMode;
                    if ( sithRender_lightingIRMode )
                    {
                        if ( v22 >= 2 )
                            v22 = 2;
                    }
                    else if ( v22 >= sithRender_lightMode )
                    {
                        v22 = sithRender_lightMode;
                    }
                    v23 = sithRender_texMode;
                    v20->lightingMode = v22;
                    v24 = v65->surfaceInfo.face.textureMode;
                    if ( v24 >= v23 )
                        v24 = v23;
                    v20->textureMode = v24;
                    v78[0] = v65->surfaceInfo.face.vertexPosIdx[v19];
                    v78[1] = v65->surfaceInfo.face.vertexPosIdx[v71];
                    v78[2] = v65->surfaceInfo.face.vertexPosIdx[v18];
                    if ( v20->geometryMode >= 4 )
                    {
                        v79[0] = v65->surfaceInfo.face.vertexUVIdx[v19];
                        v79[1] = v65->surfaceInfo.face.vertexUVIdx[v71];
                        v79[2] = v65->surfaceInfo.face.vertexUVIdx[v18];
                    }
                    meshinfo_out.verticesProjected = vertices_tmp;
                    sithRender_idxInfo.numVertices = 3;
                    v80[0] = v65->surfaceInfo.field_40[v19];
                    v80[1] = v65->surfaceInfo.field_40[v71];
                    v80[2] = v65->surfaceInfo.field_40[v18];
                    v25 = v20->vertexIntensities;
                    meshinfo_out.vertexUVs = v20->vertexUVs;
                    sithRender_idxInfo.vertexPosIdx = v78;
                    meshinfo_out.vertex_lights_maybe_ = v25;
                    sithRender_idxInfo.vertexUVIdx = v79;
                    v26 = v20->textureMode;
                    v27 = v20->geometryMode;
                    sithRender_idxInfo.field_18 = v80;
                    rdPrimit3_ClipFace(level_idk->clipFrustum, v27, v20->lightingMode, v26, &sithRender_idxInfo, &meshinfo_out, &v65->surfaceInfo.face.clipIdk);
                    v28 = meshinfo_out.numVertices;
                    if ( meshinfo_out.numVertices < 3u )
                        goto LABEL_92;
                    rdCamera_pCurCamera->projectLst(v20->vertices, vertices_tmp, meshinfo_out.numVertices);
                    if ( sithRender_lightingIRMode )
                    {
                        v29 = sithRender_f_83198C;
                        v20->light_level_static = 0.0;
                        v20->ambientLight = v29;
                    }
                    else if ( level_idk->extraLight < 0.0 )
                    {
                        v20->ambientLight = 0.0;
                    }
                    else if ( level_idk->extraLight > 1.0 )
                    {
                        v20->ambientLight = 1.0;
                    }
                    else
                    {
                        v20->ambientLight = level_idk->extraLight;
                    }
                    if ( v20->ambientLight < 1.0 )
                    {
                        v30 = v20->lightingMode;
                        if ( v30 == 2 )
                        {
                            if ( v20->light_level_static >= 1.0 && v68 )
                            {
                                v20->lightingMode = 0;
                            }
                            else if ( v20->light_level_static <= 0.0 )
                            {
                                v20->lightingMode = 1;
                            }
                            goto LABEL_87;
                        }
                        if ( v30 != 3 )
                            goto LABEL_87;
                        v31 = v20->vertexIntensities;
                        v32 = 1;
                        v66 = *v31;
                        if ( v28 > 1 )
                        {
                            v33 = v31 + 1;
                            do
                            {
                                v34 = *v33 - v66;
                                if ( v34 < 0.0 )
                                    v34 = -v34;
                                if ( v34 > 0.015625 )
                                    break;
                                ++v32;
                                ++v33;
                            }
                            while ( v32 < v28 );
                        }
                        if ( v32 != v28 )
                        {
LABEL_87:
                            v35 = v65->surfaceInfo.face.extraLight;
                            v36 = v65->surfaceInfo.face.type;
                            v20->wallCel = v65->surfaceInfo.face.wallCel;
                            v37 = v65->surfaceInfo.face.material;
                            v20->extralight = v35;
                            v20->material = v37;
                            v38 = v20->geometryMode;
                            v20->light_flags = 0;
                            v20->type = v36;
                            v39 = 1;
                            if ( v38 >= 4 )
                                v39 = 3;
                            if ( v20->lightingMode >= 3 )
                                v39 |= 4u;
                            rdCache_AddProcFace(0, v28, v39);
LABEL_92:
                            if ( (v74 & 1) != 0 )
                            {
                                v19 = v18;
                                v18--;
                            }
                            else
                            {
                                v19 = v71;
                                ++v71;
                            }
                            if ( ++v74 >= v76 )
                                goto LABEL_149;
                            continue;
                        }
                        if ( v66 != 1.0 )
                        {
                            if ( v66 == 0.0 )
                            {
                                v20->lightingMode = 1;
                                v20->light_level_static = 0.0;
                            }
                            else
                            {
                                v20->lightingMode = 2;
                                v20->light_level_static = v66;
                            }
                            goto LABEL_87;
                        }
                    }
                    break;
                }
                if ( v68 )
                {
                    v20->lightingMode = 0;
                }
                else
                {
                    v20->lightingMode = 2;
                    v20->light_level_static = 1.0;
                }
                goto LABEL_87;
            }
LABEL_150:
            v61 = level_idk->numSurfaces;
            v65->field_4 = sithRender_8EE678;
            ++v65;
            if ( ++v75 >= v61 )
                goto LABEL_151;
        }
        procEntry = rdCache_GetProcEntry();
        if ( !procEntry )
            goto LABEL_149;
        if ( (v65->surfaceFlags & (SURFACEFLAGS_200|SURFACEFLAGS_400)) != 0 )
        {
            v41 = sithRender_geoMode;
            if ( sithRender_geoMode > 3 )
                v41 = 3;
        }
        else
        {
            v41 = v65->surfaceInfo.face.geometryMode;
            if ( v41 >= sithRender_geoMode )
                v41 = sithRender_geoMode;
        }
        procEntry->geometryMode = v41;
        v42 = v65->surfaceInfo.face.lightingMode;
        if ( sithRender_lightingIRMode )
        {
            if ( v42 >= 2 )
                v42 = 2;
        }
        else if ( v42 >= sithRender_lightMode )
        {
            v42 = sithRender_lightMode;
        }
        v43 = sithRender_texMode;
        procEntry->lightingMode = v42;
        v44 = v65->surfaceInfo.face.textureMode;
        if ( v44 >= v43 )
            v44 = v43;
        procEntry->textureMode = v44;
        meshinfo_out.verticesProjected = vertices_tmp;
        v45 = procEntry->vertexUVs;
        sithRender_idxInfo.field_18 = v65->surfaceInfo.field_40;
        meshinfo_out.vertex_lights_maybe_ = procEntry->vertexIntensities;
        sithRender_idxInfo.vertexPosIdx = v65->surfaceInfo.face.vertexPosIdx;
        meshinfo_out.vertexUVs = v45;
        v46 = level_idk->clipFrustum;
        sithRender_idxInfo.numVertices = v65->surfaceInfo.face.numVertices;
        v64 = v44;
        v47 = procEntry->lightingMode;
        sithRender_idxInfo.vertexUVIdx = v65->surfaceInfo.face.vertexUVIdx;
        rdPrimit3_ClipFace(v46, procEntry->geometryMode, v47, v64, &sithRender_idxInfo, &meshinfo_out, &v65->surfaceInfo.face.clipIdk);
        num_vertices = meshinfo_out.numVertices;
        if ( meshinfo_out.numVertices < 3u )
        {
LABEL_149:
            level = sithWorld_pCurWorld;
            goto LABEL_150;
        }
        rdCamera_pCurCamera->projectLst(procEntry->vertices, vertices_tmp, meshinfo_out.numVertices);
        if ( sithRender_lightingIRMode )
        {
            v49 = sithRender_f_83198C;
            procEntry->light_level_static = 0.0;
            procEntry->ambientLight = v49;
        }
        else if ( level_idk->extraLight < 0.0 )
        {
            procEntry->ambientLight = 0.0;
        }
        else if ( level_idk->extraLight > 1.0 )
        {
            procEntry->ambientLight = 1.0;
        }
        else
        {
            procEntry->ambientLight = level_idk->extraLight;
        }
        if ( procEntry->ambientLight >= 1.0 )
            goto LABEL_134;
        v50 = procEntry->lightingMode;
        if ( v50 == 2 )
        {
            if ( procEntry->light_level_static >= 1.0 && v68 )
            {
                procEntry->lightingMode = 0;
            }
            else if ( procEntry->light_level_static <= 0.0 )
            {
                procEntry->lightingMode = 1;
            }
            goto LABEL_140;
        }
        if ( v50 != 3 )
            goto LABEL_140;
        v51 = procEntry->vertexIntensities;
        v67 = *v51;
        v52 = 1;
        if ( num_vertices > 1 )
        {
            v53 = v51 + 1;
            do
            {
                v54 = *v53 - v67;
                if ( v54 < 0.0 )
                    v54 = -v54;
                if ( v54 > 0.015625 )
                    break;
                ++v52;
                ++v53;
            }
            while ( v52 < num_vertices );
        }
        if ( v52 != num_vertices )
            goto LABEL_140;
        if ( v67 == 1.0 )
        {
LABEL_134:
            if ( v68 )
            {
                procEntry->lightingMode = 0;
            }
            else
            {
                procEntry->lightingMode = 2;
                procEntry->light_level_static = 1.0;
            }
        }
        else if ( v67 == 0.0 )
        {
            procEntry->lightingMode = 1;
            procEntry->light_level_static = 0.0;
        }
        else
        {
            procEntry->lightingMode = 2;
            procEntry->light_level_static = v67;
        }
LABEL_140:
        surfaceFlags = v65->surfaceFlags;
        if ( (surfaceFlags & SURFACEFLAGS_200) != 0 )
        {
            sithSector_sub_4F2E30(procEntry, &v65->surfaceInfo, num_vertices);
        }
        else if ( (surfaceFlags & SURFACEFLAGS_400) != 0 )
        {
            sithSector_sub_4F2F60(procEntry, &v65->surfaceInfo, vertices_tmp, num_vertices);
        }
        v56 = v65->surfaceInfo.face.extraLight;
        v57 = v65->surfaceInfo.face.type;
        procEntry->wallCel = v65->surfaceInfo.face.wallCel;
        v58 = v65->surfaceInfo.face.material;
        procEntry->extralight = v56;
        procEntry->material = v58;
        v59 = procEntry->geometryMode;
        procEntry->light_flags = 0;
        procEntry->type = v57;
        rend_flags = 1;
        if ( v59 >= 4 )
            rend_flags = 3;
        if ( procEntry->lightingMode >= 3 )
            rend_flags |= 4u;
        rdCache_AddProcFace(0, num_vertices, rend_flags);
        goto LABEL_149;
    }
LABEL_164:
    rdCache_Flush();
    rdCamera_pCurCamera->cameraClipFrustum = v77;
}

void sithRender_UpdateAllLights()
{
    sithAdjoin *i; // esi

    for (int j = 0; j < sithRender_numSectors; j++)
    {
        for ( i = sithRender_aSectors[j]->adjoins; i; i = i->next )
        {
            if ( i->sector->field_8C != sithRender_8EE678 && (i->flags & 1) != 0 )
            {
                i->sector->clipFrustum = sithRender_aSectors[j]->clipFrustum;
                sithRender_UpdateLights(i->sector, 0.0, i->dist);
            }
        }
    }
}

void sithRender_UpdateLights(sithSector *sector, float prev, float dist)
{
    sithThing *i;
    sithAdjoin *j;
    rdVector3 vertex_out;

    if ( sector->field_8C == sithRender_8EE678 )
        return;

    sector->field_8C = sithRender_8EE678;
    if ( prev < 2.0 && sithRender_numLights < 0x20)
    {
        for ( i = sector->thingsList; i; i = i->nextThing )
        {
            if ( sithRender_numLights >= 0x20 )
                break;

            if ((i->thingflags & SITH_TF_LIGHT) 
                && !(i->thingflags & (SITH_TF_DISABLED|SITH_TF_WILLBEREMOVED)))
            {
                if ( i->light > 0.0 )
                {
                    sithRender_aLights[sithRender_numLights].intensity = i->light;
                    rdCamera_AddLight(rdCamera_pCurCamera, &sithRender_aLights[sithRender_numLights], &i->position);
                    ++sithRender_numLights;
                }

                if ( (i->thingType == THINGTYPE_ACTOR || i->thingType == THINGTYPE_PLAYER) && sithRender_numLights < 0x20 )
                {
                    if ( (i->actorParams.typeflags & THING_TYPEFLAGS_DAMAGE) && i->actorParams.lightIntensity > 0.0 )
                    {
                        rdMatrix_TransformPoint34(&vertex_out, &i->actorParams.lightOffset, &i->lookOrientation);
                        vertex_out.x = i->position.x + vertex_out.x;
                        vertex_out.y = i->position.y + vertex_out.y;
                        vertex_out.z = i->position.z + vertex_out.z;
                        sithRender_aLights[sithRender_numLights].intensity = i->actorParams.lightIntensity;
                        rdCamera_AddLight(rdCamera_pCurCamera, &sithRender_aLights[sithRender_numLights], &vertex_out);
                        ++sithRender_numLights;
                    }
                    if ( i->actorParams.timeLeftLengthChange > 0.0 )
                    {
                        sithRender_aLights[sithRender_numLights].intensity = i->actorParams.timeLeftLengthChange;
                        rdCamera_AddLight(rdCamera_pCurCamera, &sithRender_aLights[sithRender_numLights], &i->actorParams.saberBladePos);
                        ++sithRender_numLights;
                    }
                }
            }
        }
    }
    if ( prev < 0.80000001 )
    {
        if ( sithRender_numSectors2 < 0xA0 )
        {
            sithRender_aSectors2[sithRender_numSectors2++] = sector;
        }
    }
    for ( j = sector->adjoins; j; j = j->next )
    {
        if ( (j->flags & 1) != 0 )
        {
            if ( j->sector->field_8C != sithRender_8EE678 )
            {
                float nextDist = j->mirror->dist + j->dist + dist + prev;
                if ( nextDist < 0.80000001 || nextDist < 2.0 )
                {
                    j->sector->clipFrustum = sector->clipFrustum;
                    sithRender_UpdateLights(j->sector, nextDist, 0.0);
                }
            }
        }
    }
}

void sithRender_RenderDynamicLights()
{
    sithSector *sectorIter; // edx
    rdLight **lightIter; // ebx
    rdLight **curCamera_lights; // edi
    int *verticeIdxs; // edx
    rdLight **lightIter2; // edi
    unsigned int v24; // [esp+8h] [ebp-13Ch]
    sithSector **aSectorIter; // [esp+Ch] [ebp-138h]
    float attenuationMax; // [esp+40h] [ebp-104h]
    rdLight *tmpLights[64]; // [esp+44h] [ebp-100h] BYREF

    if (!sithRender_numSectors)
        return;

    aSectorIter = sithRender_aSectors;
    for (int k = 0; k < sithRender_numSectors; k++)
    {
        sectorIter = *aSectorIter;
        
        lightIter = tmpLights;
        curCamera_lights = rdCamera_pCurCamera->lights;
        
        v24 = 0;
        for (int i = 0; i < rdCamera_pCurCamera->numLights; i++)
        {
            float distCalc = rdVector_Dist3(&rdCamera_pCurCamera->lightPositions[i], &sectorIter->center);
            if ( (*curCamera_lights)->falloffMin + sectorIter->radius > distCalc)
            {
                *lightIter++ = *curCamera_lights;
                ++v24;
            }
            ++curCamera_lights;
        }

        verticeIdxs = sectorIter->verticeIdxs;
        for (int j = 0; j < sectorIter->numVertices; j++)
        {
            int idx = *verticeIdxs;
            if ( sithWorld_pCurWorld->alloc_unk9c[idx] != sithRender_8EE678 )
            {
                sithWorld_pCurWorld->alloc_unk94[idx] = 0.0;
                lightIter2 = tmpLights;
                for (int i = 0; i < v24; i++)
                {
                    int id = (*lightIter2)->id;
                    float distCalc = rdVector_Dist3(&rdCamera_pCurCamera->lightPositions[id], &sithWorld_pCurWorld->vertices[idx]);
                    if ( distCalc < (*lightIter2)->falloffMax )
                        sithWorld_pCurWorld->alloc_unk94[idx] = (*lightIter2)->intensity - distCalc * rdCamera_pCurCamera->attenuationMax + sithWorld_pCurWorld->alloc_unk94[idx];
                    if ( sithWorld_pCurWorld->alloc_unk94[idx] >= 1.0 )
                        break;
                    ++lightIter2;
                }
                sithWorld_pCurWorld->alloc_unk9c[idx] = sithRender_8EE678;
            }
            verticeIdxs++;
        }
        ++aSectorIter;
    }
}

void sithRender_RenderThings()
{
    uint32_t v0; // edi
    sithSector *v1; // ebp
    double v2; // st7
    sithThing *thingIter; // esi
    float radius; // edx
    int clippingVal; // eax
    sithWorld *curWorld; // edx
    rdModel3 *model3; // ecx
    int v8; // ecx
    int v9; // eax
    double v10; // st7
    int v11; // eax
    float v12; // [esp-Ch] [ebp-28h]
    float a2; // [esp+8h] [ebp-14h]
    float clipRadius; // [esp+Ch] [ebp-10h]
    uint32_t i; // [esp+14h] [ebp-8h]
    BOOL v16; // [esp+18h] [ebp-4h]

    rdSetZBufferMethod(2);
    rdSetOcclusionMethod(0);
    v0 = 0;
    for ( i = 0; v0 < sithRender_numSectors2; i = v0 )
    {
        v1 = sithRender_aSectors2[v0];
        if ( sithRender_lightingIRMode )
        {
            a2 = sithRender_f_831990;
        }
        else
        {
            v2 = v1->ambientLight + v1->extraLight;
            if ( v2 < 0.0 )
            {
                a2 = 0.0;
            }
            else if ( v2 > 1.0 )
            {
                a2 = 1.0;
            }
            else
            {
                a2 = v2;
            }
        }
        rdColormap_SetCurrent(v1->colormap);
        thingIter = v1->thingsList;
        v16 = v1->colormap == sithWorld_pCurWorld->colormaps;
        if ( thingIter )
        {
            do
            {
                if ( (thingIter->thingflags & (SITH_TF_DISABLED|SITH_TF_10|SITH_TF_WILLBEREMOVED)) == 0
                  && (thingIter->thingflags & SITH_TF_LEVELGEO) == 0
                  && ((sithCamera_currentCamera->cameraPerspective & 0xFC) != 0 || thingIter != sithCamera_currentCamera->primaryFocus) )
                {
                    rdMatrix_TransformPoint34(&thingIter->screenPos, &thingIter->position, &rdCamera_pCurCamera->view_matrix);
                    if ( rdroid_curAcceleration > 0 || thingIter->rdthing.type != RD_THINGTYPE_SPRITE3 || sithRender_82F4B4 < 8 )
                    {
                        switch ( thingIter->rdthing.type )
                        {
                            case RD_THINGTYPE_MODEL:
                                radius = thingIter->rdthing.model3->radius;
                                goto LABEL_22;
                            case RD_THINGTYPE_SPRITE3:
                                clipRadius = thingIter->rdthing.sprite3->radius;
                                ++sithRender_82F4B4;
                                clippingVal = rdClip_SphereInFrustrum(v1->clipFrustum, &thingIter->screenPos, clipRadius);
                                goto LABEL_24;
                            case RD_THINGTYPE_PARTICLECLOUD:
                                clipRadius = thingIter->rdthing.particlecloud->cloudRadius;
                                clippingVal = rdClip_SphereInFrustrum(v1->clipFrustum, &thingIter->screenPos, clipRadius);
                                goto LABEL_24;
                            case RD_THINGTYPE_POLYLINE:
                                radius = thingIter->rdthing.polyline->length;
LABEL_22:
                                clipRadius = radius;
                                goto LABEL_23;
                            default:
LABEL_23:
                                clippingVal = rdClip_SphereInFrustrum(v1->clipFrustum, &thingIter->screenPos, clipRadius);
LABEL_24:
                                thingIter->rdthing.clippingIdk = clippingVal;
                                if ( clippingVal == 2 )
                                    break;
                                curWorld = sithWorld_pCurWorld;
                                if ( thingIter->rdthing.type != RD_THINGTYPE_MODEL )
                                    goto LABEL_42;
                                model3 = thingIter->rdthing.model3;
                                switch ( model3->numGeosets )
                                {
                                    case 1:
                                        goto LABEL_42;
                                    case 2:
                                        if ( thingIter->screenPos.y < (double)sithWorld_pCurWorld->loadDistance.y )
                                        {
                                            model3->geosetSelect = 0;
                                            goto LABEL_42;
                                        }
                                        goto LABEL_41;
                                    case 3:
                                        if ( thingIter->screenPos.y < (double)sithWorld_pCurWorld->loadDistance.x )
                                        {
                                            model3->geosetSelect = 0;
                                            goto LABEL_42;
                                        }
                                        if ( thingIter->screenPos.y >= (double)sithWorld_pCurWorld->loadDistance.y )
                                        {
                                            model3->geosetSelect = 2;
                                            goto LABEL_42;
                                        }
LABEL_41:
                                        model3->geosetSelect = 1;
                                        goto LABEL_42;
                                }
                                if ( thingIter->screenPos.y < (double)sithWorld_pCurWorld->loadDistance.x )
                                {
                                    model3->geosetSelect = 0;
                                    goto LABEL_42;
                                }
                                if ( thingIter->screenPos.y < (double)sithWorld_pCurWorld->loadDistance.y )
                                    goto LABEL_41;
                                if ( thingIter->screenPos.y >= (double)sithWorld_pCurWorld->loadDistance.z )
                                    model3->geosetSelect = 3;
                                else
                                    model3->geosetSelect = 2;
LABEL_42:
                                v8 = thingIter->rdthing.texMode;
                                if ( thingIter->screenPos.y >= (double)curWorld->perspectiveDistance )
                                {
                                    thingIter->rdthing.textureMode = v8 > 0 ? 0 : v8;
                                }
                                else
                                {
                                    v9 = 1;
                                    if ( v8 <= 1 )
                                        v9 = thingIter->rdthing.texMode;
                                    thingIter->rdthing.textureMode = v9;
                                }
                                if ( thingIter->screenPos.y >= (double)curWorld->perspectiveDistance )
                                {
                                    thingIter->rdthing.textureMode = v8 > 0 ? 0 : v8;
                                }
                                else
                                {
                                    if ( v8 > 1 )
                                        v8 = 1;
                                    thingIter->rdthing.textureMode = v8;
                                }
                                if ( (thingIter->thingflags & 1) != 0
                                  && thingIter->light > 0.0
                                  && (thingIter->light < 0.0 ? (v10 = 0.0) : thingIter->light > 1.0 ? (v10 = 1.0) : (v10 = thingIter->light), a2 <= v10) )
                                {
                                    if ( thingIter->light < 0.0 )
                                    {
                                        rdCamera_SetAmbientLight(rdCamera_pCurCamera, 0.0);
                                    }
                                    else
                                    {
                                        if ( thingIter->light > 1.0 )
                                            v12 = 1.0;
                                        else
                                            v12 = thingIter->light;
                                        rdCamera_SetAmbientLight(rdCamera_pCurCamera, v12);
                                    }
                                }
                                else
                                {
                                    rdCamera_SetAmbientLight(rdCamera_pCurCamera, a2);
                                }
                                if ( a2 >= 1.0 )
                                {
                                    v11 = thingIter->rdthing.lightMode;
                                    if ( v16 )
                                    {
                                        v11 = v11 > 0 ? 0 : v11;
                                        goto LABEL_77;
                                    }
                                    goto LABEL_73;
                                }
                                if ( (thingIter->thingflags & SITH_TF_4000000) == 0 && thingIter->screenPos.y >= (double)sithWorld_pCurWorld->gouradDistance )
                                {
                                    v11 = thingIter->rdthing.lightMode;
LABEL_73:
                                    if ( v11 > 2 )
                                        v11 = 2;
                                    goto LABEL_77;
                                }
                                v11 = thingIter->rdthing.lightMode;
                                if ( v11 > 3 )
                                    v11 = 3;
LABEL_77:
                                thingIter->rdthing.lightingMode = v11;
                                if ( sithRender_RenderPov(thingIter) )
                                    ++sithRender_831984;
                                break;
                        }
                    }
                }
                thingIter = thingIter->nextThing;
            }
            while ( thingIter );
            v0 = i;
        }
        ++v0;
    }
    rdCache_Flush();
}

int sithRender_RenderPov(sithThing *povThing)
{
    int ret;

    if ( (povThing->thingflags & SITH_TF_INCAMFOV) == 0 )
    {
#ifndef LINUX
        if ( (povThing->thingflags & SITH_TF_CAPTURED) != 0 )
            sithCog_SendMessageFromThing(povThing, 0, SITH_MESSAGE_SIGHTED);
#endif
        if ( povThing->thingtype == THINGTYPE_ACTOR )
        {
            if ( povThing->actor )
            {
                povThing->actor->mode &= ~0x1000u;
            }
        }
        povThing->thingflags |= SITH_TF_INCAMFOV;
    }
    povThing->isVisible = bShowInvisibleThings;
    povThing->lookOrientation.scale = povThing->position;
    ret = rdThing_Draw(&povThing->rdthing, &povThing->lookOrientation);
    povThing->lookOrientation.scale.x = 0.0;
    povThing->lookOrientation.scale.y = 0.0;
    povThing->lookOrientation.scale.z = 0.0;
    if ( sithRender_weaponRenderHandle && (povThing->thingflags & SITH_TF_RENDERWEAPON) != 0 )
        sithRender_weaponRenderHandle(povThing);
    if ( povThing->thingType == THINGTYPE_EXPLOSION && (povThing->explosionParams.typeflags & 0x100) != 0 )
    {
        float v5 = stdMath_Dist3D1(povThing->screenPos.x, povThing->screenPos.y, povThing->screenPos.z);
        uint32_t v6 = povThing->explosionParams.flashB;
        uint32_t v7 = povThing->explosionParams.flashR;
        uint32_t v8 = povThing->explosionParams.flashB;
        float v9 = ((double)(v8 + v7 + v6) * 0.013020833 - rdCamera_pCurCamera->attenuationMin * v5) * 0.1;
        if ( v9 > 0.0 )
            sithPlayer_AddDyamicAdd((__int64)((double)v7 * v9 - -0.5), (__int64)((double)v6 * v9 - -0.5), (__int64)((double)v8 * v9 - -0.5));
        povThing->explosionParams.typeflags &= ~0x100;
    }
    return ret;
}

void sithRender_RenderAlphaSurfaces()
{
    sithSurface *v0; // edi
    sithSector *v1; // esi
    double v2; // st7
    int v3; // ebx
    unsigned int v4; // ebp
    sithWorld *v5; // edx
    int v7; // eax
    rdProcEntry *v9; // esi
    float *v20; // eax
    unsigned int v21; // ecx
    float *v22; // edx
    char v23; // bl
    float v31; // [esp+4h] [ebp-10h]
    sithSector *surfaceSector; // [esp+Ch] [ebp-8h]

    rdSetZBufferMethod(2);
    rdSetOcclusionMethod(0);
    rdSetSortingMethod(2);

    for (int i = 0; i < sithRender_numSurfaces; i++)
    {
        v0 = sithRender_aSurfaces[i];
        v1 = v0->parent_sector;
        surfaceSector = v1;
        if ( sithRender_lightingIRMode )
        {
            rdCamera_SetAmbientLight(rdCamera_pCurCamera, sithRender_f_83198C);
        }
        else
        {
            v2 = v1->extraLight + v1->ambientLight;
            if ( v2 < 0.0 )
            {
                rdCamera_SetAmbientLight(rdCamera_pCurCamera, 0.0);
            }
            else if ( v2 > 1.0 )
            {
                rdCamera_SetAmbientLight(rdCamera_pCurCamera, 1.0);
            }
            else
            {
                rdCamera_SetAmbientLight(rdCamera_pCurCamera, v2);
            }
        }
        rdColormap_SetCurrent(v1->colormap);
        v3 = sithRender_8EE678;
        if ( v0->field_4 != sithRender_8EE678 )
        {
            v4 = 0;
            if ( v0->surfaceInfo.face.numVertices )
            {
                v5 = sithWorld_pCurWorld;
                do
                {
                    v7 = v0->surfaceInfo.face.vertexPosIdx[v4];
                    if ( sithWorld_pCurWorld->alloc_unk98[v7] != v3 )
                    {
                        rdMatrix_TransformPoint34(&v5->verticesTransformed[v7], &v5->vertices[v7], &rdCamera_pCurCamera->view_matrix);
                        v5 = sithWorld_pCurWorld;
                        v3 = sithRender_8EE678;
                        sithWorld_pCurWorld->alloc_unk98[v7] = sithRender_8EE678;
                    }
                    ++v4;
                }
                while ( v4 < v0->surfaceInfo.face.numVertices );
            }
            v0->field_4 = v3;
        }
        v9 = rdCache_GetProcEntry();
        if ( !v9 )
        {
            continue;
        }
        
        v9->geometryMode = sithRender_geoMode;
        if ( v0->surfaceInfo.face.geometryMode < sithRender_geoMode )
        {
            v9->geometryMode = v0->surfaceInfo.face.geometryMode;
        }

        v9->lightingMode = sithRender_lightMode;
        if ( v0->surfaceInfo.face.lightingMode < sithRender_lightMode )
        {
            v9->lightingMode = v0->surfaceInfo.face.lightingMode;
        }
        
        v9->textureMode = sithRender_texMode;
        if (v0->surfaceInfo.face.textureMode < sithRender_texMode)
            v9->textureMode = v0->surfaceInfo.face.textureMode;

        sithRender_idxInfo.field_18 = v0->surfaceInfo.field_40;
        meshinfo_out.vertexUVs = v9->vertexUVs;
        meshinfo_out.vertex_lights_maybe_ = v9->vertexIntensities;
        sithRender_idxInfo.numVertices = v0->surfaceInfo.face.numVertices;
        sithRender_idxInfo.vertexPosIdx = v0->surfaceInfo.face.vertexPosIdx;
        sithRender_idxInfo.vertexUVIdx = v0->surfaceInfo.face.vertexUVIdx;
        meshinfo_out.verticesProjected = vertices_tmp;
        rdPrimit3_ClipFace(surfaceSector->clipFrustum, v9->geometryMode, v9->lightingMode, v9->textureMode, &sithRender_idxInfo, &meshinfo_out, &v0->surfaceInfo.face.clipIdk);
        if ( meshinfo_out.numVertices < 3u )
        {
            continue;
        }
        rdCamera_pCurCamera->projectLst(v9->vertices, vertices_tmp, meshinfo_out.numVertices);
        if ( surfaceSector->extraLight < 0.0 )
        {
            v9->ambientLight = 0.0;
        }
        else if ( surfaceSector->extraLight > 1.0 )
        {
            v9->ambientLight = 1.0;
        }
        else
        {
            v9->ambientLight = surfaceSector->extraLight;
        }

        if ( v9->ambientLight < 1.0 )
        {
            if ( v9->lightingMode == 2 )
            {
                if ( v9->light_level_static >= 1.0 && surfaceSector->colormap == sithWorld_pCurWorld->colormaps )
                {
                    v9->lightingMode = 0;
                }
                else if ( v9->light_level_static <= 0.0 )
                {
                    v9->lightingMode = 1;
                }
                goto LABEL_52;
            }
            if ( v9->lightingMode != 3 )
                goto LABEL_52;
            v20 = v9->vertexIntensities;
            v21 = 1;
            v31 = *v20;
            if ( meshinfo_out.numVertices > 1 )
            {
                v22 = v20 + 1;
                do
                {
                    if ( *v22 != v31 )
                        break;
                    ++v21;
                    ++v22;
                }
                while ( v21 < meshinfo_out.numVertices );
            }
            if ( v21 != meshinfo_out.numVertices )
                goto LABEL_52;
            if ( v31 != 1.0 )
            {
                if ( v31 == 0.0 )
                {
                    v9->lightingMode = 1;
                    v9->light_level_static = 0.0;
                }
                else
                {
                    v9->lightingMode = 2;
                    v9->light_level_static = v31;
                }
                goto LABEL_52;
            }
            if ( surfaceSector->colormap != sithWorld_pCurWorld->colormaps )
            {
LABEL_48:
                v9->lightingMode = 2;
                v9->light_level_static = 1.0;
                goto LABEL_52;
            }
            v9->lightingMode = 0;
        }
        else
        {
            if ( surfaceSector->colormap != sithWorld_pCurWorld->colormaps )
                goto LABEL_48;
            v9->lightingMode = 0;
        }
LABEL_52:
        v23 = 1;
        if ( v9->geometryMode >= 4 )
            v23 = 3;
        if ( v9->lightingMode >= 3 )
            v23 |= 4u;

        v9->type = v0->surfaceInfo.face.type;
        v9->extralight = v0->surfaceInfo.face.extraLight;
        v9->wallCel = v0->surfaceInfo.face.wallCel;
        v9->light_flags = 0;
        v9->material = v0->surfaceInfo.face.material;
        rdSetProcFaceUserData(surfaceSector->id);
        rdCache_AddProcFace(0, meshinfo_out.numVertices, v23);
    }
    rdCache_Flush();
}

int sithRender_SetRenderWeaponHandle(void *a1)
{
    sithRender_weaponRenderHandle = a1;
    return 1;
}
