#include "sithRender.h"

#include <math.h>
#include <float.h>

#include "Cog/sithCog.h"
#include "Main/sithMain.h"
#include "World/sithMaterial.h"
#include "World/sithModel.h"
#include "Engine/sithKeyFrame.h"
#include "Engine/rdMaterial.h"
#include "Engine/rdKeyframe.h"
#include "Engine/rdColormap.h"
#include "Engine/rdroid.h"
#include "Engine/sithIntersect.h"
#include "Gameplay/sithTime.h"
#include "Engine/sithCamera.h"
#include "Raster/rdCache.h"
#include "Engine/rdClip.h"
#include "Engine/rdCamera.h"
#include "Engine/sithRenderSky.h"
#include "General/stdMath.h"
#include "Raster/rdFace.h"
#include "Primitives/rdModel3.h"
#include "Primitives/rdPrimit3.h"
#include "World/jkPlayer.h"
#include "Gameplay/sithPlayer.h"
#include "World/sithSector.h"
#include "World/sithWorld.h"
#include "World/sithExplosion.h"
#include "Platform/std3D.h"
#include "Primitives/rdMath.h"
#include "stdPlatform.h"

#if defined(TARGET_TWL)
#include <nds.h>
#endif

#ifdef QOL_IMPROVEMENTS
#if 0
static rdThing* lightDebugThing = NULL;
static rdModel3* lightDebugThing_model3 = NULL;
static rdMatrix34 lightDebugThing_mat;
static int lightDebugNum = 0;
#endif

#ifdef JKM_LIGHTING
int sithRender_008d4094 = 0;
flex_t sithRender_008d4098 = 0.0;
flex_t sithRender_008d409c = 0.0;
#endif

int sithRender_008d1668 = 0;

// Added: safeguard
int sithRender_adjoinSafeguard = 0;

void sithRender_RenderDebugLight(flex_t intensity, rdVector3* pos)
{
#if 0
    rdVector3 scale_test;

    //intensity *= 10.0;
    
    scale_test.x = intensity * 2.0;
    scale_test.y = intensity * 2.0;
    scale_test.z = intensity * 2.0;

    lightDebugThing_model3->radius = 0;
    lightDebugThing->desiredLightMode = 0;
    lightDebugThing->geosetSelect = 0;
    lightDebugThing_model3->geosetSelect = 0;
    
    /*if (intensity == 1.0)
    {
        scale_test.x = intensity * 2.0;
    }*/
    
    rdMatrix_Identity34(&lightDebugThing_mat);
    rdMatrix_PreScale34(&lightDebugThing_mat, &scale_test);
    
    //printf("light %u: %f %f %f, %f\n", lightDebugNum++, pos->x, pos->y, pos->z, intensity);
    rdVector_Copy3(&lightDebugThing_mat.scale, pos);
    rdThing_Draw(lightDebugThing, &lightDebugThing_mat);
#endif
}

void sithRender_RenderDebugLight2(flex_t intensity, rdVector3* pos, rdVector3* norm)
{
#if 0
    rdVector3 scale_test;

    //intensity *= 10.0;
    
    scale_test.x = stdMath_Max((1.0 - norm->x) * intensity * (flex_t)2.0, (flex_t)1.0);
    scale_test.y = stdMath_Max((1.0 - norm->y) * intensity * (flex_t)2.0, (flex_t)1.0);
    scale_test.z = stdMath_Max((1.0 - norm->z) * intensity * (flex_t)2.0, (flex_t)1.0);

    lightDebugThing_model3->radius = 0;
    lightDebugThing->desiredLightMode = 0;
    lightDebugThing->geosetSelect = 0;
    lightDebugThing_model3->geosetSelect = 0;
    
    /*if (intensity == 1.0)
    {
        scale_test.x = intensity * 2.0;
    }*/
    
    rdMatrix_Identity34(&lightDebugThing_mat);
    rdMatrix_PreScale34(&lightDebugThing_mat, &scale_test);
    
    printf("light %u: %f %f %f, %f\n", lightDebugNum++, pos->x, pos->y, pos->z, intensity);
    rdVector_Copy3(&lightDebugThing_mat.scale, pos);
    rdThing_Draw(lightDebugThing, &lightDebugThing_mat);
#endif
}

void sithRender_RenderDebugLights()
{
    SithSector *sectorIter; // edx
    //rdLight **lightIter; // ebx
    //rdLight **curCamera_lights; // edi
    int *aVertIdxs; // edx
    rdLight **lightIter2; // edi
    //unsigned int v24; // [esp+8h] [ebp-13Ch]
    SithSector **aSectorIter; // [esp+Ch] [ebp-138h]
    flex_t attenuationMax; // [esp+40h] [ebp-104h]
    rdLight *tmpLights[64]; // [esp+44h] [ebp-100h] BYREF

    if (!sithRender_g_numVisibleSectors)
        return;

    aSectorIter = sithRender_aVisibleSectors;
    for (int k = 0; k < sithRender_g_numVisibleSectors; k++)
    {
        sectorIter = aSectorIter[k];
        
        //lightIter = tmpLights;
        //curCamera_lights = rdCamera_g_pCurCamera->aLights;
        
        sithRender_RenderDebugLight(1.0, &sectorIter->center);
        
        //v24 = 0;
        for (int i = 0; i < rdCamera_g_pCurCamera->numLights; i++)
        {
            sithRender_RenderDebugLight(rdCamera_g_pCurCamera->aLights[i]->intensity, &rdCamera_g_pCurCamera->aLightPositions[i]);
        
            /*flex_t distCalc = rdVector_Dist3(&rdCamera_g_pCurCamera->aLightPositions[i], &sectorIter->center);
            if ( (*curCamera_lights)->minRadius + sectorIter->radius > distCalc)
            {
                *lightIter++ = *curCamera_lights;
                ++v24;
            }
            ++curCamera_lights;*/
        }

        /*aVertIdxs = sectorIter->aVertIdxs;
        for (int j = 0; j < sectorIter->numVertices; j++)
        {
            int idx = *aVertIdxs;
            if ( sithWorld_g_pCurrentWorld->alloc_unk9c[idx] != sithRender_lastRenderTick )
            {
                sithWorld_g_pCurrentWorld->aVertDynamicLights[idx] = 0.0;
                lightIter2 = tmpLights;
                for (int i = 0; i < v24; i++)
                {
                    int id = (*lightIter2)->id;
                    flex_t distCalc = rdVector_Dist3(&rdCamera_g_pCurCamera->aLightPositions[id], &sithWorld_g_pCurrentWorld->aVertices[idx]);
                    if ( distCalc < (*lightIter2)->maxRadius )
                        sithWorld_g_pCurrentWorld->aVertDynamicLights[idx] = (*lightIter2)->intensity - distCalc * rdCamera_g_pCurCamera->attenuationMax + sithWorld_g_pCurrentWorld->aVertDynamicLights[idx];
                    if ( sithWorld_g_pCurrentWorld->aVertDynamicLights[idx] >= 1.0 )
                        break;
                    ++lightIter2;
                }
                sithWorld_g_pCurrentWorld->alloc_unk9c[idx] = sithRender_lastRenderTick;
            }
            aVertIdxs++;
        }*/
    }
}
#endif

int sithRender_Startup()
{
    rdMaterial_RegisterLoader(sithMaterial_Load);
    rdModel3_RegisterLoader(sithModel_Load);
    rdKeyframe_RegisterLoader(sithKeyFrame_LoadEntry);
    sithRender_renderflags = 0;
    sithRender_pExtraThingRenderFunc = 0;

    return 1;
}

// MOTS altered
int sithRender_Open()
{
    sithRender_geoMode = RD_GEOMETRY_FULL;
    sithRender_lightMode = RD_LIGHTMODE_GOURAUD;
    sithRender_texMode = RD_TEXTUREMODE_PERSPECTIVE;

    for (int i = 0; i < SITHREND_NUM_LIGHTS; i++)
    {
        rdLight_NewEntry(&sithRender_aThingLights[i]);
    }

    rdColormap_SetCurrent(sithWorld_g_pCurrentWorld->colormaps);
    rdColormap_SetIdentity(sithWorld_g_pCurrentWorld->colormaps);

    sithRenderSky_Open(sithWorld_g_pCurrentWorld->horizontalPixelsPerRev, sithWorld_g_pCurrentWorld->horizonDistance, sithWorld_g_pCurrentWorld->ceilingSkyHeight);

    sithRender_lightingIRMode = 0; 
    sithRender_bResetCameraAspect = 0;

#ifdef JKM_LIGHTING
    // MOTS added
    sithRender_008d4094 = 0;
    sithRender_008d4098 = 0.0;
    sithRender_008d409c = 0.0;
#endif
    
#ifdef QOL_IMPROVEMENTS
#if 0
    // Added: Light debug
    lightDebugThing = rdThing_New(NULL);
    if (!lightDebugThing_model3)
        lightDebugThing_model3 = rdModel3_Load("3d0\\lamp.3do");
    rdThing_SetModel3(lightDebugThing, lightDebugThing_model3);
    rdMatrix_Identity34(&lightDebugThing_mat);
#endif
#endif
    
    return 1;
}

void sithRender_Close()
{
    // Added: Light debug
    //rdModel3_Free(lightDebugThing_model3); // TODO figure out weird free issues
    //rdThing_Free(lightDebugThing);

    sithRenderSky_Close();
}

void sithRender_Shutdown()
{
    ;
}

void sithRender_SetRenderFlags(int flag)
{
    sithRender_renderflags = flag;
}

int sithRender_GetRenderFlags()
{
    return sithRender_renderflags;
}

void sithRender_EnableIRMode(flex_t a, flex_t b)
{
    sithRender_lightingIRMode = 1;
    sithRender_f_83198C = stdMath_Clamp(a, 0.0, 1.0);
    sithRender_f_831990 = stdMath_Clamp(b, 0.0, 1.0);
}

void sithRender_DisableIRMode()
{
    sithRender_lightingIRMode = 0;
}

void sithRender_SetGeoMode(rdGeoMode_t geoMode)
{
    sithRender_geoMode = geoMode;
}

void sithRender_SetLightingMode(rdLightMode_t lightMode)
{
    sithRender_lightMode = lightMode;
}

void sithRender_SetTexMode(rdTexMode_t texMode)
{
    sithRender_texMode = texMode;
}

void sithRender_SetPalette(const void *palette)
{
    rdColormap_SetCurrent(sithWorld_g_pCurrentWorld->colormaps);
    rdColormap_SetIdentity(sithWorld_g_pCurrentWorld->colormaps);
    if ( rdroid_curAcceleration > 0 )
    {
        sithMaterial_UnloadAll();
        std3D_UnloadAllTextures();
        std3D_SetCurrentPalette((rdColor24 *)palette, 90);
    }
}

void sithRender_Draw()
{
    SithSector *v2; // edi
    SithSector *v4; // eax
    flex_t a2; // [esp+0h] [ebp-28h]
    flex_t v7; // [esp+8h] [ebp-20h]
    flex_t v9; // [esp+8h] [ebp-20h]
    flex_t a3; // [esp+1Ch] [ebp-Ch] BYREF
    flex_t a4; // [esp+24h] [ebp-4h] BYREF

    //printf("%x %x %x\n", sithRender_texMode, rdroid_curTextureMode, sithRender_lightMode);

    //lightDebugNum = 0; // Added

#ifdef TARGET_TWL
    //sithRender_geoMode = RD_GEOMETRY_SOLID;
    //sithRender_lightMode = RD_LIGHTMODE_DIFFUSE;
    //sithRender_texMode = RD_TEXTUREMODE_PERSPECTIVE;
    //rdroid_curVertexColorMode = 0;
#endif

    // Keeping this here in case I need to check for weird corruption again
#if 0
    for (int i = 0; i < sithWorld_g_pCurrentWorld->numThingsLoaded; i++)
    {
        SithThing* v16 = &sithWorld_g_pCurrentWorld->aThings[i];
        if (v16->moveType == SITH_MT_PATH)
        {
            if (v16->trackParams.loadedFrames < 0) {
                stdPlatform_Printf("OpenJKDF2: Track thing 0x%x %s has corrupted loadedFrames %x %x\n", i, v16->aName, v16->trackParams.loadedFrames, v16->trackParams.sizeFrames);
            }
        }
    }

    for (int i = 0; i < sithWorld_g_pCurrentWorld->numThingTemplates; i++)
    {
        SithThing* v16 = &sithWorld_g_pCurrentWorld->aThingTemplates[i];
        if (v16->moveType == SITH_MT_PATH)
        {
            if (v16->trackParams.loadedFrames < 0 || v16->trackParams.sizeFrames <= 0) {
                stdPlatform_Printf("OpenJKDF2: Template track thing 0x%x %s has corrupted loadedFrames %x %x\n", i, v16->aName, v16->trackParams.loadedFrames, v16->trackParams.sizeFrames);
            }
        }
    }
#endif

    sithRenderSky_Update();
    if (!sithRender_geoMode)
        return;

    rdSetGeometryMode(sithRender_geoMode);
    if ( sithRender_lightingIRMode )
        rdSetLightingMode(2);
    else
        rdSetLightingMode(sithRender_lightMode);
    rdSetTextureMode(sithRender_texMode);
    rdSetRenderOptions(rdGetRenterOptions() | 2);

    // Somehow backface culling on aModels got unset...?
#ifdef QOL_IMPROVEMENTS
    rdSetRenderOptions(rdGetRenterOptions() | 1);
#endif

    if (!sithCamera_g_pCurCamera || !sithCamera_g_pCurCamera->sector)
        return;

    sithPlayer_SetScreenTint(sithCamera_g_pCurCamera->sector->tint.x, sithCamera_g_pCurCamera->sector->tint.y, sithCamera_g_pCurCamera->sector->tint.z);

    // TODO: Verify this is expensive
#ifndef TARGET_TWL
    if ( (sithCamera_g_pCurCamera->sector->flags & 2) != 0 )
    {
        flex_t fov = sithCamera_g_pCurCamera->fov;
        flex_t aspect = sithCamera_g_pCurCamera->aspectRatio;

#ifdef QOL_IMPROVEMENTS
        fov = jkPlayer_fov;
        aspect = sithMain_lastAspect;
#endif
        stdMath_SinCos(sithTime_g_secGameTime * 70.0, &a3, &a4);
        rdCamera_SetFOV(&sithCamera_g_pCurCamera->rdCamera, a3 + fov);
        stdMath_SinCos(sithTime_g_secGameTime * 100.0, &a3, &a4);
        rdCamera_SetAspectRatio(&sithCamera_g_pCurCamera->rdCamera, a3 * 0.016666668 + aspect);
        sithRender_bResetCameraAspect = 1;
    }
    else if ( sithRender_bResetCameraAspect )
    {
        rdCamera_SetFOV(&sithCamera_g_pCurCamera->rdCamera, sithCamera_g_pCurCamera->fov);
        rdCamera_SetAspectRatio(&sithCamera_g_pCurCamera->rdCamera, sithCamera_g_pCurCamera->aspectRatio);
        sithRender_bResetCameraAspect = 0;
    }
#endif

    rdSetSortingMethod(0);
    rdSetMipDistances(&sithWorld_g_pCurrentWorld->mipmapDistance);
    rdSetCullFlags(1);
    sithRender_g_numVisibleSectors = 0;
    sithRender_numThingSectors = 0;
    sithRender_numThingLights = 0;
    sithRender_numSecorFrustrums = 0;
    sithRender_numAlphaAdjoins = 0;
    sithRender_numSpritesToDraw = 0;
    sithRender_numRenderedSectors = 0;
    sithRender_nongeoThingsDrawn = 0;
    sithRender_geoThingsDrawn = 0;
    rdCamera_ClearLights(rdCamera_g_pCurCamera);
    //printf("------\n");
    sithRender_adjoinSafeguard = 0; // Added: safeguard

    // Added: noclip
    if (!(g_debugmodeFlags & DEBUGFLAG_NOCLIP)) {
        sithPlayer_bNoClippingRend = 0;
    }

#ifdef TARGET_TWL
    int testClip = stdPlatform_GetTimeMsec();

    // Added: noclip
    if (!sithPlayer_bNoClippingRend) {
        //sithRender_BuildVisibleSectorList(sithCamera_g_pCurCamera->sector, rdCamera_g_pCurCamera->pClipFrustum, 0.0, 0);
        sithRender_renderflags |= 4;
        sithRender_f_82F4B0 = rdCamera_g_pCurCamera->pClipFrustum->farPlane * 1.5;
        sithRender_KindaClipAssignFrustum(sithCamera_g_pCurCamera->sector, rdCamera_g_pCurCamera->pClipFrustum, 0, 0);
        sithRender_KindaClip(sithCamera_g_pCurCamera->sector, rdCamera_g_pCurCamera->pClipFrustum, 0.0, 0);
        sithRender_renderflags &= ~4;
    }
    else {
        sithPlayer_bNoClippingRend = 0;
        sithRender_renderflags |= 4;
        sithRender_f_82F4B0 = 3.0;
        sithRender_NoClip(sithCamera_g_pCurCamera->sector, rdCamera_g_pCurCamera->pClipFrustum, 0.0, 0);
        sithRender_renderflags &= ~4;
        sithPlayer_bNoClippingRend = 1;

        rdVector3 camPos = sithCamera_g_pCurCamera->lookPos;
        for (int i = 0; i < sithWorld_g_pCurrentWorld->numSectors; i++)
        {
            SithSector* pSectorIter = &sithWorld_g_pCurrentWorld->aSectors[i];
            if (pSectorIter == sithCamera_g_pCurCamera->sector) {
                //continue;
            }
            if (pSectorIter->clipVisited == sithRender_lastRenderTick || pSectorIter->renderTick == sithRender_lastRenderTick) {
                continue;
            }
            /*flex_t dist = rdMath_DistancePointToPlane(&sithCamera_g_pCurCamera->lookPos, &rdCamera_g_pCurCamera->orient.lvec, &pSectorIter->center);
            if (dist + (pSectorIter->radius * 3.5) < 0.0) {
                continue;
            }
            if (dist - (pSectorIter->radius * 3.5) > SITHCAMERA_ZFAR * 2) {
                continue;
            }*/

            rdVector3 centerTrans = pSectorIter->center;
            rdMatrix_TransformPoint34Acc(&centerTrans, &rdCamera_g_pCurCamera->orient);
            int clipTestA = rdClip_SphereInFrustrum(rdCamera_g_pCurCamera->pClipFrustum, &centerTrans, 0.0);
            int clipTestB = rdClip_SphereInFrustrum(rdCamera_g_pCurCamera->pClipFrustum, &centerTrans, pSectorIter->radius);
            if (clipTestA == SPHERE_FULLY_INSIDE) {

            }
            else if (clipTestB == SPHERE_FULLY_OUTSIDE) {
                continue;
            }

            sithPlayer_bNoClippingRend = 0;
            sithRender_NoClip(pSectorIter, rdCamera_g_pCurCamera->pClipFrustum, 0.0, 0);
            sithPlayer_bNoClippingRend = 1;
        }
    }

#else
    // Added: noclip
    if (!sithPlayer_bNoClippingRend) {
        //sithRender_BuildVisibleSectorList(sithCamera_g_pCurCamera->sector, rdCamera_g_pCurCamera->pClipFrustum, 0.0, 0);
#if 0
        sithRender_KindaClipAssignFrustum(sithCamera_g_pCurCamera->sector, rdCamera_g_pCurCamera->pClipFrustum, 0, 0);
        sithRender_KindaClip(sithCamera_g_pCurCamera->sector, rdCamera_g_pCurCamera->pClipFrustum, 0.0, 0);
#else
        sithRender_BuildVisibleSectorList(sithCamera_g_pCurCamera->sector, rdCamera_g_pCurCamera->pClipFrustum, 0.0, 0);
#endif
    }
    else {
        rdVector3 camPos = sithCamera_g_pCurCamera->lookPos;
        for (int i = 0; i < sithWorld_g_pCurrentWorld->numSectors; i++)
        {
            SithSector* pSectorIter = &sithWorld_g_pCurrentWorld->aSectors[i];
            if (pSectorIter == sithCamera_g_pCurCamera->sector) {
                //continue;
            }
            if (pSectorIter->clipVisited == sithRender_lastRenderTick || pSectorIter->renderTick == sithRender_lastRenderTick) {
                continue;
            }

            // Only render aSectors that are in front of the camera near plane
            /*flex_t dist = rdMath_DistancePointToPlane(&sithCamera_g_pCurCamera->lookPos, &rdCamera_g_pCurCamera->orient.uvec, &pSectorIter->center);
            if (dist + (pSectorIter->radius * 3.5) < 0.0) {
                continue;
            }
            if (dist - (pSectorIter->radius) > SITHCAMERA_ZFAR) {
                continue;
            }*/

            rdVector3 centerTrans = pSectorIter->center;
            rdMatrix_TransformPoint34Acc(&centerTrans, &rdCamera_g_pCurCamera->orient);
            if (rdClip_SphereInFrustrum(rdCamera_g_pCurCamera->pClipFrustum, &centerTrans, pSectorIter->radius * 3.5) == SPHERE_FULLY_OUTSIDE) {
                flex_t dist = rdVector_Dist3(&sithCamera_g_pCurCamera->lookPos, &pSectorIter->center);
                if (dist + (pSectorIter->radius * 3.5) < 0.0) {
                    continue;
                }
            }

            sithRender_BuildVisibleSectorList(pSectorIter, rdCamera_g_pCurCamera->pClipFrustum, 0.0, 0);
        }
    }
#endif
#ifdef TARGET_TWL
    int testClipEnd = stdPlatform_GetTimeMsec();
#endif

#ifdef TARGET_TWL
    int testLights = stdPlatform_GetTimeMsec();
#endif
    // TWL: 0ms
    sithRender_BuildVisibleSectorsThingList();
    
    if ( (sithRender_renderflags & 2) != 0 )
        sithRender_BuildDynamicLights();

#ifdef JKM_LIGHTING
    // MOTS added
    if (sithRender_008d4094 != 0) {
        int local_8, iVar6, iVar5;

        if (0.0 <= sithRender_008d4098) {
            local_8 = 1;
            if (sithRender_008d4098 < 0.0) {
                local_8 = 0;
            }
        }
        else {
            local_8 = 0xffffffff;
        }
        flex_t fVar3 = sithRender_008d4098 - (flex_t)local_8 * sithRender_008d409c * sithTime_g_frameTimeFlex;
        if (0.0 <= sithRender_008d4098) {
            if (sithRender_008d4098 < 0.0) {
                iVar6 = 0;
            }
            else {
                iVar6 = 1;
            }
        }
        else {
            iVar6 = -1;
        }
        if (0.0 <= fVar3) {
            if (fVar3 > 0.0) {
                iVar5 = 1;
            }
            else {
                iVar5 = 0;
            }
        }
        else {
            iVar5 = -1;
        }
        sithRender_008d4098 = fVar3;
        if (iVar6 != iVar5) {
            sithRender_008d4098 = 0.0;
        }
        if (sithRender_008d4098 == 0.0) {
            sithRender_008d4094 = 0;
            sithRender_008d4098 = 0.0;
            sithRender_008d409c = 0.0;
        }
    }
#endif
#ifdef TARGET_TWL
    int testLightsEnd = stdPlatform_GetTimeMsec();

    int testLevelGeo = stdPlatform_GetTimeMsec();
#endif

    // TWL: 16ms
    sithRender_RenderSectors();

#ifdef TARGET_TWL
    int testLevelGeoEnd = stdPlatform_GetTimeMsec();

    int testThings = stdPlatform_GetTimeMsec();
#endif

    // TWL: 10-20ms
    if ( sithRender_numThingSectors )
        sithRender_RenderThings();

#ifdef TARGET_TWL
    int testThingsEnd = stdPlatform_GetTimeMsec();

    int testAlpha = stdPlatform_GetTimeMsec();
#endif

    // TWL: 0ms
    if ( sithRender_numAlphaAdjoins )
        sithRender_RenderAlphaAdjoins();

    rdSetCullFlags(3);
#ifdef QOL_IMPROVEMENTS
    //sithRender_RenderDebugLights();
#endif

#ifdef TARGET_TWL
    int testAlphaEnd = stdPlatform_GetTimeMsec();
    char resetConsole[16];
    int consoleX, consoleY;
    consoleGetCursor(NULL, &consoleX, &consoleY);
    snprintf(resetConsole, sizeof(resetConsole)-1, "\x1b[%d;%dH", consoleY, consoleX);
    printf("\x1b[8;0H                               \rclp=%d lts=%d geo=%d thg=%d al=%d %d \n                        \n", testClipEnd - testClip, testLightsEnd - testLights, testLevelGeoEnd - testLevelGeo, testThingsEnd - testThings, testAlphaEnd - testAlpha, sithRender_g_numVisibleSectors);
    stdPlatform_Printf(resetConsole);
#endif
}

// MOTS altered?
// Added: depth safety
void sithRender_BuildVisibleSectorList(SithSector *sector, rdClipFrustum *frustumArg, flex_t prevAdjoinDistAdd, int depth)
{
    int v5; // ecx
    rdClipFrustum *frustum; // edx
    SithThing *thing; // esi
    unsigned int lightIdx; // ecx
    SithSurfaceAdjoin *adjoinIter; // ebx
    SithSurface *adjoinSurface; // esi
    rdMaterial *adjoinMat; // eax
    rdVector3 *v20; // eax
    int v25; // eax
    unsigned int v27; // edi
    rdClipFrustum *v31; // ecx
    rdClipFrustum outClip; // [esp+Ch] [ebp-74h] BYREF
    rdVector3 vertex_out; // [esp+40h] [ebp-40h] BYREF
    int v45; // [esp+4Ch] [ebp-34h]
    rdTexinfo *v51; // [esp+64h] [ebp-1Ch]

    // Clip visited hardening
    // Does not help much, but no visual harm either
#ifdef QOL_IMPROVEMENTS
    if (sector->clipVisited == sithRender_lastRenderTick) {
        sector->pClipFrustum = rdCamera_g_pCurCamera->pClipFrustum;
        return;
    }
#endif

    if ( sector->renderTick == sithRender_lastRenderTick )
    {
        sector->pClipFrustum = rdCamera_g_pCurCamera->pClipFrustum;
    }
    else
    {
        sector->renderTick = sithRender_lastRenderTick;
        // Added: Prevent crashing
        if (sithRender_g_numVisibleSectors >= SITH_MAX_VISIBLE_SECTORS) {
            jk_printf("OpenJKDF2: Hit max visible sectors.\n");
            return;
        }
        // Added: Prevent crashing
        if (sithRender_numSecorFrustrums >= SITH_MAX_VISIBLE_SECTORS) {
            jk_printf("OpenJKDF2: Hit max visible sector clip frustums.\n");
            return;
        }
        // Added: Prevent crashing
        if (sithRender_numThingSectors >= SITH_MAX_VISIBLE_SECTORS_2) {
            jk_printf("OpenJKDF2: Hit max visible sectors (2).\n");
            return;
        }

        sithRender_aVisibleSectors[sithRender_g_numVisibleSectors++] = sector;
        if (!(sector->flags & SITH_SECTOR_SEEN) && !(g_debugmodeFlags & DEBUGFLAG_NOCLIP)) // Added: don't send sighted stuff in noclip, otherwise the whole map reveals
        {
            sector->flags |= SITH_SECTOR_SEEN;
            if ( (sector->flags & SITH_SECTOR_COGLINKED) != 0 )
                sithCog_SectorSendMessage(sector, 0, SITH_MESSAGE_SIGHTED);
        }
        frustum = &sithRender_aSectorFrustrums[sithRender_numSecorFrustrums++];
        _memcpy(frustum, frustumArg, sizeof(rdClipFrustum));
        thing = sector->pFirstThingInSector;
        sector->pClipFrustum = frustum;
        lightIdx = sithRender_numThingLights;

        // Added: safety
        int safeguard = 0;
        while ( thing )
        {
            if ( lightIdx >= 0x20 )
                break;

            // Added: safety
            if (++safeguard >= SITH_MAX_THINGS)
                break;

            // Debug, add extra light from player
#if 0
            if (thing->type == SITH_THING_PLAYER)
            {
                rdMatrix_TransformPoint34(&vertex_out, &thing->actorParams.lightOffset, &thing->orient);
                rdVector_Add3Acc(&vertex_out, &thing->position);
                sithRender_aThingLights[sithRender_numThingLights].intensity = 1.0;//thing->actorParams.lightIntensity;
                rdCamera_AddLight(rdCamera_g_pCurCamera, &sithRender_aThingLights[sithRender_numThingLights], &vertex_out);
                lightIdx = ++sithRender_numThingLights;
            }
#endif

            if ((thing->flags & SITH_TF_EMITLIGHT)
                 && !(thing->flags & (SITH_TF_DISABLED|SITH_TF_10|SITH_TF_DESTROYED)))
            {
                if ( thing->light > 0.0 )
                {
                    sithRender_aThingLights[lightIdx].intensity = thing->light;
                    rdCamera_AddLight(rdCamera_g_pCurCamera, &sithRender_aThingLights[lightIdx], &thing->position);
                    lightIdx = ++sithRender_numThingLights;
                }

                if ( (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER) && lightIdx < 0x20 )
                {
                    if ( (thing->actorParams.flags & SITH_AF_HEADLIGHT) != 0 && thing->actorParams.lightIntensity > 0.0 )
                    {
                        rdMatrix_TransformPoint34(&vertex_out, &thing->actorParams.lightOffset, &thing->orient);
                        rdVector_Add3Acc(&vertex_out, &thing->position);
                        sithRender_aThingLights[sithRender_numThingLights].intensity = thing->actorParams.lightIntensity;
                        rdCamera_AddLight(rdCamera_g_pCurCamera, &sithRender_aThingLights[sithRender_numThingLights], &vertex_out);
                        lightIdx = ++sithRender_numThingLights;
                    }
                    if ( thing->actorParams.timeLeftLengthChange > 0.0 )
                    {
                        sithRender_aThingLights[lightIdx].intensity = thing->actorParams.timeLeftLengthChange;
                        rdCamera_AddLight(rdCamera_g_pCurCamera, &sithRender_aThingLights[lightIdx], &thing->actorParams.saberBladePos);
                        lightIdx = ++sithRender_numThingLights;
                    }
                }
            }
            thing = thing->pNextThingInSector;
        }
        sithRender_aThingSectors[sithRender_numThingSectors++] = sector;
    }

    // Added: noclip
    if (sithPlayer_bNoClippingRend) return;
    
    v45 = sector->clipVisited;

    // Clip visited hardening
#ifdef QOL_IMPROVEMENTS
    sector->clipVisited = sithRender_lastRenderTick;
#else
    sector->clipVisited = 1;
#endif

    // Added: safeguard
    for (adjoinIter = sector->adjoins ; adjoinIter != NULL; adjoinIter = adjoinIter->next)
    {
        // Clip visited hardening
#ifdef QOL_IMPROVEMENTS
        if (adjoinIter->sector->clipVisited == sithRender_lastRenderTick)
#else
        if (adjoinIter->sector->clipVisited)
#endif
        {
            continue;
        }

        // Added
        if (++sithRender_adjoinSafeguard >= 0x100000) {
            stdPlatform_Printf("Hit safeguard...\n");
            break;
        }

        adjoinSurface = adjoinIter->surface;

        adjoinMat = adjoinSurface->surfaceInfo.face.material;
        if ( adjoinMat )
        {
            int v19 = adjoinSurface->surfaceInfo.face.wallCel;
            if ( v19 == -1 )
                v19 = adjoinMat->curCelNum;
            v51 = adjoinMat->texinfos[v19]; 
        }
        else {
            v51 = NULL; // Added. TODO: does setting this to NULL cause issues?
        }

        v20 = &sithWorld_g_pCurrentWorld->aVertices[*adjoinSurface->surfaceInfo.face.vertexPosIdx];
        flex_t dist = rdMath_DistancePointToPlane(&sithCamera_g_pCurCamera->lookPos, &adjoinSurface->surfaceInfo.face.normal, v20);
        flex_t adjoinDistAdd = adjoinIter->dist + adjoinIter->mirror->dist + prevAdjoinDistAdd;

        // Avoid rendering adjoins if they're far enough away
#ifdef TARGET_TWL
        // adjoinDistAdd compare GREATLY reduces recursion issues 
        // TODO: Test against TODOA and verify if this is QOL-worthy
        if (dist > SITHCAMERA_ZFAR /*|| dist < sector->pClipFrustum->nearPlane*/) {
            // Doesn't help, causes visual issues
            //adjoinIter->sector->clipVisited = sithRender_lastRenderTick;

            continue;
        }
        if ((sithRender_renderflags & 4) && adjoinDistAdd >= sithRender_f_82F4B0) {
            continue;
        }
#endif

        if ( dist > 0.0 || (dist == 0.0 && sector == sithCamera_g_pCurCamera->sector))
        {
            int bAdjoinIsTransparent = (((!adjoinSurface->surfaceInfo.face.material ||
                        (adjoinSurface->surfaceInfo.face.geometryMode == 0)) ||
                       ((adjoinSurface->surfaceInfo.face.type & 2))) ||
                      (v51 && (v51->header.texture_type & 8) && (v51->texture_ptr && v51->texture_ptr->alpha_en & 1)) // Added: v51->texture_ptr check
                      );

#ifdef QOL_IMPROVEMENTS
            // Added: Somehow the clipping changed enough to cause a bug in MoTS Lv12.
            // The ground under the water surface somehow renders.
            // As a mitigation, if a mirror surface is transparent but the top-layer isn't,
            // we will render underneath anyways.
            SithSurface* adjoinMirrorSurface = adjoinIter->mirror->surface;
            rdMaterial* adjoinMirrorMat = adjoinMirrorSurface->surfaceInfo.face.material;
            rdTexinfo* adjoinMirrorTexinfo = NULL;
            if ( adjoinMirrorMat )
            {
                int v19 = adjoinMirrorSurface->surfaceInfo.face.wallCel;
                if ( v19 == -1 )
                    v19 = adjoinMirrorMat->curCelNum;
                adjoinMirrorTexinfo = adjoinMirrorMat->texinfos[v19]; 
            }
            else {
                adjoinMirrorTexinfo = NULL; // Added. TODO: does setting this to NULL cause issues?
            }

            int bMirrorAdjoinIsTransparent = (((!adjoinMirrorSurface->surfaceInfo.face.material ||
                        (adjoinMirrorSurface->surfaceInfo.face.geometryMode == RD_GEOMETRY_NONE)) ||
                       ((adjoinMirrorSurface->surfaceInfo.face.type & 2))) ||
                      (adjoinMirrorTexinfo && (adjoinMirrorTexinfo->header.texture_type & 8) && (adjoinMirrorTexinfo->texture_ptr && adjoinMirrorTexinfo->texture_ptr->alpha_en & 1))
                      );

            bAdjoinIsTransparent |= bMirrorAdjoinIsTransparent;

            // Added: When swimming, sometimes the camera dips below the water. Consider the pAdjoin transparent if we are very close to it.
            bAdjoinIsTransparent |= (dist < 0.05);
#endif

            if ( adjoinSurface->field_4 != sithRender_lastRenderTick )
            {
                for (int i = 0; i < adjoinSurface->surfaceInfo.face.numVertices; i++)
                {
                    v25 = adjoinSurface->surfaceInfo.face.vertexPosIdx[i];
                    if ( sithWorld_g_pCurrentWorld->alloc_unk98[v25] != sithRender_lastRenderTick )
                    {
                        rdMatrix_TransformPoint34(&sithWorld_g_pCurrentWorld->aTransformedVertices[v25], &sithWorld_g_pCurrentWorld->aVertices[v25], &rdCamera_g_pCurCamera->orient);
                        sithWorld_g_pCurrentWorld->alloc_unk98[v25] = sithRender_lastRenderTick;
                    }
                }
                adjoinSurface->field_4 = sithRender_lastRenderTick;
            }

            sithRender_faceView.aVertices = sithWorld_g_pCurrentWorld->aTransformedVertices;
            sithRender_faceView.aTexVerticies = sithWorld_g_pCurrentWorld->aTexVerticies;
            sithRender_faceView.paDynamicLight = sithWorld_g_pCurrentWorld->aVertDynamicLights;
            sithRender_faceView.numVertices = adjoinSurface->surfaceInfo.face.numVertices;
            sithRender_faceView.vertexPosIdx = adjoinSurface->surfaceInfo.face.vertexPosIdx;
            meshinfo_out.aVertices = sithRender_aClipVertices;
            sithRender_faceView.vertexUVIdx = adjoinSurface->surfaceInfo.face.vertexUVIdx;

            rdPrimit3_ClipFace(frustumArg, RD_GEOMETRY_WIREFRAME, RD_LIGHTMODE_NOTLIT, RD_TEXTUREMODE_AFFINE, &sithRender_faceView, &meshinfo_out, &adjoinSurface->surfaceInfo.face.texVertOffset);

            if ((((unsigned int)meshinfo_out.numVertices >= 3u) || (rdClip_g_faceStatus & CLIPSTAT_NONE_VISIBLE)) 
                && ((rdClip_g_faceStatus & (CLIPSTAT_NEAR|CLIPSTAT_NONE_VISIBLE)) || ((adjoinIter->flags & 1) && bAdjoinIsTransparent))) 
            {
#ifdef TARGET_TWL
                rdCamera_g_pCurCamera->fnProjectLstClip(sithRender_aTransformedClipVertices, sithRender_aClipVertices, meshinfo_out.numVertices);
#else
                rdCamera_g_pCurCamera->pfProjectList(sithRender_aTransformedClipVertices, sithRender_aClipVertices, meshinfo_out.numVertices);
#endif
                
                v31 = frustumArg;

                // no frustum culling if forced
                if (rdClip_g_faceStatus & (CLIPSTAT_NEAR|CLIPSTAT_NONE_VISIBLE))
                {
                    v31 = frustumArg;
                }
                else
                {
                    flex_t minX = FLT_MAX;
                    flex_t minY = FLT_MAX;
                    flex_t maxX = -FLT_MAX;
                    flex_t maxY = -FLT_MAX;
#ifdef TARGET_TWL
                    //flex_t minZ = FLT_MAX;
                    //flex_t maxZ = -FLT_MAX;
#endif
                    for (int i = 0; i < meshinfo_out.numVertices; i++)
                    {
                        flex_t v34 = sithRender_aTransformedClipVertices[i].x;
                        flex_t v57 = sithRender_aTransformedClipVertices[i].y;
                        flex_t v_z = sithRender_aTransformedClipVertices[i].z;
                        if (v34 < minX)
                            minX = v34;
                        if (v34 > maxX)
                            maxX = v34;

                        if (v57 < minY)
                            minY = v57;
                        if (v57 > maxY)
                            maxY = v57;
#ifdef TARGET_TWL
                        //minZ = stdMath_Min(v_z, minZ);
                        //maxZ = stdMath_Max(v_z, maxZ);
#endif
                    }

                    // Causes random black lines?
#ifdef RENDER_ROUND_VERTICES
                    flex_t v46 = stdMath_Ceil(minX);
                    flex_t v47 = stdMath_Ceil(minY);
                    flex_t v48 = stdMath_Ceil(maxX);
                    flex_t v49 = stdMath_Ceil(maxY);
#else
                    // Fixed
                    flex_t v46 = minX - 2.0;//stdMath_Ceil(minX);
                    flex_t v47 = minY - 2.0;//stdMath_Ceil(minY);
                    flex_t v48 = maxX + 1.5;
                    flex_t v49 = maxY + 1.5;
#endif

                    rdCamera_SetFrustrum(rdCamera_g_pCurCamera, &outClip, (int)(v46 - -0.5), (int)(v47 - -0.5), (int)v48, (int32_t)v49);
                    v31 = &outClip;

                    // TODO: Test against TODOA and verify if this is QOL-worthy
#ifdef TARGET_TWL
                    //v31->nearPlane = minZ - 0.1;
#endif
                }
                
                // Block backward traversal during depth-first search
                // TODO: Test against TODOA and verify if this is QOL-worthy
#ifdef TARGET_TWL
                // wtf is with this float?
                if (!(sithRender_renderflags & 4) || adjoinDistAdd < sithRender_f_82F4B0 ) {
                    if (depth > 2) {
                        sithRender_KindaClip(adjoinIter->sector, v31, adjoinDistAdd, depth+1);    
                    }
                    else {
                        sithRender_BuildVisibleSectorList(adjoinIter->sector, v31, adjoinDistAdd, depth+1);
                    }
                }
#else
                // wtf is with this float?
                if (!(sithRender_renderflags & 4) || adjoinDistAdd < sithRender_f_82F4B0 ) {
                    sithRender_BuildVisibleSectorList(adjoinIter->sector, v31, adjoinDistAdd, depth+1);
                }
#endif
            }
        }
    }
    sector->clipVisited = v45;
}

#ifdef TARGET_TWL
// TODO: clean this up of ifdefs
void sithRender_NoClip(SithSector *sector, rdClipFrustum *frustumArg, flex_t prevAdjoinDistAdd, int depth)
{
    int v5; // ecx
    rdClipFrustum *frustum; // edx
    SithThing *thing; // esi
    unsigned int lightIdx; // ecx
    SithSurfaceAdjoin *adjoinIter; // ebx
    SithSurface *adjoinSurface; // esi
    rdMaterial *adjoinMat; // eax
    rdVector3 *v20; // eax
    int v25; // eax
    unsigned int v27; // edi
    rdClipFrustum *v31; // ecx
    rdClipFrustum outClip; // [esp+Ch] [ebp-74h] BYREF
    rdVector3 vertex_out; // [esp+40h] [ebp-40h] BYREF
    int v45; // [esp+4Ch] [ebp-34h]
    rdTexinfo *v51; // [esp+64h] [ebp-1Ch]

    // Clip visited hardening
    // Does not help much, but no visual harm either
#ifdef QOL_IMPROVEMENTS
    if (sector->clipVisited == sithRender_lastRenderTick || sector->renderTick == sithRender_lastRenderTick) {
        sector->pClipFrustum = rdCamera_g_pCurCamera->pClipFrustum;
        return;
    }
#endif

    if ( sector->renderTick == sithRender_lastRenderTick )
    {
        sector->pClipFrustum = rdCamera_g_pCurCamera->pClipFrustum;
    }
    else
    {
        //stdPlatform_Printf("Render sector %u %x %u\n", sector->id, sithRender_lastRenderTick, depth);

        sector->renderTick = sithRender_lastRenderTick;
        sector->clipVisited = 0;

        // Added: Prevent crashing
        if (sithRender_g_numVisibleSectors >= SITH_MAX_VISIBLE_SECTORS) {
            jk_printf("OpenJKDF2: Hit max visible sectors.\n");
            return;
        }

        // Added: Prevent crashing
        if (sithRender_numSecorFrustrums >= SITH_MAX_VISIBLE_SECTORS) {
            jk_printf("OpenJKDF2: Hit max visible sector clip frustums.\n");
            return;
        }

        // Added: Prevent crashing
        if (sithRender_numThingSectors >= SITH_MAX_VISIBLE_SECTORS_2) {
            jk_printf("OpenJKDF2: Hit max visible sectors (2).\n");
            return;
        }

        sithRender_aVisibleSectors[sithRender_g_numVisibleSectors++] = sector;
        if (!(sector->flags & SITH_SECTOR_SEEN) && !(g_debugmodeFlags & DEBUGFLAG_NOCLIP)) // Added: don't send sighted stuff in noclip, otherwise the whole map reveals
        {
            sector->flags |= SITH_SECTOR_SEEN;
            if ( (sector->flags & SITH_SECTOR_COGLINKED) != 0 )
                sithCog_SectorSendMessage(sector, 0, SITH_MESSAGE_SIGHTED);
        }
        frustum = &sithRender_aSectorFrustrums[sithRender_numSecorFrustrums++];
        _memcpy(frustum, frustumArg, sizeof(rdClipFrustum));
        thing = sector->pFirstThingInSector;
        //sector->pClipFrustum = frustum;
        sector->pClipFrustum = rdCamera_g_pCurCamera->pClipFrustum;
        lightIdx = sithRender_numThingLights;

        // Added: safety
        int safeguard = 0;
        while ( thing )
        {
            if ( lightIdx >= 0x20 )
                break;

            // Added: safety
            if (++safeguard >= SITH_MAX_THINGS)
                break;

            // Debug, add extra light from player
#if 0
            if (thing->type == SITH_THING_PLAYER)
            {
                rdMatrix_TransformPoint34(&vertex_out, &thing->actorParams.lightOffset, &thing->orient);
                rdVector_Add3Acc(&vertex_out, &thing->position);
                sithRender_aThingLights[sithRender_numThingLights].intensity = 1.0;//thing->actorParams.lightIntensity;
                rdCamera_AddLight(rdCamera_g_pCurCamera, &sithRender_aThingLights[sithRender_numThingLights], &vertex_out);
                lightIdx = ++sithRender_numThingLights;
            }
#endif

            if ((thing->flags & SITH_TF_EMITLIGHT)
                 && !(thing->flags & (SITH_TF_DISABLED|SITH_TF_10|SITH_TF_DESTROYED)))
            {
                if ( thing->light > 0.0 )
                {
                    sithRender_aThingLights[lightIdx].intensity = thing->light;
                    rdCamera_AddLight(rdCamera_g_pCurCamera, &sithRender_aThingLights[lightIdx], &thing->position);
                    lightIdx = ++sithRender_numThingLights;
                }

                if ( (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER) && lightIdx < 0x20 )
                {
                    if ( (thing->actorParams.flags & SITH_AF_HEADLIGHT) != 0 && thing->actorParams.lightIntensity > 0.0 )
                    {
                        rdMatrix_TransformPoint34(&vertex_out, &thing->actorParams.lightOffset, &thing->orient);
                        rdVector_Add3Acc(&vertex_out, &thing->position);
                        sithRender_aThingLights[sithRender_numThingLights].intensity = thing->actorParams.lightIntensity;
                        rdCamera_AddLight(rdCamera_g_pCurCamera, &sithRender_aThingLights[sithRender_numThingLights], &vertex_out);
                        lightIdx = ++sithRender_numThingLights;
                    }
                    if ( thing->actorParams.timeLeftLengthChange > 0.0 )
                    {
                        sithRender_aThingLights[lightIdx].intensity = thing->actorParams.timeLeftLengthChange;
                        rdCamera_AddLight(rdCamera_g_pCurCamera, &sithRender_aThingLights[lightIdx], &thing->actorParams.saberBladePos);
                        lightIdx = ++sithRender_numThingLights;
                    }
                }
            }
            thing = thing->pNextThingInSector;
        }
        sithRender_aThingSectors[sithRender_numThingSectors++] = sector;
    }

    // Added: noclip
    if (sithPlayer_bNoClippingRend) return;
    
    //v45 = sector->clipVisited;

    // Clip visited hardening
#ifdef QOL_IMPROVEMENTS
    sector->clipVisited = sithRender_lastRenderTick;
#else
    sector->clipVisited = 1;
#endif

    // Added: safeguard
    for (adjoinIter = sector->adjoins ; adjoinIter != NULL; adjoinIter = adjoinIter->next)
    {
        // Clip visited hardening
        if (adjoinIter->sector->clipVisited == sithRender_lastRenderTick)
        {
            continue;
        }

        // Added: safeguard
        if (++sithRender_adjoinSafeguard >= 0x100000) {
            stdPlatform_Printf("Hit safeguard...\n");
            break;
        }

        adjoinSurface = adjoinIter->surface;

        v20 = &sithWorld_g_pCurrentWorld->aVertices[*adjoinSurface->surfaceInfo.face.vertexPosIdx];
        flex_t dist = rdMath_DistancePointToPlane(&sithCamera_g_pCurCamera->lookPos, &adjoinSurface->surfaceInfo.face.normal, v20);
        flex_t adjoinDistAdd = adjoinIter->dist + adjoinIter->mirror->dist + prevAdjoinDistAdd;

        // Avoid rendering adjoins if they're far enough away
#ifdef TARGET_TWL
        // adjoinDistAdd compare GREATLY reduces recursion issues 
        // TODO: Test against TODOA and verify if this is QOL-worthy
        if (/*(adjoinDistAdd > 3.5) ||*/ (dist > SITHCAMERA_ZFAR) /*|| dist < sector->pClipFrustum->nearPlane*/) {
            // Doesn't help, causes visual issues
            //adjoinIter->sector->clipVisited = sithRender_lastRenderTick;

            continue;
        }
        if ((sithRender_renderflags & 4) && adjoinDistAdd >= sithRender_f_82F4B0) {
            continue;
        }
#endif

        if ( dist > 0.0 || (dist == 0.0 && sector == sithCamera_g_pCurCamera->sector))
        {
            adjoinMat = adjoinSurface->surfaceInfo.face.material;
            if ( adjoinMat )
            {
                int v19 = adjoinSurface->surfaceInfo.face.wallCel;
                if ( v19 == -1 )
                    v19 = adjoinMat->curCelNum;
                v51 = adjoinMat->texinfos[v19]; 
            }
            else {
                v51 = NULL; // Added. TODO: does setting this to NULL cause issues?
            }

            int bAdjoinIsTransparent = (((!adjoinSurface->surfaceInfo.face.material ||
                        (adjoinSurface->surfaceInfo.face.geometryMode == 0)) ||
                       ((adjoinSurface->surfaceInfo.face.type & 2))) ||
                      (v51 && (v51->header.texture_type & 8) && (v51->texture_ptr && v51->texture_ptr->alpha_en & 1)) // Added: v51->texture_ptr check
                      );

#ifdef QOL_IMPROVEMENTS
            // Added: Somehow the clipping changed enough to cause a bug in MoTS Lv12.
            // The ground under the water surface somehow renders.
            // As a mitigation, if a mirror surface is transparent but the top-layer isn't,
            // we will render underneath anyways.
            SithSurface* adjoinMirrorSurface = adjoinIter->mirror->surface;
            rdMaterial* adjoinMirrorMat = adjoinMirrorSurface->surfaceInfo.face.material;
            rdTexinfo* adjoinMirrorTexinfo = NULL;
            if ( adjoinMirrorMat )
            {
                int v19 = adjoinMirrorSurface->surfaceInfo.face.wallCel;
                if ( v19 == -1 )
                    v19 = adjoinMirrorMat->curCelNum;
                adjoinMirrorTexinfo = adjoinMirrorMat->texinfos[v19]; 
            }
            else {
                adjoinMirrorTexinfo = NULL; // Added. TODO: does setting this to NULL cause issues?
            }

            int bMirrorAdjoinIsTransparent = (((!adjoinMirrorSurface->surfaceInfo.face.material ||
                        (adjoinMirrorSurface->surfaceInfo.face.geometryMode == RD_GEOMETRY_NONE)) ||
                       ((adjoinMirrorSurface->surfaceInfo.face.type & 2))) ||
                      (adjoinMirrorTexinfo && (adjoinMirrorTexinfo->header.texture_type & 8) && (adjoinMirrorTexinfo->texture_ptr && adjoinMirrorTexinfo->texture_ptr->alpha_en & 1))
                      );

            bAdjoinIsTransparent |= bMirrorAdjoinIsTransparent;
#endif

            if ((adjoinIter->flags & 1) && bAdjoinIsTransparent) 
            {
                v31 = frustumArg;
                
                v31 = &outClip;
                outClip = *frustumArg;
                
                // wtf is with this float?
                if (!(sithRender_renderflags & 4) || adjoinDistAdd < sithRender_f_82F4B0 ) {
                    //stdPlatform_Printf("Render sector %u %x %u\n", adjoinIter->sector->id, sithRender_lastRenderTick, depth);
                    sithRender_NoClip(adjoinIter->sector, v31, adjoinDistAdd, depth+1);
                }
            }
        }
    }
    //sector->clipVisited = v45;
}
#endif

void sithRender_KindaClipAssignFrustum(SithSector *sector, rdClipFrustum *frustumArg, int depth, int parentSector)
{
    int v5; // ecx
    rdClipFrustum *frustum; // edx
    SithThing *thing; // esi
    unsigned int lightIdx; // ecx
    SithSurfaceAdjoin *adjoinIter; // ebx
    SithSurface *adjoinSurface; // esi
    rdMaterial *adjoinMat; // eax
    rdVector3 *v20; // eax
    int v25; // eax
    unsigned int v27; // edi
    rdClipFrustum *v31; // ecx
    rdClipFrustum outClip; // [esp+Ch] [ebp-74h] BYREF
    rdVector3 vertex_out; // [esp+40h] [ebp-40h] BYREF
    int v45; // [esp+4Ch] [ebp-34h]
    rdTexinfo *v51; // [esp+64h] [ebp-1Ch]

#if 0
    for (int i = 0; i < depth; i++) {
        printf("    ");
    }
    printf("- %d (%d)\n", sector->id, parentSector);
#endif

    if ( sector->renderTick == sithRender_lastRenderTick )
    {
        return;
    }
    
    sector->renderTick = sithRender_lastRenderTick;
    sector->clipVisited = 0;

    // Added: Prevent crashing
    if (sithRender_g_numVisibleSectors >= SITH_MAX_VISIBLE_SECTORS) {
        jk_printf("OpenJKDF2: Hit max visible sectors.\n");
        return;
    }

    // Added: Prevent crashing
    if (sithRender_numSecorFrustrums >= SITH_MAX_VISIBLE_SECTORS) {
        jk_printf("OpenJKDF2: Hit max visible sector clip frustums.\n");
        return;
    }

    // Added: Prevent crashing
    if (sithRender_numThingSectors >= SITH_MAX_VISIBLE_SECTORS_2) {
        jk_printf("OpenJKDF2: Hit max visible sectors (2).\n");
        return;
    }

    sithRender_aVisibleSectors[sithRender_g_numVisibleSectors++] = sector;
    if (!(sector->flags & SITH_SECTOR_SEEN) && !(g_debugmodeFlags & DEBUGFLAG_NOCLIP)) // Added: don't send sighted stuff in noclip, otherwise the whole map reveals
    {
        sector->flags |= SITH_SECTOR_SEEN;
        if ( (sector->flags & SITH_SECTOR_COGLINKED) != 0 )
            sithCog_SectorSendMessage(sector, 0, SITH_MESSAGE_SIGHTED);
    }
    frustum = &sithRender_aSectorFrustrums[sithRender_numSecorFrustrums++];
    _memcpy(frustum, frustumArg, sizeof(rdClipFrustum));
    thing = sector->pFirstThingInSector;
    sector->pClipFrustum = frustum;
    //sector->pClipFrustum = rdCamera_g_pCurCamera->pClipFrustum;
    lightIdx = sithRender_numThingLights;

    // Added: safety
    int safeguard = 0;
    while ( thing )
    {
        if ( lightIdx >= 0x20 )
            break;

        // Added: safety
        if (++safeguard >= SITH_MAX_THINGS)
            break;

        if ((thing->flags & SITH_TF_EMITLIGHT)
             && !(thing->flags & (SITH_TF_DISABLED|SITH_TF_10|SITH_TF_DESTROYED)))
        {
            if ( thing->light > 0.0 )
            {
                sithRender_aThingLights[lightIdx].intensity = thing->light;
                rdCamera_AddLight(rdCamera_g_pCurCamera, &sithRender_aThingLights[lightIdx], &thing->position);
                lightIdx = ++sithRender_numThingLights;
            }

            if ( (thing->type == SITH_THING_ACTOR || thing->type == SITH_THING_PLAYER) && lightIdx < 0x20 )
            {
                if ( (thing->actorParams.flags & SITH_AF_HEADLIGHT) != 0 && thing->actorParams.lightIntensity > 0.0 )
                {
                    rdMatrix_TransformPoint34(&vertex_out, &thing->actorParams.lightOffset, &thing->orient);
                    rdVector_Add3Acc(&vertex_out, &thing->position);
                    sithRender_aThingLights[sithRender_numThingLights].intensity = thing->actorParams.lightIntensity;
                    rdCamera_AddLight(rdCamera_g_pCurCamera, &sithRender_aThingLights[sithRender_numThingLights], &vertex_out);
                    lightIdx = ++sithRender_numThingLights;
                }
                if ( thing->actorParams.timeLeftLengthChange > 0.0 )
                {
                    sithRender_aThingLights[lightIdx].intensity = thing->actorParams.timeLeftLengthChange;
                    rdCamera_AddLight(rdCamera_g_pCurCamera, &sithRender_aThingLights[lightIdx], &thing->actorParams.saberBladePos);
                    lightIdx = ++sithRender_numThingLights;
                }
            }
        }
        thing = thing->pNextThingInSector;
    }
    sithRender_aThingSectors[sithRender_numThingSectors++] = sector;
}

void sithRender_KindaClip(SithSector *sector, rdClipFrustum *frustumArg, flex_t prevAdjoinDistAdd, int depth)
{
    int v5; // ecx
    rdClipFrustum *frustum; // edx
    SithThing *thing; // esi
    unsigned int lightIdx; // ecx
    SithSurfaceAdjoin *adjoinIter; // ebx
    SithSurface *adjoinSurface; // esi
    rdMaterial *adjoinMat; // eax
    rdVector3 *v20; // eax
    int v25; // eax
    unsigned int v27; // edi
    rdClipFrustum *v31; // ecx
    rdClipFrustum outClip; // [esp+Ch] [ebp-74h] BYREF
    rdVector3 vertex_out; // [esp+40h] [ebp-40h] BYREF
    int v45; // [esp+4Ch] [ebp-34h]
    rdTexinfo *v51; // [esp+64h] [ebp-1Ch]

    /*for (int i = 0; i < depth; i++) {
        printf("    ");
    }
    printf("- %d\n", sector->id);*/
    
    v45 = sector->clipVisited;

    // Clip visited hardening
    sector->clipVisited = sithRender_lastRenderTick;

    // Added: safeguard
    for (adjoinIter = sector->adjoins ; adjoinIter != NULL; adjoinIter = adjoinIter->next)
    {
        if (adjoinIter->sector->clipVisited == sithRender_lastRenderTick)
        {
            //*adjoinIter->sector->pClipFrustum = *rdCamera_g_pCurCamera->pClipFrustum;
            continue;
        }

        // Added: safeguard
        if (++sithRender_adjoinSafeguard >= 0x100000) {
            stdPlatform_Printf("Hit safeguard...\n");
            break;
        }

        adjoinSurface = adjoinIter->surface;

        v20 = &sithWorld_g_pCurrentWorld->aVertices[*adjoinSurface->surfaceInfo.face.vertexPosIdx];
        flex_t dist = rdMath_DistancePointToPlane(&sithCamera_g_pCurCamera->lookPos, &adjoinSurface->surfaceInfo.face.normal, v20);
        flex_t adjoinDistAdd = adjoinIter->dist /*+ adjoinIter->mirror->dist*/ + prevAdjoinDistAdd;

        // Avoid rendering adjoins if they're far enough away
#ifdef TARGET_TWL
        // adjoinDistAdd compare GREATLY reduces recursion issues 
        // TODO: Test against TODOA and verify if this is QOL-worthy
        if (/*(adjoinDistAdd > 3.5) ||*/ (dist > SITHCAMERA_ZFAR) /*|| dist < sector->pClipFrustum->nearPlane*/) {
            // Doesn't help, causes visual issues
            //adjoinIter->sector->clipVisited = sithRender_lastRenderTick;

            // Assume the frustums have gone to shit
            adjoinIter->sector->pClipFrustum = rdCamera_g_pCurCamera->pClipFrustum;
            continue;
        }
        if ((sithRender_renderflags & 4) && adjoinDistAdd >= sithRender_f_82F4B0 && depth > 4) {
            // Assume the frustums have gone to shit
            *frustumArg = *rdCamera_g_pCurCamera->pClipFrustum;
            adjoinIter->sector->pClipFrustum = rdCamera_g_pCurCamera->pClipFrustum;
            continue;
        }
#endif

        if ( dist > 0.0 || (dist == 0.0 && sector == sithCamera_g_pCurCamera->sector))
        {
            adjoinMat = adjoinSurface->surfaceInfo.face.material;
            if ( adjoinMat )
            {
                int v19 = adjoinSurface->surfaceInfo.face.wallCel;
                if ( v19 == -1 )
                    v19 = adjoinMat->curCelNum;
                v51 = adjoinMat->texinfos[v19]; 
            }
            else {
                v51 = NULL; // Added. TODO: does setting this to NULL cause issues?
            }

            int bAdjoinIsTransparent = (((!adjoinSurface->surfaceInfo.face.material ||
                        (adjoinSurface->surfaceInfo.face.geometryMode == 0)) ||
                       ((adjoinSurface->surfaceInfo.face.type & 2))) ||
                      (v51 && (v51->header.texture_type & 8) && (v51->texture_ptr && v51->texture_ptr->alpha_en & 1)) // Added: v51->texture_ptr check
                      );

#ifdef QOL_IMPROVEMENTS
            // Added: Somehow the clipping changed enough to cause a bug in MoTS Lv12.
            // The ground under the water surface somehow renders.
            // As a mitigation, if a mirror surface is transparent but the top-layer isn't,
            // we will render underneath anyways.
            SithSurface* adjoinMirrorSurface = adjoinIter->mirror->surface;
            rdMaterial* adjoinMirrorMat = adjoinMirrorSurface->surfaceInfo.face.material;
            rdTexinfo* adjoinMirrorTexinfo = NULL;
            if ( adjoinMirrorMat )
            {
                int v19 = adjoinMirrorSurface->surfaceInfo.face.wallCel;
                if ( v19 == -1 )
                    v19 = adjoinMirrorMat->curCelNum;
                adjoinMirrorTexinfo = adjoinMirrorMat->texinfos[v19]; 
            }
            else {
                adjoinMirrorTexinfo = NULL; // Added. TODO: does setting this to NULL cause issues?
            }

            int bMirrorAdjoinIsTransparent = (((!adjoinMirrorSurface->surfaceInfo.face.material ||
                        (adjoinMirrorSurface->surfaceInfo.face.geometryMode == RD_GEOMETRY_NONE)) ||
                       ((adjoinMirrorSurface->surfaceInfo.face.type & 2))) ||
                      (adjoinMirrorTexinfo && (adjoinMirrorTexinfo->header.texture_type & 8) && (adjoinMirrorTexinfo->texture_ptr && adjoinMirrorTexinfo->texture_ptr->alpha_en & 1))
                      );

            bAdjoinIsTransparent |= bMirrorAdjoinIsTransparent;

            // Added: When swimming, sometimes the camera dips below the water. 
            // Consider the pAdjoin transparent if we are very close to it.
            bAdjoinIsTransparent |= (dist < 0.01);
#endif

            if (LIKELY((adjoinIter->flags & 1) && bAdjoinIsTransparent))
            {
#ifdef SITHRENDER_SPHERE_TEST_SURFACES
                BOOL bKeepFullFrustum = 0;
                flex_t radius = adjoinSurface->radius;
                rdVector3 centerTrans = adjoinSurface->center;
                rdClipFrustum* pSphereFrustum = frustumArg;//rdCamera_g_pCurCamera->pClipFrustum;//frustumArg;
                rdMatrix_TransformPoint34Acc(&centerTrans, &rdCamera_g_pCurCamera->orient);

                int clipResult = rdClip_SphereInFrustrum(pSphereFrustum, &centerTrans, radius);

                // Try to guess if the sphere is actually encapsulating the camera
                if (UNLIKELY((dist - radius) < 0.0 || (dist + radius) >= rdCamera_g_pCurCamera->pClipFrustum->farPlane || (radius * 2.0) >= 2.5 || dist < 0.01)) {
                    clipResult = SPHERE_CLIPPING_EDGE;
                    bKeepFullFrustum = 1;
                }

                // Just in case?
                if (radius == 0.0) {
                    clipResult = SPHERE_CLIPPING_EDGE;
                }

                if (LIKELY(clipResult == SPHERE_FULLY_OUTSIDE)) {

#if 0
                    // Double-check if the sphere is encapsulating the frustum
                    clipResult = rdClip_SphereInFrustrum(pSphereFrustum, &centerTrans, 0.0);
                    if (clipResult == SPHERE_FULLY_OUTSIDE) {
#if 0
                        for (int i = 0; i < depth+1; i++) {
                            printf("    ");
                        }
                        printf("- toss %d (%d)\n", adjoinIter->sector->id, sector->id);
#endif
                        continue;
                    }
                    else {
                        clipResult = SPHERE_CLIPPING_EDGE;
                        bKeepFullFrustum = 1;
                    }
#endif

#if 0
                    for (int i = 0; i < depth+1; i++) {
                        printf("    ");
                    }
                    printf("- toss %d (%d)\n", adjoinIter->sector->id, sector->id);
#endif
                    continue;
                    
                }

                //sithRender_RenderDebugLight2(adjoinSurface->radius * 50.0, &adjoinSurface->center, &adjoinSurface->surfaceInfo.face.normal);

                v31 = &outClip;
                outClip = *frustumArg;

                // no frustum culling if forced
                if (bKeepFullFrustum)
                {
                    //v31 = frustumArg;
                    v31 = &outClip;
                    outClip = *rdCamera_g_pCurCamera->pClipFrustum;//*frustumArg;
                }

                if (LIKELY(adjoinSurface->field_4 != sithRender_lastRenderTick))
                {
                    for (int i = 0; i < adjoinSurface->surfaceInfo.face.numVertices; i++)
                    {
                        v25 = adjoinSurface->surfaceInfo.face.vertexPosIdx[i];
                        if (LIKELY(sithWorld_g_pCurrentWorld->alloc_unk98[v25] != sithRender_lastRenderTick))
                        {
                            rdMatrix_TransformPoint34(&sithWorld_g_pCurrentWorld->aTransformedVertices[v25], &sithWorld_g_pCurrentWorld->aVertices[v25], &rdCamera_g_pCurCamera->orient);
                            sithWorld_g_pCurrentWorld->alloc_unk98[v25] = sithRender_lastRenderTick;
                        }
                    }
                    adjoinSurface->field_4 = sithRender_lastRenderTick;
                }

                flex_t viewportWidth = rdCamera_g_pCurCamera->pCanvas->half_screen_width*2;
                flex_t viewportHeight = rdCamera_g_pCurCamera->pCanvas->half_screen_height*2;
                flex_t minX = FLT_MAX;
                flex_t minY = FLT_MAX;
                flex_t maxX = -FLT_MAX;
                flex_t maxY = -FLT_MAX;

                flex_t leftLimit = outClip.farLeft;
                flex_t rightLimit = outClip.right;
                flex_t bottomLimit = outClip.bottom;
                flex_t topLimit = outClip.farTop;

                // If we've visited before, grow the frustum
                if (UNLIKELY(adjoinIter->sector->renderTick == sithRender_lastRenderTick))
                {
                    leftLimit = stdMath_Min(adjoinIter->sector->pClipFrustum->farLeft, leftLimit);
                    rightLimit = stdMath_Max(adjoinIter->sector->pClipFrustum->right, rightLimit);
                    bottomLimit = stdMath_Min(adjoinIter->sector->pClipFrustum->bottom, bottomLimit);
                    topLimit = stdMath_Max(adjoinIter->sector->pClipFrustum->farTop, topLimit);
                }

                for (int i = 0; i < adjoinSurface->surfaceInfo.face.numVertices; i++) {
                    v25 = adjoinSurface->surfaceInfo.face.vertexPosIdx[i];
                    rdVector3* pVertIter = &sithWorld_g_pCurrentWorld->aTransformedVertices[v25];
                    flex_t iterX = pVertIter->x;
                    flex_t iterY = pVertIter->y;
                    flex_t iterZ = pVertIter->z;

                    iterY = stdMath_Max(iterY, (flex_t)0.001);
                    flex_t fov_y_calc = (1.0 / iterY);
                    flex_t projX = (iterX * fov_y_calc);
                    flex_t projY =  (iterZ * fov_y_calc);
                    
                    projX = stdMath_Clamp(projX, leftLimit, rightLimit);
                    projY = stdMath_Clamp(projY, bottomLimit, topLimit);

                    minX = stdMath_Min(minX, projX);
                    maxX = stdMath_Max(maxX, projX);
                    minY = stdMath_Min(minY, projY);
                    maxY = stdMath_Max(maxY, projY);
                }

                if (UNLIKELY(minX == maxX || minY == maxY)) {
                    *v31 = *rdCamera_g_pCurCamera->pClipFrustum;
#if 0
                    printf("aaaaaa2 %d in %d, depth %d, %f %f %f %f\n", adjoinIter->sector->id, sector->id, depth, minX, maxX, minY, maxY);
#endif

                    if (UNLIKELY(adjoinIter->sector->renderTick == sithRender_lastRenderTick && !bKeepFullFrustum))
                    {
                        int lastClipVisited = adjoinIter->sector->clipVisited;
                        adjoinIter->sector->clipVisited = 0;
                        sithRender_KindaClip(adjoinIter->sector, adjoinIter->sector->pClipFrustum, adjoinDistAdd, depth+1);
                        adjoinIter->sector->clipVisited = sithRender_lastRenderTick;
                    }
                }
                else {
                    v31->farLeft = minX;
                    v31->nearLeft = minX;
                    v31->right = maxX;

                    v31->farTop = maxY;
                    v31->nearTop = maxY;
                    v31->bottom = minY;
                }
#else // SITHRENDER_SPHERE_TEST_SURFACES
                v31 = &outClip;
                outClip = *frustumArg;
#endif

                // Assign the grown frustum and don't iterate deeper
                if (UNLIKELY(adjoinIter->sector->renderTick == sithRender_lastRenderTick))
                {
                    rdClipFrustum* pFrustumPrior = adjoinIter->sector->pClipFrustum;
                    v31->farTop   = stdMath_Max(v31->farTop, pFrustumPrior->farTop);
                    v31->bottom   = stdMath_Min(v31->bottom, pFrustumPrior->bottom);
                    v31->farLeft  = stdMath_Min(v31->farLeft, pFrustumPrior->farLeft);
                    v31->right    = stdMath_Max(v31->right, pFrustumPrior->right);
                    v31->nearTop  = stdMath_Max(v31->nearTop, pFrustumPrior->nearTop);
                    v31->nearLeft = stdMath_Min(v31->nearLeft, pFrustumPrior->nearLeft);
                    //printf("     %f %f %f %f -> %f %f %f %f\n", (flex32_t)adjoinIter->sector->pClipFrustum->farLeft, (flex32_t)adjoinIter->sector->pClipFrustum->right, (flex32_t)adjoinIter->sector->pClipFrustum->bottom, (flex32_t)adjoinIter->sector->pClipFrustum->farTop, (flex32_t)v31->farLeft, (flex32_t)v31->right, (flex32_t)v31->bottom, (flex32_t)v31->farTop);
                    
                    //*adjoinIter->sector->pClipFrustum = *rdCamera_g_pCurCamera->pClipFrustum;
                    
                    BOOL hasChanged =  v31->farTop != pFrustumPrior->farTop ||
                        v31->bottom != pFrustumPrior->bottom ||
                        v31->farLeft != pFrustumPrior->farLeft ||
                        v31->right != pFrustumPrior->right ||
                        v31->nearTop != pFrustumPrior->nearTop ||
                        v31->nearLeft != pFrustumPrior->nearLeft;

#if 0
                    for (int i = 0; i < depth+1; i++) {
                        printf("    ");
                    }
                    printf("- %d again (%d) %f %f %f %f -> %f %f %f %f, %s\n", adjoinIter->sector->id, sector->id, (flex32_t)adjoinIter->sector->pClipFrustum->farLeft, (flex32_t)adjoinIter->sector->pClipFrustum->right, (flex32_t)adjoinIter->sector->pClipFrustum->bottom, (flex32_t)adjoinIter->sector->pClipFrustum->farTop, (flex32_t)v31->farLeft, (flex32_t)v31->right, (flex32_t)v31->bottom, (flex32_t)v31->farTop, hasChanged ? "yes" : "no");
#endif

                    *adjoinIter->sector->pClipFrustum = *v31;
                    if (!hasChanged && depth > 3) {
                        adjoinIter->sector->clipVisited = sithRender_lastRenderTick;
                    }
                    else {
                        //if (depth > 3) {
                            *adjoinIter->sector->pClipFrustum = *rdCamera_g_pCurCamera->pClipFrustum;
                            //continue;
                        //}
                        //int lastClipVisited = adjoinIter->sector->clipVisited;
                        adjoinIter->sector->clipVisited = 0;
                        sithRender_KindaClip(adjoinIter->sector, adjoinIter->sector->pClipFrustum, adjoinDistAdd, depth+1);
                        //adjoinIter->sector->clipVisited = lastClipVisited;
                        adjoinIter->sector->clipVisited = sithRender_lastRenderTick;
                    }
                    continue;
                }
                
                sithRender_KindaClipAssignFrustum(adjoinIter->sector, v31, depth+1, sector->id);
                sithRender_KindaClip(adjoinIter->sector, adjoinIter->sector->pClipFrustum, adjoinDistAdd, depth+1);
            }
        }
    }

    sector->clipVisited = v45;
}

#ifdef SITHRENDER_SPHERE_TEST_SURFACES
// TODO: Non-DSi maximums
const flex_t frustMaxCoord = 1.5;
rdClipFrustum sithRender_absoluteMaxFrustum = {
    .bClipFar = 1,
    .nearPlane = SITHCAMERA_ZNEAR_FIRSTPERSON,
    .farPlane = SITHCAMERA_ZFAR,
    
    .orthoLeftPlane = -frustMaxCoord,
    .orthoTopPlane = frustMaxCoord,
    .orthoRightPlane = frustMaxCoord,
    .orthoBottomPlane = -frustMaxCoord,

    .farTop = frustMaxCoord,
    .bottom = -frustMaxCoord,
    .farLeft = -frustMaxCoord,
    .right = frustMaxCoord,
    .nearTop = frustMaxCoord,
    .nearLeft = -frustMaxCoord,
};
#endif

// MOTS altered
void sithRender_RenderSectors()
{
    rdVector2 *vertices_uvs; // edx
    rdVector3 *vertices_alloc; // esi
    rdTexinfo *v10; // ecx
    int v18; // ebx
    int v19; // ebp
    rdProcEntry *v20; // esi
    int v21; // eax
    rdLightMode_t lightMode2; // eax
    int v23; // ecx
    int v24; // eax
    unsigned int v28; // ebp
    flex_t v29; // ecx
    flex_t *v31; // eax
    unsigned int v32; // ecx
    flex_t *v33; // edx
    flex_d_t v34; // st7
    int v38; // ecx
    char v39; // al
    rdProcEntry *procEntry; // esi
    rdGeoMode_t geoMode; // eax
    rdLightMode_t lightMode; // eax
    rdTexMode_t texMode; // ecx
    rdTexMode_t texMode2; // eax
    unsigned int num_vertices; // ebp
    flex_t v49; // edx
    flex_t *v51; // eax
    unsigned int v52; // ecx
    flex_t *v53; // edx
    flex_d_t v54; // st7
    int flags; // eax
    int v57; // edx
    rdMaterial *v58; // ecx
    int v59; // ecx
    char rend_flags; // al
    SithThing *i; // esi
    int v63; // eax
    rdTexMode_t texMode3; // [esp-10h] [ebp-74h]
    SithSurface *v65; // [esp+10h] [ebp-54h]
    flex_t v66; // [esp+14h] [ebp-50h]
    flex_t v67; // [esp+14h] [ebp-50h]
    BOOL v68; // [esp+18h] [ebp-4Ch]
    SithSector *level_idk; // [esp+1Ch] [ebp-48h]
    flex_t a2; // [esp+20h] [ebp-44h]
    int v71; // [esp+24h] [ebp-40h]
    int v72; // [esp+28h] [ebp-3Ch]
    rdTexinfo *v73; // [esp+2Ch] [ebp-38h]
    int v74; // [esp+30h] [ebp-34h]
    int v75; // [esp+34h] [ebp-30h]
    signed int v76; // [esp+38h] [ebp-2Ch]
    rdClipFrustum *pFullCameraFrustum; // [esp+3Ch] [ebp-28h]
    int v78[3]; // [esp+40h] [ebp-24h] BYREF
    int v79[3]; // [esp+4Ch] [ebp-18h] BYREF
    flex_t v80[3]; // [esp+58h] [ebp-Ch] BYREF
    flex_t tmpBlue[3];
    flex_t tmpGreen[3];

#ifdef EXPERIMENTAL_FIXED_POINT
    int skip_this_surface = 1;
#endif
#ifdef TARGET_TWL
    rdroid_curAcceleration = 1;
    sithRender_renderflags &= ~0x8; // Drops render time by 2/3 by rendering by n-gons instead of tris
#endif

    if (LIKELY(rdroid_curAcceleration))
    {
        rdSetZBufferMethod(RD_ZBUFFER_READ_WRITE);
        if (sithRender_renderflags & 0x80) {
            rdSetVertexColorMode(1);
        }
    }
    else
    {
        rdSetZBufferMethod(RD_ZBUFFER_NOREAD_WRITE);
        if ( (sithRender_renderflags & 0x20) != 0 )
            rdSetOcclusionMethod(0);
        else
            rdSetOcclusionMethod(1);
        rdSetVertexColorMode(0);
    }
    rdSetSortingMethod(0);

#ifdef TARGET_TWL
    //rdSetVertexColorMode(0);
    //sithRender_SetLightingMode(RD_LIGHTMODE_DIFFUSE);
    //printf("%x %x %x %x\n", rdroid_curVertexColorMode, sithRender_renderflags, rdroid_curAcceleration, sithRender_lightMode);
#endif

    vertices_uvs = sithWorld_g_pCurrentWorld->aTexVerticies;
    sithRender_faceView.aVertices = sithWorld_g_pCurrentWorld->aTransformedVertices;
    sithRender_faceView.paDynamicLight = sithWorld_g_pCurrentWorld->aVertDynamicLights;
    sithRender_faceView.aTexVerticies = vertices_uvs;
    pFullCameraFrustum = rdCamera_g_pCurCamera->pClipFrustum;

    for (v72 = 0; v72 < sithRender_g_numVisibleSectors; v72++)
    {
        // Surfaces are 13ms on landing terminal spawn
        level_idk = sithRender_aVisibleSectors[v72];
#ifdef TARGET_TWL
        level_idk->clipVisited = 0;
        if (level_idk->geoRenderTick == sithRender_lastRenderTick) {
            continue;
        }
        level_idk->geoRenderTick = sithRender_lastRenderTick;
        //level_idk->pClipFrustum = rdCamera_g_pCurCamera->pClipFrustum;
#endif
        if (UNLIKELY(sithRender_lightingIRMode))
        {
            a2 = sithRender_f_83198C;
            rdCamera_SetAmbientLight(rdCamera_g_pCurCamera, sithRender_f_83198C);
        }
        else
        {
            flex_t baseLight = level_idk->ambientLight + level_idk->extraLight + sithRender_008d4098;
            a2 = stdMath_Clamp(baseLight, 0.0, 1.0);
            rdCamera_SetAmbientLight(rdCamera_g_pCurCamera, a2);
        }
        rdColormap_SetCurrent(level_idk->colormap);
        v68 = level_idk->colormap == sithWorld_g_pCurrentWorld->colormaps;
        rdSetProcFaceUserData(level_idk->id);
        v65 = level_idk->surfaces;

#if defined(TARGET_TWL) || defined(SITHRENDER_SPHERE_TEST_SURFACES) || defined(EXPERIMENTAL_FIXED_POINT)
        BOOL noDistCulling = (level_idk != sithCamera_g_pCurCamera->sector);
#endif
        rdClipFrustum* pSectorFrustum = level_idk->pClipFrustum;

        // Added: Removed the field_4 set?
        for (v75 = 0; v75 < level_idk->numSurfaces; /*v65->field_4 = sithRender_lastRenderTick,*/ ++v65, v75++)
        {
            rdClipFrustum* pSurfaceFrustum = pSectorFrustum;
            if (UNLIKELY(!v65->surfaceInfo.face.geometryMode))
                continue;
            vertices_alloc = sithWorld_g_pCurrentWorld->aVertices;

            BOOL bIsSkySurface = (v65->flags & (SITH_SURFACE_CEILING_SKY|SITH_SURFACE_HORIZON_SKY));
            flex_t dist = rdMath_DistancePointToPlane(&sithCamera_g_pCurCamera->lookPos, &v65->surfaceInfo.face.normal, &vertices_alloc[*v65->surfaceInfo.face.vertexPosIdx]);
            if (UNLIKELY(dist <= 0.0))
                continue;
#ifdef TARGET_TWL
            if (noDistCulling && dist > SITHCAMERA_ZFAR && !bIsSkySurface) {
                continue;
            }
#endif

            rdMaterial* surfaceMat = v65->surfaceInfo.face.material;
            if (LIKELY(surfaceMat))
            {
                if ( v65->surfaceInfo.face.wallCel == -1 )
                    v10 = surfaceMat->texinfos[surfaceMat->curCelNum];
                else
                    v10 = surfaceMat->texinfos[v65->surfaceInfo.face.wallCel];
                v73 = v10;
            }
            else
            {
#ifdef QOL_IMPROVEMENTS
                // Added? Avoid undefined behavior
                v73 = NULL;
#endif
                v10 = v73;
            }

#ifndef TARGET_TWL
            if ( v65->pAdjoin && surfaceMat && ((v65->surfaceInfo.face.type & 2) != 0 || (v10 && (v10->header.texture_type & 8)) && (v10 && v10->texture_ptr && (v10->texture_ptr->alpha_en & 1))) ) // Added: nullptr checks for v10 and v10->texture_ptr
            {
                if (sithRender_numAlphaAdjoins < SITH_MAX_VISIBLE_ALPHA_SURFACES)
                {
                    sithRender_aAlphaAdjoins[sithRender_numAlphaAdjoins++] = v65;
                }
                continue;
            }
#endif

#ifdef SITHRENDER_SPHERE_TEST_SURFACES
            int clipResult = SPHERE_CLIPPING_EDGE; 
            if (LIKELY(/*noDistCulling &&*/ !bIsSkySurface))
            {
                rdVector3 centerTrans = v65->center;
                rdClipFrustum* pSphereFrustum = pSurfaceFrustum;

                rdMatrix_TransformPoint34Acc(&centerTrans, &rdCamera_g_pCurCamera->orient);

                clipResult = rdClip_SphereInFrustrum(pSphereFrustum, &centerTrans, v65->radius);

                /*if (sithRender_lastRenderTick & 1) {
                    clipResult = SPHERE_CLIPPING_EDGE;
                }*/
                if (UNLIKELY(v65->radius * 2.0 > rdCamera_g_pCurCamera->pClipFrustum->farPlane)) {
                    clipResult = SPHERE_CLIPPING_EDGE;
                    //pSurfaceFrustum = rdCamera_g_pCurCamera->pClipFrustum;
                }
                else if (clipResult == SPHERE_CLIPPING_EDGE) {

                    // Run a second check to see if we can have hardware clip for us
                    // (mostly pertinent on fixed-pt 3D hardware like DSi)
                    clipResult = rdClip_SphereInFrustrum(&sithRender_absoluteMaxFrustum, &centerTrans, v65->radius);
                }

                if (LIKELY(clipResult == SPHERE_FULLY_OUTSIDE)) {
                    continue;
                }

                //pSurfaceFrustum = &sithRender_absoluteMaxFrustum;
                pSurfaceFrustum = rdCamera_g_pCurCamera->pClipFrustum;
            }
            else {
                //pSurfaceFrustum = &sithRender_absoluteMaxFrustum;
                pSurfaceFrustum = rdCamera_g_pCurCamera->pClipFrustum;
            }
#endif

            if (LIKELY(v65->field_4 != sithRender_lastRenderTick))
            {
                for (int j = 0; j < v65->surfaceInfo.face.numVertices; j++)
                {
                    int idx = v65->surfaceInfo.face.vertexPosIdx[j];
                    if (LIKELY(sithWorld_g_pCurrentWorld->alloc_unk98[idx] != sithRender_lastRenderTick))
                    {
                        rdMatrix_TransformPoint34(&sithWorld_g_pCurrentWorld->aTransformedVertices[idx], &sithWorld_g_pCurrentWorld->aVertices[idx], &rdCamera_g_pCurCamera->orient);
                        sithWorld_g_pCurrentWorld->alloc_unk98[idx] = sithRender_lastRenderTick;
                    }
                }
                v65->field_4 = sithRender_lastRenderTick;
            }

            // Render with N-Gons instead of triangle strips if flag 0x8 is unset, or if it's sky aVertices
            if (LIKELY((sithRender_renderflags & 8) == 0 || v65->surfaceInfo.face.numVertices <= 3 || bIsSkySurface || !v65->surfaceInfo.face.lightingMode))
            {
                procEntry = rdCache_GetProcEntry();
                if ( !procEntry )
                    continue;
                procEntry->light_level_static = 1.0; // Added?
                if (UNLIKELY(bIsSkySurface))
                {
                    geoMode = sithRender_geoMode;
                    if ( sithRender_geoMode > RD_GEOMETRY_SOLID)
                        geoMode = RD_GEOMETRY_SOLID;
                }
                else
                {
                    geoMode = v65->surfaceInfo.face.geometryMode;
                    if (UNLIKELY(geoMode >= sithRender_geoMode))
                        geoMode = sithRender_geoMode;
                }
                procEntry->geometryMode = geoMode;
                lightMode = v65->surfaceInfo.face.lightingMode;
                if (UNLIKELY(sithRender_lightingIRMode))
                {
                    if ( lightMode >= RD_LIGHTMODE_DIFFUSE)
                        lightMode = RD_LIGHTMODE_DIFFUSE;
                }
                else if (UNLIKELY(lightMode >= sithRender_lightMode))
                {
                    lightMode = sithRender_lightMode;
                }
                texMode = sithRender_texMode;
                procEntry->lightingMode = lightMode;
                texMode2 = v65->surfaceInfo.face.textureMode;
                if (UNLIKELY(texMode2 >= texMode))
                    texMode2 = texMode;
                procEntry->textureMode = texMode2;
                meshinfo_out.aVertices = sithRender_aClipVertices;
                meshinfo_out.paDynamicLight = procEntry->vertexIntensities;
                sithRender_faceView.vertexPosIdx = v65->surfaceInfo.face.vertexPosIdx;
                meshinfo_out.aTexVerticies = procEntry->aTexVerticies;
                sithRender_faceView.numVertices = v65->surfaceInfo.face.numVertices;
                texMode3 = texMode2;
                sithRender_faceView.vertexUVIdx = v65->surfaceInfo.face.vertexUVIdx;

                // MOTS added
                if (rdGetVertexColorMode() == 0) {
                    sithRender_faceView.intensities = v65->surfaceInfo.intensities;

                    // HACK: We adjust the sky Z later
#ifdef TARGET_TWL
                    if (bIsSkySurface) {
                        pSurfaceFrustum->bClipFar = 0;
                    }
#endif
#ifdef SITHRENDER_SPHERE_TEST_SURFACES
                    if (UNLIKELY(clipResult != SPHERE_FULLY_INSIDE)) {
#endif
                    rdPrimit3_ClipFace(pSurfaceFrustum, 
                                       procEntry->geometryMode, 
                                       procEntry->lightingMode, 
                                       texMode3, 
                                       &sithRender_faceView, 
                                       &meshinfo_out, 
                                       &v65->surfaceInfo.face.texVertOffset);
#ifdef SITHRENDER_SPHERE_TEST_SURFACES
                    } else {
                        rdPrimit3_NoClipFace(/*pSurfaceFrustum,*/ 
                                       procEntry->geometryMode, 
                                       procEntry->lightingMode, 
                                       texMode3, 
                                       &sithRender_faceView, 
                                       &meshinfo_out, 
                                       &v65->surfaceInfo.face.texVertOffset);
                    }
#endif
#ifdef TARGET_TWL
                    pSurfaceFrustum->bClipFar = 1;
#endif
                }
                else 
                {
                    if ((v65->flags & SITH_SURFACE_1000000) == 0) {
                        sithRender_faceView.paRedIntensities = (v65->surfaceInfo).intensities;
                        sithRender_faceView.paGreenIntensities = sithRender_faceView.paRedIntensities;
                        sithRender_faceView.paBlueIntensities = sithRender_faceView.paRedIntensities;
                    }
                    else {
                        sithRender_faceView.paRedIntensities =
                             (v65->surfaceInfo).intensities +
                             sithRender_faceView.numVertices;

                        sithRender_faceView.paGreenIntensities =
                             sithRender_faceView.paRedIntensities +
                             sithRender_faceView.numVertices;

                        sithRender_faceView.paBlueIntensities =
                             sithRender_faceView.paGreenIntensities +
                             sithRender_faceView.numVertices;
                    }
                    meshinfo_out.paGreenIntensities = procEntry->paGreenIntensities;
                    meshinfo_out.paRedIntensities = procEntry->paRedIntensities;
                    meshinfo_out.paBlueIntensities = procEntry->paBlueIntensities;

#ifdef TARGET_TWL
                    pSurfaceFrustum->bClipFar = !bIsSkySurface;
#endif
#ifdef SITHRENDER_SPHERE_TEST_SURFACES
                    if (clipResult != SPHERE_FULLY_INSIDE) {
#endif
                    rdPrimit3_ClipFaceRGBLevel
                              (pSurfaceFrustum,
                               procEntry->geometryMode,
                               procEntry->lightingMode,
                               texMode3,
                               &sithRender_faceView,
                               &meshinfo_out,
                               &(v65->surfaceInfo).face.texVertOffset);
#ifdef SITHRENDER_SPHERE_TEST_SURFACES
                    } else {
                        rdPrimit3_ClipFaceRGBLevel
                              (rdCamera_g_pCurCamera->pClipFrustum,
                               procEntry->geometryMode,
                               procEntry->lightingMode,
                               texMode3,
                               &sithRender_faceView,
                               &meshinfo_out,
                               &(v65->surfaceInfo).face.texVertOffset);

                        // TODO: Bugged?
                        /*rdPrimit3_NoClipFaceRGB
                              (/*pSurfaceFrustum,* /
                               procEntry->geometryMode,
                               procEntry->lightingMode,
                               texMode3,
                               &sithRender_faceView,
                               &meshinfo_out,
                               &(v65->surfaceInfo).face.texVertOffset);*/
                    }
#endif
#ifdef TARGET_TWL
                    pSurfaceFrustum->bClipFar = 1;
#endif
                }
                
                num_vertices = meshinfo_out.numVertices;
                if (UNLIKELY(meshinfo_out.numVertices < 3u))
                {
                    continue;
                }
                rdCamera_g_pCurCamera->pfProjectList(procEntry->aVertices, sithRender_aClipVertices, meshinfo_out.numVertices);

                if (UNLIKELY(sithRender_lightingIRMode))
                {
                    v49 = sithRender_f_83198C;
                    procEntry->light_level_static = 0.0;
                    procEntry->ambientLight = v49;
                }
                else
                {
                    procEntry->ambientLight = stdMath_Clamp(level_idk->extraLight + sithRender_008d4098, 0.0, 1.0);
                }

                // These lighting optimizations are for the software renderer
#ifndef TARGET_TWL
                if ( procEntry->ambientLight >= 1.0 )
                {
                    if ( v68 )
                    {
                        procEntry->lightingMode = RD_LIGHTMODE_FULLYLIT;
                    }
                    else
                    {
                        procEntry->lightingMode = RD_LIGHTMODE_DIFFUSE;
                        procEntry->light_level_static = 1.0;
                    }
                }
                else if ( procEntry->lightingMode == RD_LIGHTMODE_DIFFUSE)
                {
                    if ( procEntry->light_level_static >= 1.0 && v68 )
                    {
                        procEntry->lightingMode = RD_LIGHTMODE_FULLYLIT;
                    }
                    else if ( procEntry->light_level_static <= 0.0 )
                    {
                        procEntry->lightingMode = RD_LIGHTMODE_NOTLIT;
                    }
                }
                else if ( (rdGetVertexColorMode() == 0) && procEntry->lightingMode == RD_LIGHTMODE_GOURAUD)
                {
                    v51 = procEntry->vertexIntensities;
                    v67 = *v51;
                    v52 = 1;
                    if ( num_vertices > 1 )
                    {
                        v53 = v51 + 1;
                        do
                        {
                            v54 = stdMath_Fabs(*v53 - v67);
                            if ( v54 > 0.015625 )
                                break;
                            ++v52;
                            ++v53;
                        }
                        while ( v52 < num_vertices );
                    }
                    if ( v52 != num_vertices )
                    {
                        
                    }
                    else if ( v67 == 1.0 )
                    {
                        if ( v68 )
                        {
                            procEntry->lightingMode = RD_LIGHTMODE_FULLYLIT;
                        }
                        else
                        {
                            procEntry->lightingMode = RD_LIGHTMODE_DIFFUSE;
                            procEntry->light_level_static = 1.0;
                        }
                    }
                    else if ( v67 == 0.0 )
                    {
                        procEntry->lightingMode = RD_LIGHTMODE_NOTLIT;
                        procEntry->light_level_static = 0.0;
                    }
                    else
                    {
                        procEntry->lightingMode = RD_LIGHTMODE_DIFFUSE;
                        procEntry->light_level_static = v67;
                    }
                }
#endif

                flags = v65->flags;
                if (UNLIKELY(flags & SITH_SURFACE_HORIZON_SKY))
                {
                    sithRenderSky_HorizonFaceToPlane(procEntry, &v65->surfaceInfo, num_vertices);
                }
                else if (UNLIKELY(flags & SITH_SURFACE_CEILING_SKY))
                {
                    sithRenderSky_CeilingFaceToPlane(procEntry, &v65->surfaceInfo, sithRender_aClipVertices, num_vertices);
                }
                v57 = v65->surfaceInfo.face.type;
                procEntry->wallCel = v65->surfaceInfo.face.wallCel;
                v58 = v65->surfaceInfo.face.material;
                procEntry->extralight = v65->surfaceInfo.face.extraLight;
                procEntry->material = v58;
                v59 = procEntry->geometryMode;
                procEntry->light_flags = 0;
                procEntry->type = v57;
                rend_flags = 1;
                if ( v59 >= 4 )
                    rend_flags = 3;
                if ( procEntry->lightingMode >= RD_LIGHTMODE_GOURAUD)
                    rend_flags |= 4u;

                rdCache_AddProcFace(0, num_vertices, rend_flags);
                continue;
            }

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
                    v20->light_level_static = 1.0; // Added?
                    v21 = v65->surfaceInfo.face.geometryMode;
                    if ( v21 >= sithRender_geoMode )
                        v21 = sithRender_geoMode;
                    v20->geometryMode = v21;
                    lightMode2 = v65->surfaceInfo.face.lightingMode;
                    if ( sithRender_lightingIRMode )
                    {
                        if ( lightMode2 >= RD_LIGHTMODE_DIFFUSE)
                            lightMode2 = RD_LIGHTMODE_DIFFUSE;
                    }
                    else if ( lightMode2 >= sithRender_lightMode )
                    {
                        lightMode2 = sithRender_lightMode;
                    }
                    v23 = sithRender_texMode;
                    v20->lightingMode = lightMode2;
                    v24 = v65->surfaceInfo.face.textureMode;
                    if ( v24 >= v23 )
                        v24 = v23;
                    v20->textureMode = v24;
                    v78[0] = v65->surfaceInfo.face.vertexPosIdx[v19];
                    v78[1] = v65->surfaceInfo.face.vertexPosIdx[v71];
                    v78[2] = v65->surfaceInfo.face.vertexPosIdx[v18];
                    if ( v20->geometryMode >= RD_GEOMETRY_FULL)
                    {
                        v79[0] = v65->surfaceInfo.face.vertexUVIdx[v19];
                        v79[1] = v65->surfaceInfo.face.vertexUVIdx[v71];
                        v79[2] = v65->surfaceInfo.face.vertexUVIdx[v18];
                    }
                    meshinfo_out.aVertices = sithRender_aClipVertices;
                    sithRender_faceView.numVertices = 3;
                    meshinfo_out.aTexVerticies = v20->aTexVerticies;
                    sithRender_faceView.vertexPosIdx = v78;
                    meshinfo_out.paDynamicLight = v20->vertexIntensities;
                    sithRender_faceView.vertexUVIdx = v79;
                    
                    // MOTS added
                    if (rdGetVertexColorMode() == 0) {
                        v80[0] = v65->surfaceInfo.intensities[v19];
                        v80[1] = v65->surfaceInfo.intensities[v71];
                        v80[2] = v65->surfaceInfo.intensities[v18];
                        sithRender_faceView.intensities = v80;
                        rdPrimit3_ClipFace(pSurfaceFrustum, 
                                           v20->geometryMode, 
                                           v20->lightingMode, 
                                           v20->textureMode, 
                                           &sithRender_faceView, 
                                           &meshinfo_out, 
                                           &v65->surfaceInfo.face.texVertOffset);
                        /*rdPrimit3_NoClipFace(/*pSurfaceFrustum,* / 
                                       v20->geometryMode, 
                                       v20->lightingMode, 
                                       v20->textureMode, 
                                       &sithRender_faceView, 
                                       &meshinfo_out, 
                                       &v65->surfaceInfo.face.texVertOffset);*/
                    }
                    else {
                        

                        if ((v65->flags & SITH_SURFACE_1000000) == 0) 
                        {
                            v80[0] = v65->surfaceInfo.intensities[v19];
                            v80[1] = v65->surfaceInfo.intensities[v71];
                            v80[2] = v65->surfaceInfo.intensities[v18];

                            memcpy(tmpBlue, v80, sizeof(flex_t) * 3);
                            memcpy(tmpGreen, v80, sizeof(flex_t) * 3);
                        }
                        else {
                            v80[0] = v65->surfaceInfo.intensities[(v65->surfaceInfo.face.numVertices * 1) + v19];
                            v80[1] = v65->surfaceInfo.intensities[(v65->surfaceInfo.face.numVertices * 1) + v71];
                            v80[2] = v65->surfaceInfo.intensities[(v65->surfaceInfo.face.numVertices * 1) + v18];

                            tmpGreen[0] = v65->surfaceInfo.intensities[(v65->surfaceInfo.face.numVertices * 2) + v19];
                            tmpGreen[1] = v65->surfaceInfo.intensities[(v65->surfaceInfo.face.numVertices * 2) + v71];
                            tmpGreen[2] = v65->surfaceInfo.intensities[(v65->surfaceInfo.face.numVertices * 2) + v18];

                            tmpBlue[0] = v65->surfaceInfo.intensities[(v65->surfaceInfo.face.numVertices * 3) + v19];
                            tmpBlue[1] = v65->surfaceInfo.intensities[(v65->surfaceInfo.face.numVertices * 3) + v71];
                            tmpBlue[2] = v65->surfaceInfo.intensities[(v65->surfaceInfo.face.numVertices * 3) + v18];
                        }

                        sithRender_faceView.paRedIntensities = v80;
                        sithRender_faceView.paGreenIntensities = tmpGreen;
                        sithRender_faceView.paBlueIntensities = tmpBlue;

                        meshinfo_out.paRedIntensities = v20->paRedIntensities;
                        meshinfo_out.paGreenIntensities = v20->paGreenIntensities;
                        meshinfo_out.paBlueIntensities = v20->paBlueIntensities;

                        rdPrimit3_ClipFaceRGBLevel
                                  (pSurfaceFrustum,
                                   v20->geometryMode,
                                   v20->lightingMode,
                                   v20->textureMode, 
                                   &sithRender_faceView,
                                   &meshinfo_out,
                                   &(v65->surfaceInfo).face.texVertOffset);
                    }

                    // Avoid projecting aVertices if they're far away enough, skipping sky
                    // aVertices because they're important for aesthetics
#if 0 //def EXPERIMENTAL_FIXED_POINT
                    skip_this_surface = 0;
                    flags = v65->flags;
                    if (!noDistCulling && !(flags & (SITH_SURFACE_HORIZON_SKY | SITH_SURFACE_CEILING_SKY)))
                    {
                        flex_t zfar = rdCamera_g_pCurCamera->pClipFrustum->farPlane;
                        for (int i = 0; i < meshinfo_out.numVertices; i++) {
                            //printf("%f\n", (float)v20->aVertices[i].y);
                            flex_t verty = sithRender_aClipVertices[i].y;
                            if (verty > zfar || verty < 0.0) {
                                skip_this_surface = 1;
                                break;
                            }
                        }
                        if (skip_this_surface) {
                            goto LABEL_92;
                        }
                    }
                    else {
                        skip_this_surface = 0;
                    }
#endif

                    v28 = meshinfo_out.numVertices;
                    if ( meshinfo_out.numVertices < 3u )
                        goto LABEL_92;

                    rdCamera_g_pCurCamera->pfProjectList(v20->aVertices, sithRender_aClipVertices, meshinfo_out.numVertices);

                    if ( sithRender_lightingIRMode )
                    {
                        v29 = sithRender_f_83198C;
                        v20->light_level_static = 0.0;
                        v20->ambientLight = v29;
                    }
                    else
                    {
                        v20->ambientLight = stdMath_Clamp(level_idk->extraLight + sithRender_008d4098, 0.0, 1.0);
                    }

                    // These lighting optimizations are for the software renderer
#ifndef TARGET_TWL
                    if ( v20->ambientLight >= 1.0 )
                    {
                        if ( v68 )
                        {
                            v20->lightingMode = RD_LIGHTMODE_FULLYLIT;
                        }
                        else
                        {
                            v20->lightingMode = RD_LIGHTMODE_DIFFUSE;
                            v20->light_level_static = 1.0;
                        }
                    }
                    else if ( v20->lightingMode == RD_LIGHTMODE_DIFFUSE)
                    {
                        if ( v20->light_level_static >= 1.0 && v68 )
                        {
                            v20->lightingMode = RD_LIGHTMODE_FULLYLIT;
                        }
                        else if ( v20->light_level_static <= 0.0 )
                        {
                            v20->lightingMode = RD_LIGHTMODE_NOTLIT;
                        }
                    }
                    else if ( (rdGetVertexColorMode() == 0) && v20->lightingMode == RD_LIGHTMODE_GOURAUD )
                    {
                        v31 = v20->vertexIntensities;
                        v32 = 1;
                        v66 = *v31;
                        if ( v28 > 1 )
                        {
                            v33 = v31 + 1;
                            do
                            {
                                v34 = stdMath_Fabs(*v33 - v66);
                                if ( v34 > (1.0/64.0) )
                                    break;
                                ++v32;
                                ++v33;
                            }
                            while ( v32 < v28 );
                        }
                        if ( v32 == v28 )
                        {
                            if ( v66 != 1.0 )
                            {
                                if ( v66 == 0.0 )
                                {
                                    v20->lightingMode = RD_LIGHTMODE_NOTLIT;
                                    v20->light_level_static = 0.0;
                                }
                                else
                                {
                                    v20->lightingMode = RD_LIGHTMODE_DIFFUSE;
                                    v20->light_level_static = v66;
                                }
                            }
                        }
                    }
#endif

                    v20->wallCel = v65->surfaceInfo.face.wallCel;
                    v20->extralight = v65->surfaceInfo.face.extraLight;
                    v20->material = v65->surfaceInfo.face.material;
                    v38 = v20->geometryMode;
                    v20->light_flags = 0;
                    v20->type = v65->surfaceInfo.face.type;
                    v39 = 1;
                    if ( v38 >= 4 )
                        v39 = 3;
                    if ( v20->lightingMode >= RD_LIGHTMODE_GOURAUD)
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
                        goto LABEL_150;
                    continue;
                }
            }
LABEL_150:
            ;    
        }

        // Surprisingly, this is a fairly minimal cost to the entire render, 3ms on landing terminal spawn
        rdSetProcFaceUserData(level_idk->id | 0x10000);
        int safeguard = 0;
        for ( i = level_idk->pFirstThingInSector; i; i = i->pNextThingInSector )
        {
            // Added: safeguards
            if (++safeguard >= SITH_MAX_THINGS) {
                break;
            }

            if (!(i->flags & SITH_TF_LEVELGEO)) {
                continue;
            }

            if (i->flags & (SITH_TF_DISABLED|SITH_TF_10|SITH_TF_DESTROYED)) {
                continue;
            }

            if (!((sithCamera_g_pCurCamera->type & 0xFC) != 0 || i != sithCamera_g_pCurCamera->pPrimaryFocusThing)) {
                continue;
            }

            if (i->renderData.type != RD_THING_MODEL3) {
                continue;
            }

            rdMatrix_TransformPoint34(&i->transformedPos, &i->position, &rdCamera_g_pCurCamera->orient);
            v63 = rdClip_SphereInFrustrum(level_idk->pClipFrustum, &i->transformedPos, i->renderData.model3->radius);
#ifdef SITHRENDER_SPHERE_TEST_SURFACES
            extern rdClipFrustum sithRender_absoluteMaxFrustum;

            if (UNLIKELY(v63 == SPHERE_CLIPPING_EDGE)) {
                v63 = rdClip_SphereInFrustrum(&sithRender_absoluteMaxFrustum, &i->transformedPos, i->renderData.model3->radius);
            }
#endif
            i->renderData.clippingIdk = v63;
            if (LIKELY(v63 == SPHERE_FULLY_OUTSIDE)) {
                continue;
            }

            // REMOVED: This was bugged idk
            //if ( a2 >= 1.0 )
            //    i->renderData.desiredLightMode = RD_LIGHTMODE_FULLYLIT;
            if ( a2 >= 1.0 )
                i->renderData.curLightMode = RD_LIGHTMODE_FULLYLIT;
            else
                i->renderData.curLightMode = i->renderData.desiredLightMode;

            // MOTS added
#ifdef JKM_LIGHTING
            if ((i->archlightIdx != -1) && ((i->renderData).type == RD_THING_MODEL3)) {
                rdModel3* iVar22 = i->renderData.model3;
                for (int k = 0; k < 4; k++) {
                    for (int j = 0; j < iVar22->aGeos[k].numMeshes; j++) 
                    {
                        if (rdGetVertexColorMode() == 0) {
                            iVar22->aGeos[k].aMeshes[j].vertices_unk = iVar22->aGeos[k].aMeshes[j].vertices_i;
                            iVar22->aGeos[k].aMeshes[j].vertices_i = sithWorld_g_pCurrentWorld->aArchlights[i->archlightIdx].aMeshes[j].aMono;
                        }
                        else {
                            iVar22->aGeos[k].aMeshes[j].paRedIntensities = sithWorld_g_pCurrentWorld->aArchlights[i->archlightIdx].aMeshes[j].aRed;
                            iVar22->aGeos[k].aMeshes[j].paGreenIntensities = sithWorld_g_pCurrentWorld->aArchlights[i->archlightIdx].aMeshes[j].aGreen;
                            iVar22->aGeos[k].aMeshes[j].paBlueIntensities = sithWorld_g_pCurrentWorld->aArchlights[i->archlightIdx].aMeshes[j].aBlue;
                        }
                    }
                }
            }
            if ((i->archlightIdx == -1) && (rdGetVertexColorMode() == 1)) {
                rdModel3* iVar13 = i->renderData.model3;
                for (int k = 0; k < 4; k++) {
                    for (int j = 0; j < iVar13->aGeos[k].numMeshes; j++) 
                    {
                        iVar13->aGeos[k].aMeshes[j].paRedIntensities = iVar13->aGeos[k].aMeshes[j].vertices_i;
                        iVar13->aGeos[k].aMeshes[j].paGreenIntensities = iVar13->aGeos[k].aMeshes[j].vertices_i;
                        iVar13->aGeos[k].aMeshes[j].paBlueIntensities = iVar13->aGeos[k].aMeshes[j].vertices_i;
                    }
                }
            }
#endif // JKM_LIGHTING

            if ( sithRender_RenderThing(i) )
                ++sithRender_geoThingsDrawn;

            // MOTS added
#ifdef JKM_LIGHTING
            if (((i->archlightIdx != -1) && (i->renderData.type == RD_THING_MODEL3)) && (rdGetVertexColorMode() == 0)) {
                rdModel3* iVar14 = i->renderData.model3;
                for (int k = 0; k < 4; k++) {
                    for (int j = 0; j < iVar14->aGeos[k].numMeshes; j++) 
                    {
                        iVar14->aGeos[k].aMeshes[j].vertices_i = iVar14->aGeos[k].aMeshes[j].vertices_unk;
                    }
                }
            }
#endif
        }

        ++sithRender_numRenderedSectors;
    }
    

//#ifndef TARGET_TWL
    // TWL: 5-27ms
    rdCache_Flush();
//#endif
    rdCamera_g_pCurCamera->pClipFrustum = pFullCameraFrustum;
}

void sithRender_BuildVisibleSectorsThingList()
{
    SithSurfaceAdjoin *i; // esi

    for (int j = 0; j < sithRender_g_numVisibleSectors; j++)
    {
        for ( i = sithRender_aVisibleSectors[j]->adjoins; i; i = i->next )
        {
            if ( i->sector->renderTick != sithRender_lastRenderTick && (i->flags & 1) != 0 )
            {
                // Allow aThings to peek their light around corners w/o screwing with frustums
#ifndef QOL_IMPROVEMENTS
                i->sector->pClipFrustum = sithRender_aVisibleSectors[j]->pClipFrustum;
#else
                i->sector->pClipFrustum = NULL;
#endif
                sithRender_BuildSectorThingList(i->sector, 0.0, i->dist, 0);
            }
        }
    }
}

// Added: recursion depth
void sithRender_BuildSectorThingList(SithSector *sector, flex_t prev, flex_t dist, int depth)
{
    SithThing *i;
    SithSurfaceAdjoin *j;
    rdVector3 vertex_out;

    // Added: safeguards
    if (depth > SITH_MAX_VISIBLE_SECTORS_2) {
        return;
    }

    if ( sector->renderTick == sithRender_lastRenderTick )
        return;

    sector->renderTick = sithRender_lastRenderTick;
    if ( prev < 2.0 && sithRender_numThingLights < 0x20)
    {
        int safeguard = 0;
        for ( i = sector->pFirstThingInSector; i; i = i->pNextThingInSector )
        {
            // Added: safeguards
            if (++safeguard >= SITH_MAX_THINGS) {
                break;
            }

            if ( sithRender_numThingLights >= 0x20 )
                break;

            if ((i->flags & SITH_TF_EMITLIGHT) 
                && !(i->flags & (SITH_TF_DISABLED|SITH_TF_DESTROYED)))
            {
                if ( i->light > 0.0 )
                {
                    sithRender_aThingLights[sithRender_numThingLights].intensity = i->light;
                    rdCamera_AddLight(rdCamera_g_pCurCamera, &sithRender_aThingLights[sithRender_numThingLights], &i->position);
                    ++sithRender_numThingLights;
                }

                if ( (i->type == SITH_THING_ACTOR || i->type == SITH_THING_PLAYER) && sithRender_numThingLights < 0x20 )
                {
                    // Actors all have a small amount of light
                    if ( (i->actorParams.flags & SITH_AF_HEADLIGHT) && i->actorParams.lightIntensity > 0.0 )
                    {
                        rdMatrix_TransformPoint34(&vertex_out, &i->actorParams.lightOffset, &i->orient);
                        rdVector_Add3Acc(&vertex_out, &i->position);
                        
                        sithRender_aThingLights[sithRender_numThingLights].intensity = i->actorParams.lightIntensity;
                        rdCamera_AddLight(rdCamera_g_pCurCamera, &sithRender_aThingLights[sithRender_numThingLights], &vertex_out);
                        ++sithRender_numThingLights;
                    }
                    
                    // Saber light
                    if ( i->actorParams.timeLeftLengthChange > 0.0 )
                    {
                        sithRender_aThingLights[sithRender_numThingLights].intensity = i->actorParams.timeLeftLengthChange;
                        rdCamera_AddLight(rdCamera_g_pCurCamera, &sithRender_aThingLights[sithRender_numThingLights], &i->actorParams.saberBladePos);
                        ++sithRender_numThingLights;
                    }
                }
            }
        }
    }
    if ( prev < 0.8 )
    {
        if ( sithRender_numThingSectors < SITH_MAX_VISIBLE_SECTORS_2 )
        {
            sithRender_aThingSectors[sithRender_numThingSectors++] = sector;
        }
    }

#ifndef TARGET_TWL
    // What is the point of this anyhow besides wasting time?
    for ( j = sector->adjoins; j; j = j->next )
    {
        if ( (j->flags & 1) != 0 && j->sector->renderTick != sithRender_lastRenderTick )
        {
            flex_t nextDist = j->mirror->dist + j->dist + dist + prev;
            if ( nextDist < 0.8 || nextDist < 2.0 ) // Bug?
            {
                // Allow aThings to peek their light around corners w/o screwing with frustums
#ifndef QOL_IMPROVEMENTS
                j->sector->pClipFrustum = sector->pClipFrustum;
#else
                j->sector->pClipFrustum = NULL;
#endif
                sithRender_BuildSectorThingList(j->sector, nextDist, 0.0, ++depth);

                // Added: safeguards
                if (depth >= SITH_MAX_VISIBLE_SECTORS_2) break;
            }
        }
    }
#endif
}

void sithRender_BuildDynamicLights()
{
    SithSector *sectorIter;
    rdLight **curCamera_lights;
    unsigned int numSectorLights;
    rdLight *tmpLights[64];

    if (!sithRender_g_numVisibleSectors)
        return;

    for (int k = 0; k < sithRender_g_numVisibleSectors; k++)
    {
        sectorIter = sithRender_aVisibleSectors[k];
        
        curCamera_lights = rdCamera_g_pCurCamera->aLights;
        
        //sithRender_RenderDebugLight(10.0, &sectorIter->center);
        
        numSectorLights = 0;
        for (int i = 0; i < rdCamera_g_pCurCamera->numLights; i++)
        {
            //sithRender_RenderDebugLight(10.0, &rdCamera_g_pCurCamera->aLightPositions[i]);
        
            flex_t distCalc = rdVector_Dist3(&rdCamera_g_pCurCamera->aLightPositions[i], &sectorIter->center);
            if ( curCamera_lights[i]->minRadius + sectorIter->radius > distCalc)
            {
                tmpLights[numSectorLights++] = curCamera_lights[i];
            }
        }

        for (int j = 0; j < sectorIter->numVertices; j++)
        {
            int idx = sectorIter->aVertIdxs[j];
            if ( sithWorld_g_pCurrentWorld->alloc_unk9c[idx] != sithRender_lastRenderTick )
            {
                sithWorld_g_pCurrentWorld->aVertDynamicLights[idx] = 0.0;

                for (int i = 0; i < numSectorLights; i++)
                {
                    int id = tmpLights[i]->id;
                    flex_t distCalc = rdVector_Dist3(&rdCamera_g_pCurCamera->aLightPositions[id], &sithWorld_g_pCurrentWorld->aVertices[idx]);

                    // Light is within distance of the vertex
                    if ( distCalc < tmpLights[i]->maxRadius )
                        sithWorld_g_pCurrentWorld->aVertDynamicLights[idx] += tmpLights[i]->intensity - distCalc * rdCamera_g_pCurCamera->attenuationMax;

                    // This vertex is as lit as it can be, stop adding aLights to it
                    if ( sithWorld_g_pCurrentWorld->aVertDynamicLights[idx] >= 1.0 )
                        break;
                }
                sithWorld_g_pCurrentWorld->alloc_unk9c[idx] = sithRender_lastRenderTick;
            }
        }
    }
}

// MoTS altered
void sithRender_RenderThings()
{
    SithSector *v1; // ebp
    flex_d_t v2; // st7
    SithThing *thingIter; // esi
    flex_t radius; // edx
    int clippingVal; // eax
    SithWorld *curWorld; // edx
    rdModel3 *model3; // ecx
    int texMode; // ecx
    int texMode2; // eax
    rdLightMode_t lightMode; // eax
    flex_t v12; // [esp-Ch] [ebp-28h]
    flex_t a2; // [esp+8h] [ebp-14h]
    flex_t clipRadius; // [esp+Ch] [ebp-10h]
    uint32_t i; // [esp+14h] [ebp-8h]
    BOOL v16; // [esp+18h] [ebp-4h]

    // MoTS added
    SithThing* lastDrawn = NULL;
    if (sithRender_008d1668) {
        rdSetCullFlags(0);
    }

    rdSetZBufferMethod(RD_ZBUFFER_READ_WRITE);
    rdSetOcclusionMethod(0);
    rdSetVertexColorMode(0);

    for ( i = 0; i < sithRender_numThingSectors; i++ )
    {
        v1 = sithRender_aThingSectors[i];
        if ( sithRender_lightingIRMode )
        {
            a2 = sithRender_f_831990;
        }
        else
        {
            v2 = v1->ambientLight + v1->extraLight + sithRender_008d4098;
            a2 = stdMath_Clamp(v2, 0.0, 1.0);
        }
        rdColormap_SetCurrent(v1->colormap);
        thingIter = v1->pFirstThingInSector;
        v16 = v1->colormap == sithWorld_g_pCurrentWorld->colormaps;

        int safeguard = 0;
        for (; thingIter; thingIter = thingIter->pNextThingInSector)
        {
            // Added: safeguards
            if (++safeguard >= SITH_MAX_THINGS) {
                break;
            }

            if ( (thingIter->flags & (SITH_TF_DISABLED|SITH_TF_10|SITH_TF_DESTROYED)) == 0
              && (thingIter->flags & SITH_TF_LEVELGEO) == 0
              && ((sithCamera_g_pCurCamera->type & 0xFC) != 0 || thingIter != sithCamera_g_pCurCamera->pPrimaryFocusThing) )
            {
                rdMatrix_TransformPoint34(&thingIter->transformedPos, &thingIter->position, &rdCamera_g_pCurCamera->orient);
                
                //printf("%f %f %f ; %f %f %f\n", thingIter->transformedPos.x, thingIter->transformedPos.y, thingIter->transformedPos.z, thingIter->position.x, thingIter->position.y, thingIter->position.z);
                
                if ( rdroid_curAcceleration > 0 || thingIter->renderData.type != RD_THING_SPRITE3 || sithRender_numSpritesToDraw < 8 )
                {
                    // Allow aThings to peek their light around corners w/o screwing with frustums
#ifdef QOL_IMPROVEMENTS
                    if ( (thingIter->flags & SITH_TF_EMITLIGHT) != 0
                      && thingIter->light > 0.0
                      && a2 <= stdMath_Clamp(thingIter->light, 0.0, 1.0) )
                    {
                        rdCamera_SetAmbientLight(rdCamera_g_pCurCamera, stdMath_Clamp(thingIter->light, 0.0, 1.0));
                    }
                    else
                    {
                        rdCamera_SetAmbientLight(rdCamera_g_pCurCamera, a2);
                    }

                    if (!v1->pClipFrustum) {
#ifdef TARGET_TWL
                        // Preload model textures, if supported
                        rdModel3_EnsureMaterialData(&thingIter->renderData);
                        continue;
#endif
                        v1->pClipFrustum = rdCamera_g_pCurCamera->pClipFrustum;
                    }
#endif
                    clipRadius = 0.0f;
                    switch ( thingIter->renderData.type )
                    {
                        case RD_THING_MODEL3:
                            radius = thingIter->renderData.model3->radius;
                            clipRadius = radius;
                            clippingVal = rdClip_SphereInFrustrum(v1->pClipFrustum, &thingIter->transformedPos, clipRadius);
                            break;

                        case RD_THING_SPRITE3:
                            clipRadius = thingIter->renderData.sprite3->radius;
                            ++sithRender_numSpritesToDraw;
                            clippingVal = rdClip_SphereInFrustrum(v1->pClipFrustum, &thingIter->transformedPos, clipRadius);
                            break;

                        case RD_THING_PARTICLE:
                            clipRadius = thingIter->renderData.particlecloud->cloudRadius;
                            clippingVal = rdClip_SphereInFrustrum(v1->pClipFrustum, &thingIter->transformedPos, clipRadius);
                            break;

                        case RD_THING_POLYLINE:
                            radius = thingIter->renderData.polyline->length;
                            clipRadius = radius;
                            clippingVal = rdClip_SphereInFrustrum(v1->pClipFrustum, &thingIter->transformedPos, clipRadius);
                            break;

                        default:
                            clippingVal = rdClip_SphereInFrustrum(v1->pClipFrustum, &thingIter->transformedPos, clipRadius);
                            break;
                    }
                    //printf("%f %f %f %d\n", (flex32_t)thingIter->transformedPos.x, (flex32_t)thingIter->transformedPos.y, (flex32_t)thingIter->transformedPos.z, clippingVal);
                    thingIter->renderData.clippingIdk = clippingVal;
                    if ( clippingVal == SPHERE_FULLY_OUTSIDE || sithRender_008d1668) // MoTS added: sithRender_008d1668
                        continue;
                    curWorld = sithWorld_g_pCurrentWorld;

                    flex_t yval = thingIter->transformedPos.y;

                    // MoTS added
                    if (sithCamera_g_pCurCamera->zoomScale != 1.0) {
                        yval = sithCamera_g_pCurCamera->invZoomScale * (thingIter->transformedPos).y;
                    }

#ifdef TARGET_TWL
                    // Added: Force corpses to use the lowest geoset possible
                    if (thingIter->type == SITH_THING_CORPSE) {
                        yval = 100.0;
                    }
#endif

                    if ( thingIter->renderData.type == RD_THING_MODEL3 )
                    {
                        model3 = thingIter->renderData.model3;

                        switch ( model3->numGeos )
                        {
                            case 1:
                                break;
                            case 2:
                                if ( yval < (flex_d_t)sithWorld_g_pCurrentWorld->distancesLOD.y )
                                {
                                    model3->geosetSelect = 0;
                                }
                                else
                                {
                                    model3->geosetSelect = 1;
                                }
                                break;
                            case 3:
                                if ( yval < (flex_d_t)sithWorld_g_pCurrentWorld->distancesLOD.x )
                                {
                                    model3->geosetSelect = 0;
                                    
                                }
                                else if ( yval >= (flex_d_t)sithWorld_g_pCurrentWorld->distancesLOD.y )
                                {
                                    model3->geosetSelect = 2;
                                }
                                else
                                {
                                    model3->geosetSelect = 1;
                                }

                                break;
                            default:
                                if ( yval < (flex_d_t)sithWorld_g_pCurrentWorld->distancesLOD.x )
                                {
                                    model3->geosetSelect = 0;
                                }
                                else if ( yval < (flex_d_t)sithWorld_g_pCurrentWorld->distancesLOD.y )
                                    model3->geosetSelect = 1;
                                else if ( yval >= (flex_d_t)sithWorld_g_pCurrentWorld->distancesLOD.z )
                                    model3->geosetSelect = 3;
                                else
                                    model3->geosetSelect = 2;
                                break;
                        }
                    }
                    
                    texMode = thingIter->renderData.desiredTexMode;

                    // These texture optimizations are for the sw renderer
#ifndef TARGET_TWL
                    if ( yval >= (flex_d_t)curWorld->perspectiveDistance )
                    {
                        thingIter->renderData.curTexMode = texMode > RD_TEXTUREMODE_AFFINE ? RD_TEXTUREMODE_AFFINE : texMode;
                    }
                    else
#endif
                    {
                        texMode2 = RD_TEXTUREMODE_PERSPECTIVE;
                        if ( texMode <= RD_TEXTUREMODE_PERSPECTIVE)
                            texMode2 = thingIter->renderData.desiredTexMode;
                        thingIter->renderData.curTexMode = texMode2;
                    }

                    // These texture optimizations are for the sw renderer
#ifndef TARGET_TWL
                    if ( yval >= (flex_d_t)curWorld->perspectiveDistance )
                    {
                        thingIter->renderData.curTexMode = texMode > RD_TEXTUREMODE_AFFINE ? RD_TEXTUREMODE_AFFINE : texMode;
                    }
                    else
#endif
                    {
                        if ( texMode > RD_TEXTUREMODE_PERSPECTIVE)
                            texMode = RD_TEXTUREMODE_PERSPECTIVE;
                        thingIter->renderData.curTexMode = texMode;
                    }

                    // Moved this before culling
#ifndef QOL_IMPROVEMENTS
                    if ( (thingIter->flags & SITH_TF_EMITLIGHT) != 0
                      && thingIter->light > 0.0
                      && a2 <= stdMath_Clamp(thingIter->light, 0.0, 1.0) )
                    {
                        rdCamera_SetAmbientLight(rdCamera_g_pCurCamera, stdMath_Clamp(thingIter->light, 0.0, 1.0));
                    }
                    else
                    {
                        rdCamera_SetAmbientLight(rdCamera_g_pCurCamera, a2);
                    }
#endif

                    lightMode = thingIter->renderData.desiredLightMode;
                    if ( a2 >= 1.0 )
                    {
                        if ( v16 )
                        {
                            lightMode = lightMode > RD_LIGHTMODE_FULLYLIT ? RD_LIGHTMODE_FULLYLIT : lightMode;
                        }
                        else
                        {
                            if ( lightMode > RD_LIGHTMODE_DIFFUSE)
                                lightMode = RD_LIGHTMODE_DIFFUSE;
                        }
                    }
                    else if ( (thingIter->flags & SITH_TF_IGNOREGOURAUDDISTANCE) == 0 && yval >= (flex_d_t)sithWorld_g_pCurrentWorld->gouradDistance )
                    {
                        if ( lightMode > RD_LIGHTMODE_DIFFUSE)
                            lightMode = RD_LIGHTMODE_DIFFUSE;
                    }
                    else
                    {
                        if ( lightMode > RD_LIGHTMODE_GOURAUD)
                            lightMode = RD_LIGHTMODE_GOURAUD;
                    }
                    thingIter->renderData.curLightMode = lightMode;
                    if (thingIter->flags & SITH_TF_80000000) {
                        lastDrawn = thingIter;
                        continue;
                    }

                    if (sithRender_RenderThing(thingIter) ) // MOTS added: flag check
                        ++sithRender_nongeoThingsDrawn;
                }
            }
        }
    }

    // DSi doesn't really have Z buffer options, so just batch everything
//#ifndef TARGET_TWL
    rdCache_Flush();
//#endif

    // MoTS added
    if (lastDrawn) 
    {
        if (sithRender_RenderThing(lastDrawn)) {
            ++sithRender_nongeoThingsDrawn;
        }
    }

    // DSi doesn't really have Z buffer options, so just batch everything
//#ifndef TARGET_TWL
    rdCache_Flush();
//#endif

    if (sithRender_008d1668) {
        rdSetCullFlags(1);
    }
    
}

int sithRender_RenderThing(SithThing *pThing)
{
    int ret;

    // Added: Ensure the clipping frustum doesn't get mutated
    //rdClipFrustum* pFullCameraFrustum = rdCamera_g_pCurCamera->pClipFrustum;

    if (!(pThing->flags & SITH_TF_INCAMFOV) && !(g_debugmodeFlags & DEBUGFLAG_NOCLIP)) // Added: don't send sighted stuff in noclip
    {
        if (pThing->flags & SITH_TF_CAPTURED) {
            sithCog_ThingSendMessage(pThing, 0, SITH_MESSAGE_SIGHTED);
        }

        if (pThing->controlType == SITH_CT_AI && pThing->actor)
        {
            pThing->actor->flags &= ~SITHAI_MODE_SLEEPING;
        }
        pThing->flags |= SITH_TF_INCAMFOV;
    }

    pThing->renderFrame = jkPlayer_currentTickIdx;
    pThing->orient.scale = pThing->position;

#ifdef TARGET_TWL
    int skip_this_thing = 0;
    flex_t realDepth = pThing->transformedPos.y - (pThing->renderData.type == RD_THING_MODEL3 ? pThing->renderData.model3->radius : (flex_t)0.0);
    if (realDepth > 3.0) {
        skip_this_thing = 1;
    }
    if (realDepth > 1.5) {
        // geomode
    }
    if (!skip_this_thing) {
#endif

    // Clip aThings against their respective sector clipping bounds
#if 0
    if (pThing->sector) {
        rdCamera_g_pCurCamera->pClipFrustum = pThing->sector->pClipFrustum;
    }
#endif

    ret = rdThing_Draw(&pThing->renderData, &pThing->orient);
    rdVector_Zero3(&pThing->orient.scale);
    if (sithRender_pExtraThingRenderFunc && (pThing->flags & SITH_TF_RENDERWEAPON)) {
        sithRender_pExtraThingRenderFunc(pThing);
    }
#ifdef TARGET_TWL
    }
    else {
        // Preload model textures, if supported
        rdModel3_EnsureMaterialData(&pThing->renderData);
    }
#endif

    if (pThing->type == SITH_THING_EXPLOSION && (pThing->explosionParams.flags & SITHEXPLOSION_FLAG_FLASH_BLINDS_THINGS))
    {
        flex_t cameraDist = stdMath_Dist3D1(pThing->transformedPos.x, pThing->transformedPos.y, pThing->transformedPos.z);
        uint32_t flashG = pThing->explosionParams.flashG;
        uint32_t flashR = pThing->explosionParams.flashR;
        uint32_t flashB = pThing->explosionParams.flashB;
        flex_t flashMagnitude = ((flex_d_t)(flashB + flashR + flashG) * 0.013020833 - rdCamera_g_pCurCamera->attenuationMin * cameraDist) * 0.1;
        if ( flashMagnitude > 0.0 ) {
            sithPlayer_AddDyamicAdd((__int64)((flex_d_t)flashR * flashMagnitude - -0.5), (__int64)((flex_d_t)flashG * flashMagnitude - -0.5), (__int64)((flex_d_t)flashB * flashMagnitude - -0.5));
        }
        pThing->explosionParams.flags &= ~SITHEXPLOSION_FLAG_FLASH_BLINDS_THINGS;
    }

    // Added: Ensure the clipping frustum doesn't get mutated
    //rdCamera_g_pCurCamera->pClipFrustum = pFullCameraFrustum;
    return ret;
}

void sithRender_RenderAlphaAdjoins()
{
    SithSurface *v0; // edi
    SithSector *v1; // esi
    flex_d_t v2; // st7
    unsigned int v4; // ebp
    int v7; // eax
    rdProcEntry *v9; // esi
    flex_t *v20; // eax
    unsigned int v21; // ecx
    flex_t *v22; // edx
    char v23; // bl
    flex_t v31; // [esp+4h] [ebp-10h]
    SithSector *surfaceSector; // [esp+Ch] [ebp-8h]

    // Added: Ensure the clipping frustum doesn't get mutated
    rdClipFrustum* pFullCameraFrustum = rdCamera_g_pCurCamera->pClipFrustum;

#ifdef SDL2_RENDER
    rdCache_Flush();
    rdSetZBufferMethod(RD_ZBUFFER_READ_NOWRITE);
#else
    rdSetZBufferMethod(RD_ZBUFFER_READ_WRITE);
#endif
    rdSetOcclusionMethod(0);
    rdSetSortingMethod(2);

    for (int i = 0; i < sithRender_numAlphaAdjoins; i++)
    {
        v0 = sithRender_aAlphaAdjoins[i];
        v1 = v0->pSector;
        surfaceSector = v1;
        rdClipFrustum* pSurfaceFrustum = v1->pClipFrustum;

#ifdef TARGET_TWL
        pSurfaceFrustum = pFullCameraFrustum;
#endif

#ifdef SITHRENDER_SPHERE_TEST_SURFACES
        int clipResult = SPHERE_CLIPPING_EDGE; 
        //if (noDistCulling && !bIsSkySurface)
        {
            rdVector3 centerTrans = v0->center;
            rdClipFrustum* pSphereFrustum = pSurfaceFrustum;

            rdMatrix_TransformPoint34Acc(&centerTrans, &rdCamera_g_pCurCamera->orient);

            clipResult = rdClip_SphereInFrustrum(pSphereFrustum, &centerTrans, v0->radius);

            /*if (sithRender_lastRenderTick & 1) {
                clipResult = SPHERE_CLIPPING_EDGE;
            }*/
            if (v0->radius * 2.0 > pFullCameraFrustum->farPlane) {
                clipResult = SPHERE_CLIPPING_EDGE;
                //pSurfaceFrustum = pFullCameraFrustum;
            }
            else if (clipResult == SPHERE_CLIPPING_EDGE) {

                // Run a second check to see if we can have hardware clip for us
                // (mostly pertinent on fixed-pt 3D hardware like DSi)
                clipResult = rdClip_SphereInFrustrum(&sithRender_absoluteMaxFrustum, &centerTrans, v0->radius);
            }

            if (clipResult == SPHERE_FULLY_OUTSIDE) {
                continue;
            }

            //pSurfaceFrustum = &sithRender_absoluteMaxFrustum;
            pSurfaceFrustum = pFullCameraFrustum;
        }
        
#endif

        if ( sithRender_lightingIRMode )
        {
            rdCamera_SetAmbientLight(rdCamera_g_pCurCamera, sithRender_f_83198C);
        }
        else
        {
            v2 = v1->extraLight + v1->ambientLight + sithRender_008d4098;
            rdCamera_SetAmbientLight(rdCamera_g_pCurCamera, stdMath_Clamp(v2, 0.0, 1.0));
        }
        rdColormap_SetCurrent(v1->colormap);

        if (LIKELY(v0->field_4 != sithRender_lastRenderTick))
        {
            for (int j = 0; j < v0->surfaceInfo.face.numVertices; j++)
            {
                int idx = v0->surfaceInfo.face.vertexPosIdx[j];
                if (LIKELY(sithWorld_g_pCurrentWorld->alloc_unk98[idx] != sithRender_lastRenderTick))
                {
                    rdMatrix_TransformPoint34(&sithWorld_g_pCurrentWorld->aTransformedVertices[idx], &sithWorld_g_pCurrentWorld->aVertices[idx], &rdCamera_g_pCurCamera->orient);
                    sithWorld_g_pCurrentWorld->alloc_unk98[idx] = sithRender_lastRenderTick;
                }
            }
            v0->field_4 = sithRender_lastRenderTick;
        }
        
        v9 = rdCache_GetProcEntry();
        if ( !v9 )
        {
            continue;
        }
        v9->light_level_static = 1.0; // Added?
        
        v9->geometryMode = sithRender_geoMode;
        if ( v0->surfaceInfo.face.geometryMode < v9->geometryMode )
        {
            v9->geometryMode = v0->surfaceInfo.face.geometryMode;
        }

        v9->lightingMode = sithRender_lightMode;
        if ( v0->surfaceInfo.face.lightingMode < v9->lightingMode )
        {
            v9->lightingMode = v0->surfaceInfo.face.lightingMode;
        }
        
        v9->textureMode = v0->surfaceInfo.face.textureMode;
        if (sithRender_texMode <= v9->textureMode)
            v9->textureMode = sithRender_texMode;

        sithRender_faceView.intensities = v0->surfaceInfo.intensities;
        meshinfo_out.aTexVerticies = v9->aTexVerticies;
        meshinfo_out.paDynamicLight = v9->vertexIntensities;
        sithRender_faceView.numVertices = v0->surfaceInfo.face.numVertices;
        sithRender_faceView.vertexPosIdx = v0->surfaceInfo.face.vertexPosIdx;
        sithRender_faceView.vertexUVIdx = v0->surfaceInfo.face.vertexUVIdx;
        meshinfo_out.aVertices = sithRender_aClipVertices;

        // Added: Just in case
        if (!sithRender_faceView.vertexUVIdx && v9->geometryMode > RD_GEOMETRY_SOLID) {
            v9->geometryMode = RD_GEOMETRY_SOLID;
        }

#ifdef SITHRENDER_SPHERE_TEST_SURFACES
        if (clipResult != SPHERE_FULLY_INSIDE) {
#endif
        rdPrimit3_ClipFace(pSurfaceFrustum, 
            v9->geometryMode, 
            v9->lightingMode, 
            v9->textureMode, 
            &sithRender_faceView, 
            &meshinfo_out, 
            &v0->surfaceInfo.face.texVertOffset);
#ifdef SITHRENDER_SPHERE_TEST_SURFACES
        } else {
            rdPrimit3_NoClipFace(/*pSurfaceFrustum,*/
                v9->geometryMode, 
                v9->lightingMode, 
                v9->textureMode, 
                &sithRender_faceView, 
                &meshinfo_out, 
                &v0->surfaceInfo.face.texVertOffset);
        }
#endif
        
        if ( meshinfo_out.numVertices < 3u )
        {
            continue;
        }
        rdCamera_g_pCurCamera->pfProjectList(v9->aVertices, sithRender_aClipVertices, meshinfo_out.numVertices);
        
        v9->ambientLight = stdMath_Clamp(surfaceSector->extraLight + sithRender_008d4098, 0.0, 1.0);

        // These light optimizations are for the sw renderer
#ifndef TARGET_TWL
        if ( v9->ambientLight < 1.0 )
        {
            if ( v9->lightingMode == RD_LIGHTMODE_DIFFUSE)
            {
                if ( v9->light_level_static >= 1.0 && surfaceSector->colormap == sithWorld_g_pCurrentWorld->colormaps )
                {
                    v9->lightingMode = RD_LIGHTMODE_FULLYLIT;
                }
                else if ( v9->light_level_static <= 0.0 )
                {
                    v9->lightingMode = RD_LIGHTMODE_NOTLIT;
                }
            }
            else if ( v9->lightingMode == RD_LIGHTMODE_GOURAUD)
            {
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
                {

                }
                else if ( v31 != 1.0 )
                {
                    if ( v31 == 0.0 )
                    {
                        v9->lightingMode = RD_LIGHTMODE_NOTLIT;
                        v9->light_level_static = 0.0;
                    }
                    else
                    {
                        v9->lightingMode = RD_LIGHTMODE_DIFFUSE;
                        v9->light_level_static = v31;
                    }
                }
                else if ( surfaceSector->colormap != sithWorld_g_pCurrentWorld->colormaps )
                {
                    v9->lightingMode = RD_LIGHTMODE_DIFFUSE;
                    v9->light_level_static = 1.0;
                }
                else
                {
                    v9->lightingMode = RD_LIGHTMODE_FULLYLIT;
                }
            }
        }
        else
        {
            if ( surfaceSector->colormap != sithWorld_g_pCurrentWorld->colormaps )
            {
                v9->lightingMode = RD_LIGHTMODE_DIFFUSE;
                v9->light_level_static = 1.0;
            }
            else
            {
                v9->lightingMode = RD_LIGHTMODE_FULLYLIT;
            }
        }
#endif

        v23 = 1;
        if ( v9->geometryMode >= RD_GEOMETRY_FULL)
            v23 = 3;
        if ( v9->lightingMode >= RD_LIGHTMODE_GOURAUD)
            v23 |= 4u;

        v9->type = v0->surfaceInfo.face.type;
        v9->extralight = v0->surfaceInfo.face.extraLight;
        v9->wallCel = v0->surfaceInfo.face.wallCel;
        v9->light_flags = 0;
        v9->material = v0->surfaceInfo.face.material;
        rdSetProcFaceUserData(surfaceSector->id);
        rdCache_AddProcFace(0, meshinfo_out.numVertices, v23);
    }

    // DSi doesn't really have Z buffer options, so just batch everything
//#ifndef TARGET_TWL
    rdCache_Flush();
//#endif
#ifdef SDL2_RENDER
    rdSetZBufferMethod(RD_ZBUFFER_READ_WRITE);
#endif

    // Added: Ensure the clipping frustum doesn't get mutated
    rdCamera_g_pCurCamera->pClipFrustum = pFullCameraFrustum;
}

int sithRender_SetExtraThingRenderFunc(sithRender_weapRendFunc_t a1)
{
    sithRender_pExtraThingRenderFunc = a1;
    return 1;
}

// MoTS Added
void sithRender_WorldFlash(flex_t arg1,flex_t arg2)
{
  if ((arg1 != 0.0) && ((uint16_t)((uint16_t)(arg2 < 0.0) << 8 | (uint16_t)(arg2 == 0.0) << 0xe) == 0)) {
    sithRender_008d4094 = 1;
    sithRender_008d4098 = arg1;
    sithRender_008d409c = arg2;
  }
}


