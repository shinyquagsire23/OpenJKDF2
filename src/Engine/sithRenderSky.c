#include "sithRenderSky.h"

#include "General/stdMath.h"
#include "Engine/sithCamera.h"
#include "Engine/sithIntersect.h"
#include "World/sithSector.h"
#include "jk.h"

int sithRenderSky_Open(flex_t horizontalPixelsPerRev, flex_t horizontalDist, flex_t ceilingSkyHeight)
{
    sithSector_horizontalPixelsPerRev_idk = horizontalPixelsPerRev * 0.0027777778;
    sithSector_horizontalDist = horizontalDist;
    sithSector_ceilingSky = ceilingSkyHeight;
    sithSector_zMaxVec.x = 0.0;
    sithSector_zMaxVec.y = 0.0;
    sithSector_zMaxVec.z = ceilingSkyHeight;
    sithSector_horizontalPixelsPerRev = horizontalPixelsPerRev;
    sithSector_zMinVec.x = 0.0;
    sithSector_zMinVec.y = 0.0;
    sithSector_zMinVec.z = -ceilingSkyHeight;
    return 1;
}

void sithRenderSky_Close()
{
}

void sithRenderSky_Update()
{
    sithSector_flt_8553C0 = sithSector_horizontalDist / rdCamera_g_pCurCamera->fovDx;
    stdMath_SinCos(sithCamera_g_pCurCamera->lookPYR.z, &sithSector_flt_8553F4, &sithSector_flt_8553C8);
    sithSector_flt_8553B8 = -(sithCamera_g_pCurCamera->lookPYR.y * sithSector_horizontalPixelsPerRev_idk);
    sithSector_flt_8553C4 = -(sithCamera_g_pCurCamera->lookPYR.x * sithSector_horizontalPixelsPerRev_idk);
}

// As seen in: Return Home to Sulon
void sithRenderSky_HorizonFaceToPlane(rdProcEntry *pProcEntry, sithSurfaceInfo *pSurfaceInfo, uint32_t num_vertices)
{
    rdVector2 *pVertUV;
    rdVector3 *pVertXYZ;
    flex_d_t tmp1;
    flex_d_t tmp2;

    pProcEntry->geometryMode = sithRender_geoMode > RD_GEOMETRY_FULL ? RD_GEOMETRY_FULL : sithRender_geoMode;
    pProcEntry->lightingMode = sithRender_lightMode > RD_LIGHTMODE_FULLYLIT ? RD_LIGHTMODE_FULLYLIT : sithRender_lightMode;
    pProcEntry->textureMode = sithRender_texMode > RD_TEXTUREMODE_AFFINE ? RD_TEXTUREMODE_AFFINE : sithRender_texMode;
    
    pVertUV = pProcEntry->aTexVerticies;
    pVertXYZ = pProcEntry->aVertices;

    while ( num_vertices )
    {
#ifdef TARGET_TWL
        rdVector3 proj;
        rdCamera_g_pCurCamera->fnProjectLstClip(&proj, pVertXYZ, 1);
        tmp1 = (proj.x - rdCamera_g_pCurCamera->canvas->half_screen_width) * sithSector_flt_8553C0;
        tmp2 = (proj.y - rdCamera_g_pCurCamera->canvas->half_screen_height) * sithSector_flt_8553C0;

        flex_t prev_z = pVertXYZ->y;
        pVertXYZ->y = rdCamera_g_pCurCamera->pClipFrustum->zFar - 0.1;

        pVertXYZ->x /= prev_z;
        pVertXYZ->x *= pVertXYZ->y;
        pVertXYZ->z /= prev_z;
        pVertXYZ->z *= pVertXYZ->y;
#else
        pVertXYZ->z = rdCamera_g_pCurCamera->pClipFrustum->zFar; // zFar
        tmp1 = (pVertXYZ->x - rdCamera_g_pCurCamera->canvas->half_screen_width) * sithSector_flt_8553C0;
        tmp2 = (pVertXYZ->y - rdCamera_g_pCurCamera->canvas->half_screen_height) * sithSector_flt_8553C0;
#endif

        pVertUV->x = tmp1 * sithSector_flt_8553C8 - tmp2 * sithSector_flt_8553F4 + sithSector_flt_8553B8;
        pVertUV->y = tmp2 * sithSector_flt_8553C8 + tmp1 * sithSector_flt_8553F4 + sithSector_flt_8553C4;
        rdVector_Add2Acc(pVertUV, &sithWorld_g_pCurrentWorld->horizonSkyOffset);
        rdVector_Add2Acc(pVertUV, &pSurfaceInfo->face.clipIdk);

        ++pVertXYZ;
        ++pVertUV;
        --num_vertices;
    }
}

// As seen in: Canyon Oasis, Droidworks' `Pulley`
void sithRenderSky_CeilingFaceToPlane(rdProcEntry *pProcEntry, sithSurfaceInfo *pSurfaceInfo, rdVector3 *pUntransformedVerts, uint32_t num_vertices)
{
    rdVector2 *pVertUV;
    rdVector3 a1a;
    rdVector3 a2a;
    rdVector3 vertex_out;

    pProcEntry->geometryMode = sithRender_geoMode > RD_GEOMETRY_FULL ? RD_GEOMETRY_FULL : sithRender_geoMode;
    pProcEntry->lightingMode = sithRender_lightMode > RD_LIGHTMODE_FULLYLIT ? RD_LIGHTMODE_FULLYLIT : sithRender_lightMode;
    // Weird, no texture mode, though idk if the affine mode even worked
#ifdef TARGET_TWL
    pProcEntry->textureMode = sithRender_texMode > RD_TEXTUREMODE_AFFINE ? RD_TEXTUREMODE_AFFINE : sithRender_texMode;
#endif

    // Jones3D does this, idk
#ifdef QOL_IMPROVEMENTS
    //float invMatWidth = 1.0f / (float)pSurfaceInfo->face.material->texinfos[0]->texture_ptr->texture_struct[0]->format.width;
    //float invMatHeight = 1.0f / (float)pSurfaceInfo->face.material->texinfos[0]->texture_ptr->texture_struct[0]->format.height;
#endif

    // TODO: Clamp aVertices to horizon? Would be easier to just have a skybox tbh
#ifdef QOL_IMPROVEMENTS
    //BOOL bHitTestFailed = false;
#endif

    for (uint32_t i = 0; i < num_vertices; i++)
    {
        rdMatrix_TransformPoint34(&a2a, &pUntransformedVerts[i], &rdCamera_g_camMatrix);
        rdVector_Sub3Acc(&a2a, &sithCamera_g_pCurCamera->lookPos);

        // This seems to bug out when a2a.z < 0.0 (not sure how that's even happening)
        rdVector_Normalize3(&a1a, &a2a);

        const flex_t hitTestMaxZ = 1000.0;
        flex_t tmp = 0.0;
        if (!sithIntersect_CheckSphereHit(&sithCamera_g_pCurCamera->lookPos, &a1a, hitTestMaxZ, 0.0, &sithSector_surfaceNormal, &sithSector_zMaxVec, &tmp, 0)) {
            tmp = hitTestMaxZ;
#ifdef QOL_IMPROVEMENTS
            /*bHitTestFailed = true;
            break;*/
#endif
        }
        rdVector_Scale3Acc(&a1a, tmp);
        pVertUV = &pProcEntry->aTexVerticies[i];
        rdVector_Add3Acc(&a1a, &sithCamera_g_pCurCamera->lookPos);
        rdVector_Scale2(pVertUV, (rdVector2*)&a1a, 16.0);

#ifdef QOL_IMPROVEMENTS
        //pVertUV->x *= invMatWidth;
        //pVertUV->y *= invMatHeight;
#endif

        rdVector_Add2Acc(pVertUV, &sithWorld_g_pCurrentWorld->ceilingSkyOffset);
        rdVector_Add2Acc(pVertUV, &pSurfaceInfo->face.clipIdk);
        rdMatrix_TransformPoint34(&vertex_out, &a1a, &sithCamera_g_pCurCamera->rdCamera.view_matrix);

#ifdef TARGET_TWL
        flex_t prev_z = pProcEntry->aVertices[i].y;
        vertex_out.y *= 0.15;
        pProcEntry->aVertices[i].y = vertex_out.y;
        pProcEntry->aVertices[i].y = stdMath_Clamp(pProcEntry->aVertices[i].y, 0.0f, rdCamera_g_pCurCamera->pClipFrustum->zFar - 0.1);
        pProcEntry->aVertices[i].x /= prev_z;
        pProcEntry->aVertices[i].x *= pProcEntry->aVertices[i].y;
        pProcEntry->aVertices[i].z /= prev_z;
        pProcEntry->aVertices[i].z *= pProcEntry->aVertices[i].y;
#else
        pProcEntry->aVertices[i].z = vertex_out.y;
#endif
        // TODO: There's a bug where facing a vertical wall of sky starts dividing strangely
    }

#ifdef QOL_IMPROVEMENTS
    /*if (bHitTestFailed) {
        pProcEntry->geometryMode = RD_GEOMETRY_SOLID;
    }*/
#endif
}