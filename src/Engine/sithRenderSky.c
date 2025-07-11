#include "sithRenderSky.h"

#include "General/stdMath.h"
#include "Engine/sithCamera.h"
#include "Engine/sithIntersect.h"
#include "World/sithSector.h"
#include "jk.h"

int sithRenderSky_Open(flex_t horizontalPixelsPerRev, flex_t horizontalDist, flex_t ceilingSky)
{
    sithSector_horizontalPixelsPerRev_idk = horizontalPixelsPerRev * 0.0027777778;
    sithSector_horizontalDist = horizontalDist;
    sithSector_ceilingSky = ceilingSky;
    sithSector_zMaxVec.x = 0.0;
    sithSector_zMaxVec.y = 0.0;
    sithSector_zMaxVec.z = ceilingSky;
    sithSector_horizontalPixelsPerRev = horizontalPixelsPerRev;
    sithSector_zMinVec.x = 0.0;
    sithSector_zMinVec.y = 0.0;
    sithSector_zMinVec.z = -ceilingSky;
    return 1;
}

void sithRenderSky_Close()
{
}

void sithRenderSky_Update()
{
    sithSector_flt_8553C0 = sithSector_horizontalDist / rdCamera_pCurCamera->fov_y;
    stdMath_SinCos(sithCamera_currentCamera->viewPYR.z, &sithSector_flt_8553F4, &sithSector_flt_8553C8);
    sithSector_flt_8553B8 = -(sithCamera_currentCamera->viewPYR.y * sithSector_horizontalPixelsPerRev_idk);
    sithSector_flt_8553C4 = -(sithCamera_currentCamera->viewPYR.x * sithSector_horizontalPixelsPerRev_idk);
}

// As seen in: Return Home to Sloan
void sithRenderSky_TransformHorizontal(rdProcEntry *pProcEntry, sithSurfaceInfo *pSurfaceInfo, uint32_t num_vertices)
{
    rdVector2 *pVertUV;
    rdVector3 *pVertXYZ;
    flex_d_t tmp1;
    flex_d_t tmp2;

    pProcEntry->geometryMode = sithRender_geoMode > RD_GEOMODE_TEXTURED ? RD_GEOMODE_TEXTURED : sithRender_geoMode;
    pProcEntry->lightingMode = sithRender_lightMode > RD_LIGHTMODE_FULLYLIT ? RD_LIGHTMODE_FULLYLIT : sithRender_lightMode;
    pProcEntry->textureMode = sithRender_texMode > RD_TEXTUREMODE_AFFINE ? RD_TEXTUREMODE_AFFINE : sithRender_texMode;
    
    pVertUV = pProcEntry->vertexUVs;
    pVertXYZ = pProcEntry->vertices;

    while ( num_vertices )
    {
        pVertXYZ->z = rdCamera_pCurCamera->pClipFrustum->zFar; // zFar
#ifdef TARGET_TWL
        pVertXYZ->z = 2.0f; // TODO figure out actual zfar or do this hack somewhere else
#endif

        tmp1 = (pVertXYZ->x - rdCamera_pCurCamera->canvas->screen_height_half) * sithSector_flt_8553C0;
        tmp2 = (pVertXYZ->y - rdCamera_pCurCamera->canvas->screen_width_half) * sithSector_flt_8553C0;
        pVertUV->x = tmp1 * sithSector_flt_8553C8 - tmp2 * sithSector_flt_8553F4 + sithSector_flt_8553B8;
        pVertUV->y = tmp2 * sithSector_flt_8553C8 + tmp1 * sithSector_flt_8553F4 + sithSector_flt_8553C4;
        rdVector_Add2Acc(pVertUV, &sithWorld_pCurrentWorld->horizontalSkyOffs);
        rdVector_Add2Acc(pVertUV, &pSurfaceInfo->face.clipIdk);

        ++pVertXYZ;
        ++pVertUV;
        --num_vertices;
    }
}

// As seen in: Canyon Oasis, Droidworks' `Pulley`
void sithRenderSky_TransformVertical(rdProcEntry *pProcEntry, sithSurfaceInfo *pSurfaceInfo, rdVector3 *pUntransformedVerts, uint32_t num_vertices)
{
    rdVector2 *pVertUV;
    rdVector3 a1a;
    rdVector3 a2a;
    rdVector3 vertex_out;

    pProcEntry->geometryMode = sithRender_geoMode > RD_GEOMODE_TEXTURED ? RD_GEOMODE_TEXTURED : sithRender_geoMode;
    pProcEntry->lightingMode = sithRender_lightMode > RD_LIGHTMODE_FULLYLIT ? RD_LIGHTMODE_FULLYLIT : sithRender_lightMode;
    // Weird, no texture mode, though idk if the affine mode even worked
#ifdef TARGET_TWL
    pProcEntry->textureMode = sithRender_texMode > RD_TEXTUREMODE_AFFINE ? RD_TEXTUREMODE_AFFINE : sithRender_texMode;
#endif

    for (uint32_t i = 0; i < num_vertices; i++)
    {
        rdMatrix_TransformPoint34(&a2a, &pUntransformedVerts[i], &rdCamera_camMatrix);
        rdVector_Sub3Acc(&a2a, &sithCamera_currentCamera->vec3_1);
        rdVector_Normalize3(&a1a, &a2a);
        
        flex_t tmp = 0.0;
        if (!sithIntersect_SphereHit(&sithCamera_currentCamera->vec3_1, &a1a, 1000.0, 0.0, &sithSector_surfaceNormal, &sithSector_zMaxVec, &tmp, 0)) {
            tmp = 1000.0;
        }
        rdVector_Scale3Acc(&a1a, tmp);
        pVertUV = &pProcEntry->vertexUVs[i];
        rdVector_Add3Acc(&a1a, &sithCamera_currentCamera->vec3_1);
        rdVector_Scale2(pVertUV, (rdVector2*)&a1a, 16.0);
        rdVector_Add2Acc(pVertUV, &sithWorld_pCurrentWorld->ceilingSkyOffs);
        rdVector_Add2Acc(pVertUV, &pSurfaceInfo->face.clipIdk);
        rdMatrix_TransformPoint34(&vertex_out, &a1a, &sithCamera_currentCamera->rdCam.view_matrix);

        pProcEntry->vertices[i].z = vertex_out.y;

        // TODO: There's a bug where facing a vertical wall of sky starts dividing strangely
#ifdef QOL_IMPROVEMENTS
        // Added: Clip Z to zfar
        pProcEntry->vertices[i].z = stdMath_Clamp(pProcEntry->vertices[i].z, 0.0f, rdCamera_pCurCamera->pClipFrustum->zFar);
#endif
#ifdef TARGET_TWL
        pProcEntry->vertices[i].z = 2.0f; // TODO figure out actual zfar or do this hack somewhere else
#endif
    }
}