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
    sithSector_flt_8553C0 = sithSector_horizontalDist / rdCamera_pCurCamera->fovDx;
    stdMath_SinCos(sithCamera_currentCamera->viewPYR.z, &sithSector_flt_8553F4, &sithSector_flt_8553C8);
    sithSector_flt_8553B8 = -(sithCamera_currentCamera->viewPYR.y * sithSector_horizontalPixelsPerRev_idk);
    sithSector_flt_8553C4 = -(sithCamera_currentCamera->viewPYR.x * sithSector_horizontalPixelsPerRev_idk);
}

// As seen in: Return Home to Sulon
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
#ifdef TARGET_TWL
        rdVector3 proj;
        rdCamera_pCurCamera->fnProjectLstClip(&proj, pVertXYZ, 1);
        tmp1 = (proj.x - rdCamera_pCurCamera->canvas->half_screen_width) * sithSector_flt_8553C0;
        tmp2 = (proj.y - rdCamera_pCurCamera->canvas->half_screen_height) * sithSector_flt_8553C0;

        flex_t prev_z = pVertXYZ->y;
        pVertXYZ->y = rdCamera_pCurCamera->pClipFrustum->zFar - 0.1;

        pVertXYZ->x /= prev_z;
        pVertXYZ->x *= pVertXYZ->y;
        pVertXYZ->z /= prev_z;
        pVertXYZ->z *= pVertXYZ->y;
#else
        pVertXYZ->z = rdCamera_pCurCamera->pClipFrustum->zFar; // zFar
        tmp1 = (pVertXYZ->x - rdCamera_pCurCamera->canvas->half_screen_width) * sithSector_flt_8553C0;
        tmp2 = (pVertXYZ->y - rdCamera_pCurCamera->canvas->half_screen_height) * sithSector_flt_8553C0;
#endif

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

    // Jones3D does this, idk
#ifdef QOL_IMPROVEMENTS
    //float invMatWidth = 1.0f / (float)pSurfaceInfo->face.material->texinfos[0]->texture_ptr->texture_struct[0]->format.width;
    //float invMatHeight = 1.0f / (float)pSurfaceInfo->face.material->texinfos[0]->texture_ptr->texture_struct[0]->format.height;
#endif

    // TODO: Clamp vertices to horizon? Would be easier to just have a skybox tbh
#ifdef QOL_IMPROVEMENTS
    //BOOL bHitTestFailed = false;
#endif

    for (uint32_t i = 0; i < num_vertices; i++)
    {
        rdMatrix_TransformPoint34(&a2a, &pUntransformedVerts[i], &rdCamera_camMatrix);
        rdVector_Sub3Acc(&a2a, &sithCamera_currentCamera->vec3_1);

        // This seems to bug out when a2a.z < 0.0 (not sure how that's even happening)
        rdVector_Normalize3(&a1a, &a2a);

        const flex_t hitTestMaxZ = 1000.0;
        flex_t tmp = 0.0;
        if (!sithIntersect_SphereHit(&sithCamera_currentCamera->vec3_1, &a1a, hitTestMaxZ, 0.0, &sithSector_surfaceNormal, &sithSector_zMaxVec, &tmp, 0)) {
            tmp = hitTestMaxZ;
#ifdef QOL_IMPROVEMENTS
            /*bHitTestFailed = true;
            break;*/
#endif
        }
        rdVector_Scale3Acc(&a1a, tmp);
        pVertUV = &pProcEntry->vertexUVs[i];
        rdVector_Add3Acc(&a1a, &sithCamera_currentCamera->vec3_1);
        rdVector_Scale2(pVertUV, (rdVector2*)&a1a, 16.0);

#ifdef QOL_IMPROVEMENTS
        //pVertUV->x *= invMatWidth;
        //pVertUV->y *= invMatHeight;
#endif

        rdVector_Add2Acc(pVertUV, &sithWorld_pCurrentWorld->ceilingSkyOffs);
        rdVector_Add2Acc(pVertUV, &pSurfaceInfo->face.clipIdk);
        rdMatrix_TransformPoint34(&vertex_out, &a1a, &sithCamera_currentCamera->rdCam.view_matrix);

#ifdef TARGET_TWL
        flex_t prev_z = pProcEntry->vertices[i].y;
        vertex_out.y *= 0.15;
        pProcEntry->vertices[i].y = vertex_out.y;
        pProcEntry->vertices[i].y = stdMath_Clamp(pProcEntry->vertices[i].y, 0.0f, rdCamera_pCurCamera->pClipFrustum->zFar - 0.1);
        pProcEntry->vertices[i].x /= prev_z;
        pProcEntry->vertices[i].x *= pProcEntry->vertices[i].y;
        pProcEntry->vertices[i].z /= prev_z;
        pProcEntry->vertices[i].z *= pProcEntry->vertices[i].y;
#else
        pProcEntry->vertices[i].z = vertex_out.y;
#endif
        // TODO: There's a bug where facing a vertical wall of sky starts dividing strangely
    }

#ifdef QOL_IMPROVEMENTS
    /*if (bHitTestFailed) {
        pProcEntry->geometryMode = RD_GEOMODE_SOLIDCOLOR;
    }*/
#endif
}