#include "sithCogFunctionSurface.h"
#include "stdPlatform.h" // Added: for SITHLOG_*/SITH_ASSERT macros

#include "Cog/sithCogExec.h"
#include "World/sithWorld.h"
#include "World/sithSector.h"
#include "World/sithSurface.h"
#include "Main/Main.h"


void sithCogFunctionSurface_GetSurfaceAdjoin(sithCog *pCog)
{
    SithSurface* pSurface = sithCogExec_PopSurface(pCog);

    // TODO was this borked in JKDF2 and fixed in MoTS?
    // Previously: (v2 = &pSurface->pAdjoin->mirror->surface->index) != 0
    if ( pSurface && pSurface->pAdjoin->mirror->surface) 
        sithCogExec_PushInt(pCog, pSurface->pAdjoin->mirror->surface->index);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSurface_GetSurfaceSector(sithCog *pCog)
{
    SithSurface *v1; // eax
    uint32_t *v2; // eax

    v1 = sithCogExec_PopSurface(pCog);
    if ( v1 && (v2 = &v1->pSector->id) != 0 )
        sithCogExec_PushInt(pCog, *v2);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSurface_GetNumSurfaceVertices(sithCog *pCog)
{
    SithSurface *surface; // eax

    surface = sithCogExec_PopSurface(pCog);
    if ( surface )
        sithCogExec_PushInt(pCog, surface->surfaceInfo.face.numVertices);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSurface_GetSurfaceVertexPos(sithCog *pCog)
{
    uint32_t vtx_idx; // edi
    SithSurface *surface; // eax

    vtx_idx = sithCogExec_PopInt(pCog);
    surface = sithCogExec_PopSurface(pCog);
    if ( surface && vtx_idx < surface->surfaceInfo.face.numVertices && (vtx_idx & 0x80000000) == 0 )
        sithCogExec_PushVector(pCog, &sithWorld_g_pCurrentWorld->aVertices[surface->surfaceInfo.face.vertexPosIdx[vtx_idx]]);
    else
        sithCogExec_PushVector(pCog, &rdroid_zeroVector3);
}

void sithCogFunctionSurface_SetHorizonSkyOffset(sithCog *pCog)
{
    rdVector3 offs;

    // TODO add valid check?
    sithCogExec_PopVector(pCog, &offs);
    sithWorld_g_pCurrentWorld->horizonSkyOffset.x = offs.x;
    sithWorld_g_pCurrentWorld->horizonSkyOffset.y = offs.y;
}

void sithCogFunctionSurface_GetHorizonSkyOffset(sithCog *pCog)
{
    rdVector3 offs;

    offs.x = sithWorld_g_pCurrentWorld->horizonSkyOffset.x;
    offs.y = sithWorld_g_pCurrentWorld->horizonSkyOffset.y;
    offs.z = 0.0;
    sithCogExec_PushVector(pCog, &offs);
}

void sithCogFunctionSurface_SetCeilingSkyOffset(sithCog *pCog)
{
    rdVector3 offs;

    // TODO add valid check?
    sithCogExec_PopVector(pCog, &offs);
    sithWorld_g_pCurrentWorld->ceilingSkyOffset.x = offs.x;
    sithWorld_g_pCurrentWorld->ceilingSkyOffset.y = offs.y;
}

void sithCogFunctionSurface_GetCeilingSkyOffset(sithCog *pCog)
{
    rdVector3 offs;

    offs.x = sithWorld_g_pCurrentWorld->ceilingSkyOffset.x;
    offs.y = sithWorld_g_pCurrentWorld->ceilingSkyOffset.y;
    offs.z = 0.0;
    sithCogExec_PushVector(pCog, &offs);
}

void sithCogFunctionSurface_SlideHorizonSky(sithCog *pCog)
{
    rdSurface *v2;
    rdVector2 a2;

    a2.y = sithCogExec_PopFlex(pCog);
    a2.x = sithCogExec_PopFlex(pCog);
    v2 = sithSurface_SlideHorizonSky(0x200, &a2);
    if ( v2 )
        sithCogExec_PushInt(pCog, v2->index);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSurface_SlideCeilingSky(sithCog *pCog)
{
    rdSurface *v2;
    rdVector2 a2;

    a2.y = sithCogExec_PopFlex(pCog);
    a2.x = sithCogExec_PopFlex(pCog);
    v2 = sithSurface_SlideHorizonSky(0x400, &a2);
    if ( v2 )
        sithCogExec_PushInt(pCog, v2->index);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSurface_SurfaceLightAnim(sithCog *pCog)
{
    rdSurface *v3; // eax
    float v4; // [esp+0h] [ebp-14h]

    cog_flex_t v5 = sithCogExec_PopFlex(pCog);
    cog_flex_t v6 = sithCogExec_PopFlex(pCog);
    cog_flex_t a1 = sithCogExec_PopFlex(pCog);
    SithSurface* v2 = sithCogExec_PopSurface(pCog);
    if ( v2 && v6 >= (flex_d_t)a1 && v5 > 0.0 && (v4 = v5 * 0.5, v2->surfaceInfo.face.extraLight = a1, (v3 = sithSurface_SurfaceLightAnim(v2, v6, v4)) != 0) )
        sithCogExec_PushInt(pCog, v3->index);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSurface_SlideWall(sithCog *pCog)
{
    signed int pop_vec; // ebx
    SithSurface *surface; // eax
    SithSurface *v4; // edi
    rdSurface *v5; // ebx
    rdVector3 v7; // [esp+Ch] [ebp-Ch] BYREF

    cog_flex_t scale = sithCogExec_PopFlex(pCog) * 0.1;
    pop_vec = sithCogExec_PopVector(pCog, &v7);
    surface = sithCogExec_PopSurface(pCog);
    v4 = surface;
    if ( surface
      && surface->surfaceInfo.face.material
      && pop_vec
      && (v7.x = scale * v7.x, v7.y = scale * v7.y, v7.z = scale * v7.z, (v5 = sithSurface_SlideWall(surface, &v7)) != 0) )
    {
        if ( COG_SHOULD_SYNC(pCog) )
        {
            sithSurface_SyncSurface(v4);
        }
        sithCogExec_PushInt(pCog, v5->index);
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionSurface_GetWallCel(sithCog *pCog)
{
    SITH_ASSERTREL(pCog); // Added: ported J3D assert
    SithSurface* surface = sithCogExec_PopSurface(pCog);
    if ( surface && surface->surfaceInfo.face.material )
        sithCogExec_PushInt(pCog, surface->surfaceInfo.face.wallCel);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSurface_SetWallCel(sithCog *pCog)
{
    SITH_ASSERTREL(pCog); // Added: ported J3D assert
    int wallCel; // esi
    SithSurface *surface; // eax
    rdMaterial *v3; // ecx
    int v4; // ebx

    wallCel = sithCogExec_PopInt(pCog);
    surface = sithCogExec_PopSurface(pCog);
    if ( surface && (v3 = surface->surfaceInfo.face.material) != 0 && wallCel >= -1 && wallCel < v3->num_texinfo )
    {
        v4 = surface->surfaceInfo.face.wallCel;
        surface->surfaceInfo.face.wallCel = wallCel;
        if (COG_SHOULD_SYNC(pCog))
        {
            sithSurface_SyncSurface(surface);
        }
        sithCogExec_PushInt(pCog, v4);
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionSurface_GetSurfaceMaterial(sithCog *pCog)
{
    rdMaterial *v2; // eax

    SithSurface* surface = sithCogExec_PopSurface(pCog);
    if ( surface && (v2 = surface->surfaceInfo.face.material) != 0 )
        sithCogExec_PushInt(pCog, v2 - sithWorld_g_pCurrentWorld->aMaterials);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSurface_SetSurfaceMaterial(sithCog *pCog)
{
    rdMaterial *v4; // eax

    rdMaterial* mat = sithCogExec_PopMaterial(pCog);
    SithSurface* surface = sithCogExec_PopSurface(pCog);
    if ( surface )
    {
        v4 = surface->surfaceInfo.face.material;
        surface->surfaceInfo.face.material = mat;
        if ( v4 )
            sithCogExec_PushInt(pCog, v4 - sithWorld_g_pCurrentWorld->aMaterials);
        else
            sithCogExec_PushInt(pCog, -1);
        if ( COG_SHOULD_SYNC(pCog) )
        {
            sithSurface_SyncSurface(surface);
        }
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionSurface_SetSurfaceFlags(sithCog *pCog)
{
    uint32_t flags = sithCogExec_PopInt(pCog);
    SithSurface* surface = sithCogExec_PopSurface(pCog);

    if (surface && flags)
    {
        surface->flags |= flags;
        if (COG_SHOULD_SYNC(pCog))
        {
            sithSurface_SyncSurface(surface);
        }
    }
}

void sithCogFunctionSurface_ClearSurfaceFlags(sithCog *pCog)
{
    uint32_t flags = sithCogExec_PopInt(pCog);
    SithSurface* surface = sithCogExec_PopSurface(pCog);

    if (surface && flags)
    {
        surface->flags &= ~flags;
        if (COG_SHOULD_SYNC(pCog))
        {
            sithSurface_SyncSurface(surface);
        }
    }
}

void sithCogFunctionSurface_GetSurfaceFlags(sithCog *pCog)
{
    SithSurface* surface = sithCogExec_PopSurface(pCog);

    if ( surface )
        sithCogExec_PushInt(pCog, surface->flags);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSurface_SetAdjoinFlags(sithCog *pCog)
{
    uint32_t flags = sithCogExec_PopInt(pCog);
    SithSurface* surface = sithCogExec_PopSurface(pCog);

    if ( surface )
    {
        SithSurfaceAdjoin* pAdjoin = surface->pAdjoin;
        if ( pAdjoin )
        {
            if ( flags )
            {
                pAdjoin->flags |= flags;
                if ( COG_SHOULD_SYNC(pCog) )
                {
                    sithSurface_SyncSurface(surface);
                }
            }
        }
    }
}

void sithCogFunctionSurface_ClearAdjoinFlags(sithCog *pCog)
{
    uint32_t flags = sithCogExec_PopInt(pCog);
    SithSurface* surface = sithCogExec_PopSurface(pCog);

    if ( surface )
    {
        SithSurfaceAdjoin* pAdjoin = surface->pAdjoin;
        if ( pAdjoin )
        {
            if ( flags )
            {
                pAdjoin->flags &= ~flags;
                if ( COG_SHOULD_SYNC(pCog) )
                {
                     sithSurface_SyncSurface(surface);
                }
            }
        }
    }
}

void sithCogFunctionSurface_GetAdjoinFlags(sithCog *pCog)
{
    SithSurface* surface = sithCogExec_PopSurface(pCog);
    if (surface && surface->pAdjoin)
    {
        sithCogExec_PushInt(pCog, surface->pAdjoin->flags);
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionSurface_SetFaceType(sithCog *pCog)
{
    uint32_t type = sithCogExec_PopInt(pCog);
    SithSurface* surface = sithCogExec_PopSurface(pCog);
    if ( surface )
    {
        surface->surfaceInfo.face.type |= type;
        if (COG_SHOULD_SYNC(pCog))
        {
            sithSurface_SyncSurface(surface);
        }
    }
}

void sithCogFunctionSurface_ClearFaceType(sithCog *pCog)
{
    uint32_t type = sithCogExec_PopInt(pCog);
    SithSurface* surface = sithCogExec_PopSurface(pCog);
    if ( surface )
    {
        surface->surfaceInfo.face.type &= ~type;
        if (COG_SHOULD_SYNC(pCog))
        {
            sithSurface_SyncSurface(surface);
        }
    }
}

void sithCogFunctionSurface_GetFaceType(sithCog *pCog)
{
    SithSurface* surface = sithCogExec_PopSurface(pCog);
    if ( surface )
        sithCogExec_PushInt(pCog, surface->surfaceInfo.face.type);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSurface_SetFaceGeoMode(sithCog *pCog)
{
    rdGeoMode_t geoMode; // edi
    SithSurface *v2; // eax

    geoMode = (rdGeoMode_t)sithCogExec_PopInt(pCog);
    v2 = sithCogExec_PopSurface(pCog);
    if ( v2 )
    {
        if ( v2->surfaceInfo.face.material )
        {
            // MoTS added
            if (!v2->surfaceInfo.face.vertexUVIdx && geoMode == RD_GEOMETRY_FULL) {
                geoMode = RD_GEOMETRY_SOLID;
            }

            v2->surfaceInfo.face.geometryMode = geoMode;
            if ( COG_SHOULD_SYNC(pCog) )
            {
                sithSurface_SyncSurface(v2);
                return;
            }
        }
        else
        {
            v2->surfaceInfo.face.geometryMode = RD_GEOMETRY_NONE;
            if ( COG_SHOULD_SYNC(pCog) )
            {
                sithSurface_SyncSurface(v2);
                return;
            }
        }
    }
}

void sithCogFunctionSurface_GetFaceGeoMode(sithCog *pCog)
{
    SithSurface *v1; // eax

    v1 = sithCogExec_PopSurface(pCog);
    if ( v1 )
        sithCogExec_PushInt(pCog, (int)v1->surfaceInfo.face.geometryMode);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSurface_SetFaceLightMode(sithCog *pCog)
{
    rdLightMode_t lightMode; // edi
    SithSurface *v2; // eax

    lightMode = (rdLightMode_t)sithCogExec_PopInt(pCog);
    v2 = sithCogExec_PopSurface(pCog);
    if ( v2 )
    {
        v2->surfaceInfo.face.lightingMode = lightMode;
        if ( COG_SHOULD_SYNC(pCog) )
        {
            sithSurface_SyncSurface(v2);
        }
    }
}

void sithCogFunctionSurface_GetFaceLightMode(sithCog *pCog)
{
    SithSurface *v1; // eax

    v1 = sithCogExec_PopSurface(pCog);
    if ( v1 )
        sithCogExec_PushInt(pCog, (int)v1->surfaceInfo.face.lightingMode);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSurface_SetFaceTexMode(sithCog *pCog)
{
    rdTexMode_t texMode; // edi
    SithSurface *v2; // eax

    texMode = (rdTexMode_t)sithCogExec_PopInt(pCog);
    v2 = sithCogExec_PopSurface(pCog);
    if ( v2 )
    {
        v2->surfaceInfo.face.textureMode = texMode;
        if ( COG_SHOULD_SYNC(pCog) )
        {
            sithSurface_SyncSurface(v2);
        }
    }
}

void sithCogFunctionSurface_GetFaceTexMode(sithCog *pCog)
{
    SithSurface *v1; // eax

    v1 = sithCogExec_PopSurface(pCog);
    if ( v1 )
        sithCogExec_PushInt(pCog, (int)v1->surfaceInfo.face.textureMode);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSurface_SetSurfaceLight(sithCog *pCog)
{
    SithSurface *v2; // ecx

    cog_flex_t v4 = sithCogExec_PopFlex(pCog);
    cog_flex_t a1 = sithCogExec_PopFlex(pCog);
    v2 = sithCogExec_PopSurface(pCog);
    if ( v2 && a1 >= 0.0 )
    {
        if ( v4 == 0.0 )
        {
            v2->surfaceInfo.face.extraLight = a1;
            if ( COG_SHOULD_SYNC(pCog) )
            {
                sithSurface_SyncSurface(v2);
            }
        }
        else
        {
            sithSurface_SurfaceLightAnim(v2, a1, v4);
        }
    }
}

void sithCogFunctionSurface_GetSurfaceLight(sithCog *pCog)
{
    SithSurface *v1; // eax

    v1 = sithCogExec_PopSurface(pCog);
    if ( v1 ) {
        sithCogExec_PushFlex(pCog, v1->surfaceInfo.face.extraLight);
    }
    // TODO: Always return *something*?
}

void sithCogFunctionSurface_GetSurfaceCenter(sithCog *pCog)
{
    SithSurface *v1; // eax
    rdVector3 a2; // [esp+4h] [ebp-Ch] BYREF

    v1 = sithCogExec_PopSurface(pCog);
    if ( v1 )
    {
        sithSurface_GetCenterPoint(v1, &a2);
        sithCogExec_PushVector(pCog, &a2);
    }
    else
    {
        sithCogExec_PushVector(pCog, &rdroid_zeroVector3);
    }
}

void sithCogFunctionSurface_GetSurfaceCount(sithCog *pCog)
{
    if ( sithWorld_g_pCurrentWorld )
        sithCogExec_PushInt(pCog, sithWorld_g_pCurrentWorld->numSurfaces);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSurface_GetSurfaceNormal(sithCog *pCog)
{
    SithSurface *v1; // eax

    v1 = sithCogExec_PopSurface(pCog);
    if ( v1 )
        sithCogExec_PushVector(pCog, &v1->surfaceInfo.face.normal);
    else
        sithCogExec_PushVector(pCog, &rdroid_zeroVector3);
}

void sithCogFunctionSurface_SyncSurface(sithCog *pCog)
{
    SithSurface *v1; // eax

    v1 = sithCogExec_PopSurface(pCog);
    if ( v1 )
        sithSurface_SyncSurface(v1);
}

// MOTS added
void sithCogFunctionSurface_GetSurfaceVertexLight(sithCog *pCog)
{
    int num = sithCogExec_PopInt(pCog);
    SithSurface* pSurface = sithCogExec_PopSurface(pCog);
    
    if ((pSurface && (num < (pSurface->surfaceInfo).face.numVertices)) && num > -1) {
        sithCogExec_PushFlex(pCog,(pSurface->surfaceInfo).intensities[num]);
        return;
    }
    
    sithCogExec_PushFlex(pCog,-1.0);
}

// MOTS added
void sithCogFunctionSurface_SetSurfaceVertexLight(sithCog *pCog)
{
    cog_flex_t val = sithCogExec_PopFlex(pCog);
    int num = sithCogExec_PopInt(pCog);
    SithSurface* pSurface = sithCogExec_PopSurface(pCog);

    if ((pSurface && ((uint32_t)num < (pSurface->surfaceInfo).face.numVertices)) && num > -1) {
        (pSurface->surfaceInfo).intensities[num] = val;
    }
}

// MOTS added
void sithCogFunctionSurface_GetSurfaceVertexLightRGB(sithCog *pCog)
{
    rdVector3 tmp;

    int num = sithCogExec_PopInt(pCog);
    SithSurface* pSurface = sithCogExec_PopSurface(pCog);
    if (pSurface == (SithSurface *)0x0) {
        tmp.x = -1.0;
        tmp.y = -1.0;
        tmp.z = -1.0;
        sithCogExec_PushVector(pCog,&tmp);
        return;
    }

    uint32_t numVerts = (pSurface->surfaceInfo).face.numVertices;
    if ((num < numVerts) && (-1 < num)) {
        if ((pSurface->flags & SITH_SURFACE_1000000) == 0) {
            tmp.x = -1.0;
            tmp.y = -1.0;
            tmp.z = -1.0;
            sithCogExec_PushVector(pCog,&tmp);
            return;
        }
        tmp.x = (pSurface->surfaceInfo).intensities[num + numVerts];
        tmp.y = (pSurface->surfaceInfo).intensities[num + (pSurface->surfaceInfo).face.numVertices * 2];
        tmp.z = (pSurface->surfaceInfo).intensities[num + (pSurface->surfaceInfo).face.numVertices * 3];
        sithCogExec_PushVector(pCog,&tmp);
        return;
    }

    tmp.x = -1.0;
    tmp.y = -1.0;
    tmp.z = -1.0;
    sithCogExec_PushVector(pCog,&tmp);
}

// MOTS added
void sithCogFunctionSurface_SetSurfaceVertexLightRGB(sithCog *pCog)
{
    rdVector3 valRGB;
    uint32_t uVar1;
    
    sithCogExec_PopVector(pCog, &valRGB);
    int num = sithCogExec_PopInt(pCog);
    SithSurface* pSurface = sithCogExec_PopSurface(pCog);

    if ((((pSurface != (SithSurface *)0x0) 
        && (uVar1 = (pSurface->surfaceInfo).face.numVertices, (uint32_t)num < uVar1)) && (-1 < num)) 
        && ((pSurface->flags & SITH_SURFACE_1000000) != 0)) {
        (pSurface->surfaceInfo).intensities[num + uVar1] = valRGB.x;
        (pSurface->surfaceInfo).intensities[num + (pSurface->surfaceInfo).face.numVertices * 2] = valRGB.y;
        (pSurface->surfaceInfo).intensities[num + (pSurface->surfaceInfo).face.numVertices * 3] = valRGB.z;
    }
}

void sithCogFunctionSurface_Startup(SithCogSymbolTable* pCog)
{
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetSurfaceAdjoin, "getsurfaceadjoin");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetSurfaceSector, "getsurfacesector");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetNumSurfaceVertices, "getnumsurfacevertices");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetSurfaceVertexPos, "getsurfacevertexpos");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SetHorizonSkyOffset, "sethorizonskyoffset");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetHorizonSkyOffset, "gethorizonskyoffset");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SetCeilingSkyOffset, "setceilingskyoffset");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetCeilingSkyOffset, "getceilingskyoffset");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SlideHorizonSky, "slidehorizonsky");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SlideCeilingSky, "slideceilingsky");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetSurfaceCount, "getsurfacecount");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SlideWall, "slidewall");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SlideWall, "slidesurface");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetWallCel, "getwallcel");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SetWallCel, "setwallcel");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetWallCel, "getsurfacecel");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SetWallCel, "setsurfacecel");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetSurfaceMaterial, "getsurfacemat");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SetSurfaceMaterial, "setsurfacemat");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetSurfaceFlags, "getsurfaceflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SetSurfaceFlags, "setsurfaceflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_ClearSurfaceFlags, "clearsurfaceflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetAdjoinFlags, "getadjoinflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SetAdjoinFlags, "setadjoinflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_ClearAdjoinFlags, "clearadjoinflags");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SetFaceType, "setfacetype");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_ClearFaceType, "clearfacetype");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetFaceType, "getfacetype");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SetFaceGeoMode, "setfacegeomode");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetFaceGeoMode, "getfacegeomode");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SetFaceLightMode, "setfacelightmode");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetFaceLightMode, "getfacelightmode");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SetFaceTexMode, "setfacetexmode");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetFaceTexMode, "getfacetexmode");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetSurfaceLight, "getsurfacelight");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SetSurfaceLight, "setsurfacelight");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SetSurfaceLight, "surfacelight");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetSurfaceCenter, "getsurfacecenter");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetSurfaceCenter, "surfacecenter");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SurfaceLightAnim, "surfacelightanim");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetSurfaceNormal, "getsurfacenormal");
    sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SyncSurface, "syncsurface");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetSurfaceVertexLight, "getsurfacevertexlight");
        sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SetSurfaceVertexLight, "setsurfacevertexlight");
        sithCog_RegisterFunction(pCog, sithCogFunctionSurface_GetSurfaceVertexLightRGB, "getsurfacevertexlightrgb");
        sithCog_RegisterFunction(pCog, sithCogFunctionSurface_SetSurfaceVertexLightRGB, "setsurfacevertexlightrgb");
    }
}
