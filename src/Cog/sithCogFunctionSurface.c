#include "sithCogFunctionSurface.h"

#include "Cog/sithCogExec.h"
#include "World/sithWorld.h"
#include "World/sithSector.h"
#include "World/sithSurface.h"
#include "Main/Main.h"


void sithCogFunctionSurface_GetSurfaceAdjoin(sithCog *ctx)
{
    SithSurface* pSurface = sithCogExec_PopSurface(ctx);

    // TODO was this borked in JKDF2 and fixed in MoTS?
    // Previously: (v2 = &pSurface->adjoin->mirror->surface->index) != 0
    if ( pSurface && pSurface->adjoin->mirror->surface) 
        sithCogExec_PushInt(ctx, pSurface->adjoin->mirror->surface->index);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_GetSurfaceSector(sithCog *ctx)
{
    SithSurface *v1; // eax
    uint32_t *v2; // eax

    v1 = sithCogExec_PopSurface(ctx);
    if ( v1 && (v2 = &v1->parent_sector->id) != 0 )
        sithCogExec_PushInt(ctx, *v2);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_GetNumSurfaceVertices(sithCog *ctx)
{
    SithSurface *surface; // eax

    surface = sithCogExec_PopSurface(ctx);
    if ( surface )
        sithCogExec_PushInt(ctx, surface->surfaceInfo.face.numVertices);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_GetSurfaceVertexPos(sithCog *ctx)
{
    uint32_t vtx_idx; // edi
    SithSurface *surface; // eax

    vtx_idx = sithCogExec_PopInt(ctx);
    surface = sithCogExec_PopSurface(ctx);
    if ( surface && vtx_idx < surface->surfaceInfo.face.numVertices && (vtx_idx & 0x80000000) == 0 )
        sithCogExec_PushVector(ctx, &sithWorld_g_pCurrentWorld->vertices[surface->surfaceInfo.face.vertexPosIdx[vtx_idx]]);
    else
        sithCogExec_PushVector(ctx, &rdroid_zeroVector3);
}

void sithCogFunctionSurface_SetHorizonSkyOffset(sithCog *ctx)
{
    rdVector3 offs;

    // TODO add valid check?
    sithCogExec_PopVector(ctx, &offs);
    sithWorld_g_pCurrentWorld->horizontalSkyOffs.x = offs.x;
    sithWorld_g_pCurrentWorld->horizontalSkyOffs.y = offs.y;
}

void sithCogFunctionSurface_GetHorizonSkyOffset(sithCog *ctx)
{
    rdVector3 offs;

    offs.x = sithWorld_g_pCurrentWorld->horizontalSkyOffs.x;
    offs.y = sithWorld_g_pCurrentWorld->horizontalSkyOffs.y;
    offs.z = 0.0;
    sithCogExec_PushVector(ctx, &offs);
}

void sithCogFunctionSurface_SetCeilingSkyOffset(sithCog *ctx)
{
    rdVector3 offs;

    // TODO add valid check?
    sithCogExec_PopVector(ctx, &offs);
    sithWorld_g_pCurrentWorld->ceilingSkyOffs.x = offs.x;
    sithWorld_g_pCurrentWorld->ceilingSkyOffs.y = offs.y;
}

void sithCogFunctionSurface_GetCeilingSkyOffset(sithCog *ctx)
{
    rdVector3 offs;

    offs.x = sithWorld_g_pCurrentWorld->ceilingSkyOffs.x;
    offs.y = sithWorld_g_pCurrentWorld->ceilingSkyOffs.y;
    offs.z = 0.0;
    sithCogExec_PushVector(ctx, &offs);
}

void sithCogFunctionSurface_SlideHorizonSky(sithCog *ctx)
{
    rdSurface *v2;
    rdVector2 a2;

    a2.y = sithCogExec_PopFlex(ctx);
    a2.x = sithCogExec_PopFlex(ctx);
    v2 = sithSurface_SlideHorizonSky(0x200, &a2);
    if ( v2 )
        sithCogExec_PushInt(ctx, v2->index);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SlideCeilingSky(sithCog *ctx)
{
    rdSurface *v2;
    rdVector2 a2;

    a2.y = sithCogExec_PopFlex(ctx);
    a2.x = sithCogExec_PopFlex(ctx);
    v2 = sithSurface_SlideHorizonSky(0x400, &a2);
    if ( v2 )
        sithCogExec_PushInt(ctx, v2->index);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SurfaceLightAnim(sithCog *ctx)
{
    rdSurface *v3; // eax
    float v4; // [esp+0h] [ebp-14h]

    cog_flex_t v5 = sithCogExec_PopFlex(ctx);
    cog_flex_t v6 = sithCogExec_PopFlex(ctx);
    cog_flex_t a1 = sithCogExec_PopFlex(ctx);
    SithSurface* v2 = sithCogExec_PopSurface(ctx);
    if ( v2 && v6 >= (flex_d_t)a1 && v5 > 0.0 && (v4 = v5 * 0.5, v2->surfaceInfo.face.extraLight = a1, (v3 = sithSurface_SurfaceLightAnim(v2, v6, v4)) != 0) )
        sithCogExec_PushInt(ctx, v3->index);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SlideWall(sithCog *ctx)
{
    signed int pop_vec; // ebx
    SithSurface *surface; // eax
    SithSurface *v4; // edi
    rdSurface *v5; // ebx
    rdVector3 v7; // [esp+Ch] [ebp-Ch] BYREF

    cog_flex_t scale = sithCogExec_PopFlex(ctx) * 0.1;
    pop_vec = sithCogExec_PopVector(ctx, &v7);
    surface = sithCogExec_PopSurface(ctx);
    v4 = surface;
    if ( surface
      && surface->surfaceInfo.face.material
      && pop_vec
      && (v7.x = scale * v7.x, v7.y = scale * v7.y, v7.z = scale * v7.z, (v5 = sithSurface_SlideWall(surface, &v7)) != 0) )
    {
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithSurface_SyncSurface(v4);
        }
        sithCogExec_PushInt(ctx, v5->index);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionSurface_GetWallCel(sithCog *ctx)
{
    SithSurface* surface = sithCogExec_PopSurface(ctx);
    if ( surface && surface->surfaceInfo.face.material )
        sithCogExec_PushInt(ctx, surface->surfaceInfo.face.wallCel);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetWallCel(sithCog *ctx)
{
    int wallCel; // esi
    SithSurface *surface; // eax
    rdMaterial *v3; // ecx
    int v4; // ebx

    wallCel = sithCogExec_PopInt(ctx);
    surface = sithCogExec_PopSurface(ctx);
    if ( surface && (v3 = surface->surfaceInfo.face.material) != 0 && wallCel >= -1 && wallCel < v3->num_texinfo )
    {
        v4 = surface->surfaceInfo.face.wallCel;
        surface->surfaceInfo.face.wallCel = wallCel;
        if (COG_SHOULD_SYNC(ctx))
        {
            sithSurface_SyncSurface(surface);
        }
        sithCogExec_PushInt(ctx, v4);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionSurface_GetSurfaceMaterial(sithCog *ctx)
{
    rdMaterial *v2; // eax

    SithSurface* surface = sithCogExec_PopSurface(ctx);
    if ( surface && (v2 = surface->surfaceInfo.face.material) != 0 )
        sithCogExec_PushInt(ctx, v2 - sithWorld_g_pCurrentWorld->materials);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetSurfaceMaterial(sithCog *ctx)
{
    rdMaterial *v4; // eax

    rdMaterial* mat = sithCogExec_PopMaterial(ctx);
    SithSurface* surface = sithCogExec_PopSurface(ctx);
    if ( surface )
    {
        v4 = surface->surfaceInfo.face.material;
        surface->surfaceInfo.face.material = mat;
        if ( v4 )
            sithCogExec_PushInt(ctx, v4 - sithWorld_g_pCurrentWorld->materials);
        else
            sithCogExec_PushInt(ctx, -1);
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithSurface_SyncSurface(surface);
        }
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionSurface_SetSurfaceFlags(sithCog *ctx)
{
    uint32_t flags = sithCogExec_PopInt(ctx);
    SithSurface* surface = sithCogExec_PopSurface(ctx);

    if (surface && flags)
    {
        surface->surfaceFlags |= flags;
        if (COG_SHOULD_SYNC(ctx))
        {
            sithSurface_SyncSurface(surface);
        }
    }
}

void sithCogFunctionSurface_ClearSurfaceFlags(sithCog *ctx)
{
    uint32_t flags = sithCogExec_PopInt(ctx);
    SithSurface* surface = sithCogExec_PopSurface(ctx);

    if (surface && flags)
    {
        surface->surfaceFlags &= ~flags;
        if (COG_SHOULD_SYNC(ctx))
        {
            sithSurface_SyncSurface(surface);
        }
    }
}

void sithCogFunctionSurface_GetSurfaceFlags(sithCog *ctx)
{
    SithSurface* surface = sithCogExec_PopSurface(ctx);

    if ( surface )
        sithCogExec_PushInt(ctx, surface->surfaceFlags);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetAdjoinFlags(sithCog *ctx)
{
    uint32_t flags = sithCogExec_PopInt(ctx);
    SithSurface* surface = sithCogExec_PopSurface(ctx);

    if ( surface )
    {
        SithSurfaceAdjoin* adjoin = surface->adjoin;
        if ( adjoin )
        {
            if ( flags )
            {
                adjoin->flags |= flags;
                if ( COG_SHOULD_SYNC(ctx) )
                {
                    sithSurface_SyncSurface(surface);
                }
            }
        }
    }
}

void sithCogFunctionSurface_ClearAdjoinFlags(sithCog *ctx)
{
    uint32_t flags = sithCogExec_PopInt(ctx);
    SithSurface* surface = sithCogExec_PopSurface(ctx);

    if ( surface )
    {
        SithSurfaceAdjoin* adjoin = surface->adjoin;
        if ( adjoin )
        {
            if ( flags )
            {
                adjoin->flags &= ~flags;
                if ( COG_SHOULD_SYNC(ctx) )
                {
                     sithSurface_SyncSurface(surface);
                }
            }
        }
    }
}

void sithCogFunctionSurface_GetAdjoinFlags(sithCog *ctx)
{
    SithSurface* surface = sithCogExec_PopSurface(ctx);
    if (surface && surface->adjoin)
    {
        sithCogExec_PushInt(ctx, surface->adjoin->flags);
    }
    else
    {
        sithCogExec_PushInt(ctx, -1);
    }
}

void sithCogFunctionSurface_SetFaceType(sithCog *ctx)
{
    uint32_t type = sithCogExec_PopInt(ctx);
    SithSurface* surface = sithCogExec_PopSurface(ctx);
    if ( surface )
    {
        surface->surfaceInfo.face.type |= type;
        if (COG_SHOULD_SYNC(ctx))
        {
            sithSurface_SyncSurface(surface);
        }
    }
}

void sithCogFunctionSurface_ClearFaceType(sithCog *ctx)
{
    uint32_t type = sithCogExec_PopInt(ctx);
    SithSurface* surface = sithCogExec_PopSurface(ctx);
    if ( surface )
    {
        surface->surfaceInfo.face.type &= ~type;
        if (COG_SHOULD_SYNC(ctx))
        {
            sithSurface_SyncSurface(surface);
        }
    }
}

void sithCogFunctionSurface_GetFaceType(sithCog *ctx)
{
    SithSurface* surface = sithCogExec_PopSurface(ctx);
    if ( surface )
        sithCogExec_PushInt(ctx, surface->surfaceInfo.face.type);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetFaceGeoMode(sithCog *ctx)
{
    rdGeoMode_t geoMode; // edi
    SithSurface *v2; // eax

    geoMode = (rdGeoMode_t)sithCogExec_PopInt(ctx);
    v2 = sithCogExec_PopSurface(ctx);
    if ( v2 )
    {
        if ( v2->surfaceInfo.face.material )
        {
            // MoTS added
            if (!v2->surfaceInfo.face.vertexUVIdx && geoMode == RD_GEOMETRY_FULL) {
                geoMode = RD_GEOMETRY_SOLID;
            }

            v2->surfaceInfo.face.geometryMode = geoMode;
            if ( COG_SHOULD_SYNC(ctx) )
            {
                sithSurface_SyncSurface(v2);
                return;
            }
        }
        else
        {
            v2->surfaceInfo.face.geometryMode = RD_GEOMETRY_NONE;
            if ( COG_SHOULD_SYNC(ctx) )
            {
                sithSurface_SyncSurface(v2);
                return;
            }
        }
    }
}

void sithCogFunctionSurface_GetFaceGeoMode(sithCog *ctx)
{
    SithSurface *v1; // eax

    v1 = sithCogExec_PopSurface(ctx);
    if ( v1 )
        sithCogExec_PushInt(ctx, (int)v1->surfaceInfo.face.geometryMode);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetFaceLightMode(sithCog *ctx)
{
    rdLightMode_t lightMode; // edi
    SithSurface *v2; // eax

    lightMode = (rdLightMode_t)sithCogExec_PopInt(ctx);
    v2 = sithCogExec_PopSurface(ctx);
    if ( v2 )
    {
        v2->surfaceInfo.face.lightingMode = lightMode;
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithSurface_SyncSurface(v2);
        }
    }
}

void sithCogFunctionSurface_GetFaceLightMode(sithCog *ctx)
{
    SithSurface *v1; // eax

    v1 = sithCogExec_PopSurface(ctx);
    if ( v1 )
        sithCogExec_PushInt(ctx, (int)v1->surfaceInfo.face.lightingMode);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetFaceTexMode(sithCog *ctx)
{
    rdTexMode_t texMode; // edi
    SithSurface *v2; // eax

    texMode = (rdTexMode_t)sithCogExec_PopInt(ctx);
    v2 = sithCogExec_PopSurface(ctx);
    if ( v2 )
    {
        v2->surfaceInfo.face.textureMode = texMode;
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithSurface_SyncSurface(v2);
        }
    }
}

void sithCogFunctionSurface_GetFaceTexMode(sithCog *ctx)
{
    SithSurface *v1; // eax

    v1 = sithCogExec_PopSurface(ctx);
    if ( v1 )
        sithCogExec_PushInt(ctx, (int)v1->surfaceInfo.face.textureMode);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetSurfaceLight(sithCog *ctx)
{
    SithSurface *v2; // ecx

    cog_flex_t v4 = sithCogExec_PopFlex(ctx);
    cog_flex_t a1 = sithCogExec_PopFlex(ctx);
    v2 = sithCogExec_PopSurface(ctx);
    if ( v2 && a1 >= 0.0 )
    {
        if ( v4 == 0.0 )
        {
            v2->surfaceInfo.face.extraLight = a1;
            if ( COG_SHOULD_SYNC(ctx) )
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

void sithCogFunctionSurface_GetSurfaceLight(sithCog *ctx)
{
    SithSurface *v1; // eax

    v1 = sithCogExec_PopSurface(ctx);
    if ( v1 ) {
        sithCogExec_PushFlex(ctx, v1->surfaceInfo.face.extraLight);
    }
    // TODO: Always return *something*?
}

void sithCogFunctionSurface_GetSurfaceCenter(sithCog *ctx)
{
    SithSurface *v1; // eax
    rdVector3 a2; // [esp+4h] [ebp-Ch] BYREF

    v1 = sithCogExec_PopSurface(ctx);
    if ( v1 )
    {
        sithSurface_GetCenterPoint(v1, &a2);
        sithCogExec_PushVector(ctx, &a2);
    }
    else
    {
        sithCogExec_PushVector(ctx, &rdroid_zeroVector3);
    }
}

void sithCogFunctionSurface_GetSurfaceCount(sithCog *ctx)
{
    if ( sithWorld_g_pCurrentWorld )
        sithCogExec_PushInt(ctx, sithWorld_g_pCurrentWorld->numSurfaces);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_GetSurfaceNormal(sithCog *ctx)
{
    SithSurface *v1; // eax

    v1 = sithCogExec_PopSurface(ctx);
    if ( v1 )
        sithCogExec_PushVector(ctx, &v1->surfaceInfo.face.normal);
    else
        sithCogExec_PushVector(ctx, &rdroid_zeroVector3);
}

void sithCogFunctionSurface_SyncSurface(sithCog *ctx)
{
    SithSurface *v1; // eax

    v1 = sithCogExec_PopSurface(ctx);
    if ( v1 )
        sithSurface_SyncSurface(v1);
}

// MOTS added
void sithCogFunctionSurface_GetSurfaceVertexLight(sithCog *ctx)
{
    int num = sithCogExec_PopInt(ctx);
    SithSurface* pSurface = sithCogExec_PopSurface(ctx);
    
    if ((pSurface && (num < (pSurface->surfaceInfo).face.numVertices)) && num > -1) {
        sithCogExec_PushFlex(ctx,(pSurface->surfaceInfo).intensities[num]);
        return;
    }
    
    sithCogExec_PushFlex(ctx,-1.0);
}

// MOTS added
void sithCogFunctionSurface_SetSurfaceVertexLight(sithCog *ctx)
{
    cog_flex_t val = sithCogExec_PopFlex(ctx);
    int num = sithCogExec_PopInt(ctx);
    SithSurface* pSurface = sithCogExec_PopSurface(ctx);

    if ((pSurface && ((uint32_t)num < (pSurface->surfaceInfo).face.numVertices)) && num > -1) {
        (pSurface->surfaceInfo).intensities[num] = val;
    }
}

// MOTS added
void sithCogFunctionSurface_GetSurfaceVertexLightRGB(sithCog *ctx)
{
    rdVector3 tmp;

    int num = sithCogExec_PopInt(ctx);
    SithSurface* pSurface = sithCogExec_PopSurface(ctx);
    if (pSurface == (SithSurface *)0x0) {
        tmp.x = -1.0;
        tmp.y = -1.0;
        tmp.z = -1.0;
        sithCogExec_PushVector(ctx,&tmp);
        return;
    }

    uint32_t numVerts = (pSurface->surfaceInfo).face.numVertices;
    if ((num < numVerts) && (-1 < num)) {
        if ((pSurface->surfaceFlags & SITH_SURFACE_1000000) == 0) {
            tmp.x = -1.0;
            tmp.y = -1.0;
            tmp.z = -1.0;
            sithCogExec_PushVector(ctx,&tmp);
            return;
        }
        tmp.x = (pSurface->surfaceInfo).intensities[num + numVerts];
        tmp.y = (pSurface->surfaceInfo).intensities[num + (pSurface->surfaceInfo).face.numVertices * 2];
        tmp.z = (pSurface->surfaceInfo).intensities[num + (pSurface->surfaceInfo).face.numVertices * 3];
        sithCogExec_PushVector(ctx,&tmp);
        return;
    }

    tmp.x = -1.0;
    tmp.y = -1.0;
    tmp.z = -1.0;
    sithCogExec_PushVector(ctx,&tmp);
}

// MOTS added
void sithCogFunctionSurface_SetSurfaceVertexLightRGB(sithCog *ctx)
{
    rdVector3 valRGB;
    uint32_t uVar1;
    
    sithCogExec_PopVector(ctx, &valRGB);
    int num = sithCogExec_PopInt(ctx);
    SithSurface* pSurface = sithCogExec_PopSurface(ctx);

    if ((((pSurface != (SithSurface *)0x0) 
        && (uVar1 = (pSurface->surfaceInfo).face.numVertices, (uint32_t)num < uVar1)) && (-1 < num)) 
        && ((pSurface->surfaceFlags & SITH_SURFACE_1000000) != 0)) {
        (pSurface->surfaceInfo).intensities[num + uVar1] = valRGB.x;
        (pSurface->surfaceInfo).intensities[num + (pSurface->surfaceInfo).face.numVertices * 2] = valRGB.y;
        (pSurface->surfaceInfo).intensities[num + (pSurface->surfaceInfo).face.numVertices * 3] = valRGB.z;
    }
}

void sithCogFunctionSurface_Startup(SithCogSymbolTable* ctx)
{
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetSurfaceAdjoin, "getsurfaceadjoin");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetSurfaceSector, "getsurfacesector");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetNumSurfaceVertices, "getnumsurfacevertices");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetSurfaceVertexPos, "getsurfacevertexpos");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SetHorizonSkyOffset, "sethorizonskyoffset");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetHorizonSkyOffset, "gethorizonskyoffset");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SetCeilingSkyOffset, "setceilingskyoffset");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetCeilingSkyOffset, "getceilingskyoffset");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SlideHorizonSky, "slidehorizonsky");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SlideCeilingSky, "slideceilingsky");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetSurfaceCount, "getsurfacecount");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SlideWall, "slidewall");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SlideWall, "slidesurface");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetWallCel, "getwallcel");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SetWallCel, "setwallcel");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetWallCel, "getsurfacecel");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SetWallCel, "setsurfacecel");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetSurfaceMaterial, "getsurfacemat");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SetSurfaceMaterial, "setsurfacemat");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetSurfaceFlags, "getsurfaceflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SetSurfaceFlags, "setsurfaceflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_ClearSurfaceFlags, "clearsurfaceflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetAdjoinFlags, "getadjoinflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SetAdjoinFlags, "setadjoinflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_ClearAdjoinFlags, "clearadjoinflags");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SetFaceType, "setfacetype");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_ClearFaceType, "clearfacetype");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetFaceType, "getfacetype");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SetFaceGeoMode, "setfacegeomode");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetFaceGeoMode, "getfacegeomode");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SetFaceLightMode, "setfacelightmode");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetFaceLightMode, "getfacelightmode");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SetFaceTexMode, "setfacetexmode");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetFaceTexMode, "getfacetexmode");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetSurfaceLight, "getsurfacelight");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SetSurfaceLight, "setsurfacelight");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SetSurfaceLight, "surfacelight");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetSurfaceCenter, "getsurfacecenter");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetSurfaceCenter, "surfacecenter");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SurfaceLightAnim, "surfacelightanim");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetSurfaceNormal, "getsurfacenormal");
    sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SyncSurface, "syncsurface");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetSurfaceVertexLight, "getsurfacevertexlight");
        sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SetSurfaceVertexLight, "setsurfacevertexlight");
        sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetSurfaceVertexLightRGB, "getsurfacevertexlightrgb");
        sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SetSurfaceVertexLightRGB, "setsurfacevertexlightrgb");
    }
}
