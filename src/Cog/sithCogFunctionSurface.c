#include "sithCogFunctionSurface.h"

#include "Cog/sithCogVm.h"
#include "World/sithWorld.h"
#include "World/sithSector.h"
#include "Engine/sithSurface.h"
#include "Engine/sithAdjoin.h"

void sithCogFunctionSurface_GetSurfaceAdjoin(sithCog *ctx);
void sithCogFunctionSurface_GetSurfaceSector(sithCog *ctx);
void sithCogFunctionSurface_GetNumSurfaceVertices(sithCog *ctx);
void sithCogFunctionSurface_GetSurfaceVertexPos(sithCog *ctx);
void sithCogFunctionSurface_SetHorizonSkyOffset(sithCog *ctx);
void sithCogFunctionSurface_GetHorizonSkyOffset(sithCog *ctx);
void sithCogFunctionSurface_SetCeilingSkyOffset(sithCog *ctx);
void sithCogFunctionSurface_GetCeilingSkyOffset(sithCog *ctx);
void sithCogFunctionSurface_SlideHorizonSky(sithCog *ctx);
void sithCogFunctionSurface_SlideCeilingSky(sithCog *ctx);
void sithCogFunctionSurface_SurfaceLightAnim(sithCog *ctx);
void sithCogFunctionSurface_SlideWallSurface(sithCog *ctx);
void sithCogFunctionSurface_GetWallCel(sithCog *ctx);
void sithCogFunctionSurface_SetWallCel(sithCog *ctx);
void sithCogFunctionSurface_GetSurfaceMat(sithCog *ctx);
void sithCogFunctionSurface_SetSurfaceMat(sithCog *ctx);
void sithCogFunctionSurface_SetSurfaceFlags(sithCog *ctx);
void sithCogFunctionSurface_ClearSurfaceFlags(sithCog *ctx);
void sithCogFunctionSurface_GetSurfaceFlags(sithCog *ctx);
void sithCogFunctionSurface_SetAdjoinFlags(sithCog *ctx);
void sithCogFunctionSurface_ClearAdjoinFlags(sithCog *ctx);
void sithCogFunctionSurface_GetAdjoinFlags(sithCog *ctx);
void sithCogFunctionSurface_SetFaceType(sithCog *ctx);
void sithCogFunctionSurface_ClearFaceType(sithCog *ctx);
void sithCogFunctionSurface_GetFaceType(sithCog *ctx);
void sithCogFunctionSurface_SetFaceGeoMode(sithCog *ctx);
void sithCogFunctionSurface_GetFaceGeoMode(sithCog *ctx);
void sithCogFunctionSurface_SetFaceLightMode(sithCog *ctx);
void sithCogFunctionSurface_GetFaceLightMode(sithCog *ctx);
void sithCogFunctionSurface_SetFaceTexMode(sithCog *ctx);
void sithCogFunctionSurface_GetFaceTexMode(sithCog *ctx);
void sithCogFunctionSurface_SetSurfaceLight(sithCog *ctx);
void sithCogFunctionSurface_GetSurfaceLight(sithCog *ctx);
void sithCogFunctionSurface_GetSurfaceCenter(sithCog *ctx);
void sithCogFunctionSurface_GetSurfaceCount(sithCog *ctx);
void sithCogFunctionSurface_GetSurfaceNormal(sithCog *ctx);
void sithCogFunctionSurface_SyncSurface(sithCog *ctx);

void sithCogFunctionSurface_Initialize(void* ctx)
{
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetSurfaceAdjoin, "getsurfaceadjoin");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetSurfaceSector, "getsurfacesector");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetNumSurfaceVertices, "getnumsurfacevertices");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetSurfaceVertexPos, "getsurfacevertexpos");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SetHorizonSkyOffset, "sethorizonskyoffset");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetHorizonSkyOffset, "gethorizonskyoffset");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SetCeilingSkyOffset, "setceilingskyoffset");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetCeilingSkyOffset, "getceilingskyoffset");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SlideHorizonSky, "slidehorizonsky");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SlideCeilingSky, "slideceilingsky");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetSurfaceCount, "getsurfacecount");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SlideWallSurface, "slidewall");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SlideWallSurface, "slidesurface");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetWallCel, "getwallcel");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SetWallCel, "setwallcel");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetWallCel, "getsurfacecel");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SetWallCel, "setsurfacecel");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetSurfaceMat, "getsurfacemat");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SetSurfaceMat, "setsurfacemat");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetSurfaceFlags, "getsurfaceflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SetSurfaceFlags, "setsurfaceflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_ClearSurfaceFlags, "clearsurfaceflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetAdjoinFlags, "getadjoinflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SetAdjoinFlags, "setadjoinflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_ClearAdjoinFlags, "clearadjoinflags");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SetFaceType, "setfacetype");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_ClearFaceType, "clearfacetype");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetFaceType, "getfacetype");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SetFaceGeoMode, "setfacegeomode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetFaceGeoMode, "getfacegeomode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SetFaceLightMode, "setfacelightmode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetFaceLightMode, "getfacelightmode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SetFaceTexMode, "setfacetexmode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetFaceTexMode, "getfacetexmode");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetSurfaceLight, "getsurfacelight");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SetSurfaceLight, "setsurfacelight");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SetSurfaceLight, "surfacelight");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetSurfaceCenter, "getsurfacecenter");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetSurfaceCenter, "surfacecenter");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SurfaceLightAnim, "surfacelightanim");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetSurfaceNormal, "getsurfacenormal");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SyncSurface, "syncsurface");
}

void sithCogFunctionSurface_GetSurfaceAdjoin(sithCog *ctx)
{
    sithSurface *surface; // eax
    uint32_t *v2; // eax

    surface = sithCogVm_PopSurface(ctx);
    if ( surface && (v2 = &surface->adjoin->mirror->surface->field_0) != 0 )
        sithCogVm_PushInt(ctx, *v2);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSurface_GetSurfaceSector(sithCog *ctx)
{
    sithSurface *v1; // eax
    uint32_t *v2; // eax

    v1 = sithCogVm_PopSurface(ctx);
    if ( v1 && (v2 = &v1->parent_sector->id) != 0 )
        sithCogVm_PushInt(ctx, *v2);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSurface_GetNumSurfaceVertices(sithCog *ctx)
{
    sithSurface *surface; // eax

    surface = sithCogVm_PopSurface(ctx);
    if ( surface )
        sithCogVm_PushInt(ctx, surface->surfaceInfo.face.numVertices);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSurface_GetSurfaceVertexPos(sithCog *ctx)
{
    sithWorld *world; // ebx
    uint32_t vtx_idx; // edi
    sithSurface *surface; // eax

    world = sithWorld_pCurrentWorld;
    vtx_idx = sithCogVm_PopInt(ctx);
    surface = sithCogVm_PopSurface(ctx);
    if ( surface && vtx_idx < surface->surfaceInfo.face.numVertices && (vtx_idx & 0x80000000) == 0 )
        sithCogVm_PushVector3(ctx, &world->vertices[surface->surfaceInfo.face.vertexPosIdx[vtx_idx]]);
    else
        sithCogVm_PushVector3(ctx, &rdroid_zeroVector3);
}

void sithCogFunctionSurface_SetHorizonSkyOffset(sithCog *ctx)
{
    rdVector3 offs;

    // TODO add valid check?
    sithCogVm_PopVector3(ctx, &offs);
    sithWorld_pCurrentWorld->horizontalSkyOffs.x = offs.x;
    sithWorld_pCurrentWorld->horizontalSkyOffs.y = offs.y;
}

void sithCogFunctionSurface_GetHorizonSkyOffset(sithCog *ctx)
{
    rdVector3 offs;

    offs.x = sithWorld_pCurrentWorld->horizontalSkyOffs.x;
    offs.y = sithWorld_pCurrentWorld->horizontalSkyOffs.y;
    offs.z = 0.0;
    sithCogVm_PushVector3(ctx, &offs);
}

void sithCogFunctionSurface_SetCeilingSkyOffset(sithCog *ctx)
{
    rdVector3 offs;

    // TODO add valid check?
    sithCogVm_PopVector3(ctx, &offs);
    sithWorld_pCurrentWorld->ceilingSkyOffs.x = offs.x;
    sithWorld_pCurrentWorld->ceilingSkyOffs.y = offs.y;
}

void sithCogFunctionSurface_GetCeilingSkyOffset(sithCog *ctx)
{
    rdVector3 offs;

    offs.x = sithWorld_pCurrentWorld->ceilingSkyOffs.x;
    offs.y = sithWorld_pCurrentWorld->ceilingSkyOffs.y;
    offs.z = 0.0;
    sithCogVm_PushVector3(ctx, &offs);
}

void sithCogFunctionSurface_SlideHorizonSky(sithCog *ctx)
{
    rdSurface *v2;
    rdVector2 a2;

    a2.y = sithCogVm_PopFlex(ctx);
    a2.x = sithCogVm_PopFlex(ctx);
    v2 = sithSurface_SlideHorizonSky(0x200, &a2);
    if ( v2 )
        sithCogVm_PushInt(ctx, v2->index);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SlideCeilingSky(sithCog *ctx)
{
    rdSurface *v2;
    rdVector2 a2;

    a2.y = sithCogVm_PopFlex(ctx);
    a2.x = sithCogVm_PopFlex(ctx);
    v2 = sithSurface_SlideHorizonSky(0x400, &a2);
    if ( v2 )
        sithCogVm_PushInt(ctx, v2->index);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SurfaceLightAnim(sithCog *ctx)
{
    rdSurface *v3; // eax
    float v4; // [esp+0h] [ebp-14h]

    float v5 = sithCogVm_PopFlex(ctx);
    float v6 = sithCogVm_PopFlex(ctx);
    float a1 = sithCogVm_PopFlex(ctx);
    sithSurface* v2 = sithCogVm_PopSurface(ctx);
    if ( v2 && v6 >= (double)a1 && v5 > 0.0 && (v4 = v5 * 0.5, v2->surfaceInfo.face.extraLight = a1, (v3 = sithSurface_SurfaceLightAnim(v2, v6, v4)) != 0) )
        sithCogVm_PushInt(ctx, v3->index);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SlideWallSurface(sithCog *ctx)
{
    signed int pop_vec; // ebx
    sithSurface *surface; // eax
    sithSurface *v4; // edi
    rdSurface *v5; // ebx
    rdVector3 v7; // [esp+Ch] [ebp-Ch] BYREF
    float scale; // [esp+1Ch] [ebp+4h]

    scale = sithCogVm_PopFlex(ctx) * 0.1;
    pop_vec = sithCogVm_PopVector3(ctx, &v7);
    surface = sithCogVm_PopSurface(ctx);
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
        sithCogVm_PushInt(ctx, v5->index);
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionSurface_GetWallCel(sithCog *ctx)
{
    sithSurface* surface = sithCogVm_PopSurface(ctx);
    if ( surface && surface->surfaceInfo.face.material )
        sithCogVm_PushInt(ctx, surface->surfaceInfo.face.wallCel);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetWallCel(sithCog *ctx)
{
    int wallCel; // esi
    sithSurface *surface; // eax
    rdMaterial *v3; // ecx
    int v4; // ebx

    wallCel = sithCogVm_PopInt(ctx);
    surface = sithCogVm_PopSurface(ctx);
    if ( surface && (v3 = surface->surfaceInfo.face.material) != 0 && wallCel >= -1 && wallCel < v3->num_texinfo )
    {
        v4 = surface->surfaceInfo.face.wallCel;
        surface->surfaceInfo.face.wallCel = wallCel;
        if (COG_SHOULD_SYNC(ctx))
        {
            sithSurface_SyncSurface(surface);
        }
        sithCogVm_PushInt(ctx, v4);
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionSurface_GetSurfaceMat(sithCog *ctx)
{
    rdMaterial *v2; // eax

    sithSurface* surface = sithCogVm_PopSurface(ctx);
    if ( surface && (v2 = surface->surfaceInfo.face.material) != 0 )
        sithCogVm_PushInt(ctx, v2 - sithWorld_pCurrentWorld->materials);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetSurfaceMat(sithCog *ctx)
{
    rdMaterial *v4; // eax

    rdMaterial* mat = sithCogVm_PopMaterial(ctx);
    sithSurface* surface = sithCogVm_PopSurface(ctx);
    if ( surface )
    {
        v4 = surface->surfaceInfo.face.material;
        surface->surfaceInfo.face.material = mat;
        if ( v4 )
            sithCogVm_PushInt(ctx, v4 - sithWorld_pCurrentWorld->materials);
        else
            sithCogVm_PushInt(ctx, -1);
        if ( COG_SHOULD_SYNC(ctx) )
        {
            sithSurface_SyncSurface(surface);
        }
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionSurface_SetSurfaceFlags(sithCog *ctx)
{
    uint32_t flags = sithCogVm_PopInt(ctx);
    sithSurface* surface = sithCogVm_PopSurface(ctx);

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
    uint32_t flags = sithCogVm_PopInt(ctx);
    sithSurface* surface = sithCogVm_PopSurface(ctx);

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
    sithSurface* surface = sithCogVm_PopSurface(ctx);

    if ( surface )
        sithCogVm_PushInt(ctx, surface->surfaceFlags);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetAdjoinFlags(sithCog *ctx)
{
    uint32_t flags = sithCogVm_PopInt(ctx);
    sithSurface* surface = sithCogVm_PopSurface(ctx);

    if ( surface )
    {
        sithAdjoin* adjoin = surface->adjoin;
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
    uint32_t flags = sithCogVm_PopInt(ctx);
    sithSurface* surface = sithCogVm_PopSurface(ctx);

    if ( surface )
    {
        sithAdjoin* adjoin = surface->adjoin;
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
    sithSurface* surface = sithCogVm_PopSurface(ctx);
    if (surface && surface->adjoin)
    {
        sithCogVm_PushInt(ctx, surface->adjoin->flags);
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionSurface_SetFaceType(sithCog *ctx)
{
    uint32_t type = sithCogVm_PopInt(ctx);
    sithSurface* surface = sithCogVm_PopSurface(ctx);
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
    uint32_t type = sithCogVm_PopInt(ctx);
    sithSurface* surface = sithCogVm_PopSurface(ctx);
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
    sithSurface* surface = sithCogVm_PopSurface(ctx);
    if ( surface )
        sithCogVm_PushInt(ctx, surface->surfaceInfo.face.type);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetFaceGeoMode(sithCog *ctx)
{
    rdGeoMode_t geoMode; // edi
    sithSurface *v2; // eax

    geoMode = (rdGeoMode_t)sithCogVm_PopInt(ctx);
    v2 = sithCogVm_PopSurface(ctx);
    if ( v2 )
    {
        if ( v2->surfaceInfo.face.material )
        {
            v2->surfaceInfo.face.geometryMode = geoMode;
            if ( COG_SHOULD_SYNC(ctx) )
            {
                sithSurface_SyncSurface(v2);
                return;
            }
        }
        else
        {
            v2->surfaceInfo.face.geometryMode = RD_GEOMODE_NOTRENDERED;
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
    sithSurface *v1; // eax

    v1 = sithCogVm_PopSurface(ctx);
    if ( v1 )
        sithCogVm_PushInt(ctx, (int)v1->surfaceInfo.face.geometryMode);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetFaceLightMode(sithCog *ctx)
{
    rdLightMode_t lightMode; // edi
    sithSurface *v2; // eax

    lightMode = (rdLightMode_t)sithCogVm_PopInt(ctx);
    v2 = sithCogVm_PopSurface(ctx);
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
    sithSurface *v1; // eax

    v1 = sithCogVm_PopSurface(ctx);
    if ( v1 )
        sithCogVm_PushInt(ctx, (int)v1->surfaceInfo.face.lightingMode);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetFaceTexMode(sithCog *ctx)
{
    rdTexMode_t texMode; // edi
    sithSurface *v2; // eax

    texMode = (rdTexMode_t)sithCogVm_PopInt(ctx);
    v2 = sithCogVm_PopSurface(ctx);
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
    sithSurface *v1; // eax

    v1 = sithCogVm_PopSurface(ctx);
    if ( v1 )
        sithCogVm_PushInt(ctx, (int)v1->surfaceInfo.face.textureMode);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetSurfaceLight(sithCog *ctx)
{
    sithSurface *v2; // ecx
    float v4; // [esp+4h] [ebp-4h]
    float a1; // [esp+Ch] [ebp+4h]

    v4 = sithCogVm_PopFlex(ctx);
    a1 = sithCogVm_PopFlex(ctx);
    v2 = sithCogVm_PopSurface(ctx);
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
    sithSurface *v1; // eax

    v1 = sithCogVm_PopSurface(ctx);
    if ( v1 )
        sithCogVm_PushFlex(ctx, v1->surfaceInfo.face.extraLight);
}

void sithCogFunctionSurface_GetSurfaceCenter(sithCog *ctx)
{
    sithSurface *v1; // eax
    rdVector3 a2; // [esp+4h] [ebp-Ch] BYREF

    v1 = sithCogVm_PopSurface(ctx);
    if ( v1 )
    {
        sithSurface_GetCenter(v1, &a2);
        sithCogVm_PushVector3(ctx, &a2);
    }
    else
    {
        sithCogVm_PushVector3(ctx, &rdroid_zeroVector3);
    }
}

void sithCogFunctionSurface_GetSurfaceCount(sithCog *ctx)
{
    if ( sithWorld_pCurrentWorld )
        sithCogVm_PushInt(ctx, sithWorld_pCurrentWorld->numSurfaces);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSurface_GetSurfaceNormal(sithCog *ctx)
{
    sithSurface *v1; // eax

    v1 = sithCogVm_PopSurface(ctx);
    if ( v1 )
        sithCogVm_PushVector3(ctx, &v1->surfaceInfo.face.normal);
    else
        sithCogVm_PushVector3(ctx, &rdroid_zeroVector3);
}

void sithCogFunctionSurface_SyncSurface(sithCog *ctx)
{
    sithSurface *v1; // eax

    v1 = sithCogVm_PopSurface(ctx);
    if ( v1 )
        sithSurface_SyncSurface(v1);
}
