#include "sithCogSurface.h"

#include "Cog/sithCogVm.h"
#include "World/sithWorld.h"
#include "World/sithSector.h"
#include "Engine/sithSurface.h"
#include "Engine/sithAdjoin.h"

void sithCogSurface_GetSurfaceAdjoin(sithCog *ctx);
void sithCogSurface_GetSurfaceSector(sithCog *ctx);
void sithCogSurface_GetNumSurfaceVertices(sithCog *ctx);
void sithCogSurface_GetSurfaceVertexPos(sithCog *ctx);
void sithCogSurface_SetHorizonSkyOffset(sithCog *ctx);
void sithCogSurface_GetHorizonSkyOffset(sithCog *ctx);
void sithCogSurface_SetCeilingSkyOffset(sithCog *ctx);
void sithCogSurface_GetCeilingSkyOffset(sithCog *ctx);
void sithCogSurface_SlideHorizonSky(sithCog *ctx);
void sithCogSurface_SlideCeilingSky(sithCog *ctx);
void sithCogSurface_SurfaceLightAnim(sithCog *ctx);
void sithCogSurface_SlideWallSurface(sithCog *ctx);
void sithCogSurface_GetWallCel(sithCog *ctx);
void sithCogSurface_SetWallCel(sithCog *ctx);
void sithCogSurface_GetSurfaceMat(sithCog *ctx);
void sithCogSurface_SetSurfaceMat(sithCog *ctx);
void sithCogSurface_SetSurfaceFlags(sithCog *ctx);
void sithCogSurface_ClearSurfaceFlags(sithCog *ctx);
void sithCogSurface_GetSurfaceFlags(sithCog *ctx);
void sithCogSurface_SetAdjoinFlags(sithCog *ctx);
void sithCogSurface_ClearAdjoinFlags(sithCog *ctx);
void sithCogSurface_GetAdjoinFlags(sithCog *ctx);
void sithCogSurface_SetFaceType(sithCog *ctx);
void sithCogSurface_ClearFaceType(sithCog *ctx);
void sithCogSurface_GetFaceType(sithCog *ctx);
void sithCogSurface_SetFaceGeoMode(sithCog *ctx);
void sithCogSurface_GetFaceGeoMode(sithCog *ctx);
void sithCogSurface_SetFaceLightMode(sithCog *ctx);
void sithCogSurface_GetFaceLightMode(sithCog *ctx);
void sithCogSurface_SetFaceTexMode(sithCog *ctx);
void sithCogSurface_GetFaceTexMode(sithCog *ctx);
void sithCogSurface_SetSurfaceLight(sithCog *ctx);
void sithCogSurface_GetSurfaceLight(sithCog *ctx);
void sithCogSurface_GetSurfaceCenter(sithCog *ctx);
void sithCogSurface_GetSurfaceCount(sithCog *ctx);
void sithCogSurface_GetSurfaceNormal(sithCog *ctx);
void sithCogSurface_SyncSurface(sithCog *ctx);

void sithCogSurface_Initialize(void* ctx)
{
    sithCogScript_RegisterVerb(ctx, sithCogSurface_GetSurfaceAdjoin, "getsurfaceadjoin");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_GetSurfaceSector, "getsurfacesector");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_GetNumSurfaceVertices, "getnumsurfacevertices");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_GetSurfaceVertexPos, "getsurfacevertexpos");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_SetHorizonSkyOffset, "sethorizonskyoffset");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_GetHorizonSkyOffset, "gethorizonskyoffset");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_SetCeilingSkyOffset, "setceilingskyoffset");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_GetCeilingSkyOffset, "getceilingskyoffset");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_SlideHorizonSky, "slidehorizonsky");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_SlideCeilingSky, "slideceilingsky");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_GetSurfaceCount, "getsurfacecount");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_SlideWallSurface, "slidewall");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_SlideWallSurface, "slidesurface");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_GetWallCel, "getwallcel");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_SetWallCel, "setwallcel");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_GetWallCel, "getsurfacecel");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_SetWallCel, "setsurfacecel");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_GetSurfaceMat, "getsurfacemat");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_SetSurfaceMat, "setsurfacemat");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_GetSurfaceFlags, "getsurfaceflags");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_SetSurfaceFlags, "setsurfaceflags");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_ClearSurfaceFlags, "clearsurfaceflags");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_GetAdjoinFlags, "getadjoinflags");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_SetAdjoinFlags, "setadjoinflags");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_ClearAdjoinFlags, "clearadjoinflags");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_SetFaceType, "setfacetype");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_ClearFaceType, "clearfacetype");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_GetFaceType, "getfacetype");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_SetFaceGeoMode, "setfacegeomode");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_GetFaceGeoMode, "getfacegeomode");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_SetFaceLightMode, "setfacelightmode");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_GetFaceLightMode, "getfacelightmode");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_SetFaceTexMode, "setfacetexmode");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_GetFaceTexMode, "getfacetexmode");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_GetSurfaceLight, "getsurfacelight");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_SetSurfaceLight, "setsurfacelight");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_SetSurfaceLight, "surfacelight");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_GetSurfaceCenter, "getsurfacecenter");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_GetSurfaceCenter, "surfacecenter");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_SurfaceLightAnim, "surfacelightanim");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_GetSurfaceNormal, "getsurfacenormal");
    sithCogScript_RegisterVerb(ctx, sithCogSurface_SyncSurface, "syncsurface");
}

void sithCogSurface_GetSurfaceAdjoin(sithCog *ctx)
{
    sithSurface *surface; // eax
    uint32_t *v2; // eax

    surface = sithCogVm_PopSurface(ctx);
    if ( surface && (v2 = &surface->adjoin->mirror->surface->field_0) != 0 )
        sithCogVm_PushInt(ctx, *v2);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogSurface_GetSurfaceSector(sithCog *ctx)
{
    sithSurface *v1; // eax
    int *v2; // eax

    v1 = sithCogVm_PopSurface(ctx);
    if ( v1 && (v2 = &v1->parent_sector->id) != 0 )
        sithCogVm_PushInt(ctx, *v2);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogSurface_GetNumSurfaceVertices(sithCog *ctx)
{
    sithSurface *surface; // eax

    surface = sithCogVm_PopSurface(ctx);
    if ( surface )
        sithCogVm_PushInt(ctx, surface->surfaceInfo.face.numVertices);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogSurface_GetSurfaceVertexPos(sithCog *ctx)
{
    sithWorld *world; // ebx
    uint32_t vtx_idx; // edi
    sithSurface *surface; // eax

    world = sithWorld_pCurWorld;
    vtx_idx = sithCogVm_PopInt(ctx);
    surface = sithCogVm_PopSurface(ctx);
    if ( surface && vtx_idx < surface->surfaceInfo.face.numVertices && (vtx_idx & 0x80000000) == 0 )
        sithCogVm_PushVector3(ctx, &world->vertices[surface->surfaceInfo.face.vertexPosIdx[vtx_idx]]);
    else
        sithCogVm_PushVector3(ctx, &rdroid_zeroVector3);
}

void sithCogSurface_SetHorizonSkyOffset(sithCog *ctx)
{
    rdVector3 offs;

    // TODO add valid check?
    sithCogVm_PopVector3(ctx, &offs);
    sithWorld_pCurWorld->horizontalSkyOffs.x = offs.x;
    sithWorld_pCurWorld->horizontalSkyOffs.y = offs.y;
}

void sithCogSurface_GetHorizonSkyOffset(sithCog *ctx)
{
    rdVector3 offs;

    offs.x = sithWorld_pCurWorld->horizontalSkyOffs.x;
    offs.y = sithWorld_pCurWorld->horizontalSkyOffs.y;
    offs.z = 0.0;
    sithCogVm_PushVector3(ctx, &offs);
}

void sithCogSurface_SetCeilingSkyOffset(sithCog *ctx)
{
    rdVector3 offs;

    // TODO add valid check?
    sithCogVm_PopVector3(ctx, &offs);
    sithWorld_pCurWorld->ceilingSkyOffs.x = offs.x;
    sithWorld_pCurWorld->ceilingSkyOffs.y = offs.y;
}

void sithCogSurface_GetCeilingSkyOffset(sithCog *ctx)
{
    rdVector3 offs;

    offs.x = sithWorld_pCurWorld->ceilingSkyOffs.x;
    offs.y = sithWorld_pCurWorld->ceilingSkyOffs.y;
    offs.z = 0.0;
    sithCogVm_PushVector3(ctx, &offs);
}

void sithCogSurface_SlideHorizonSky(sithCog *ctx)
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

void sithCogSurface_SlideCeilingSky(sithCog *ctx)
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

void sithCogSurface_SurfaceLightAnim(sithCog *ctx)
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

void sithCogSurface_SlideWallSurface(sithCog *ctx)
{
    signed int pop_vec; // ebx
    sithSurface *surface; // eax
    sithSurface *v4; // edi
    rdSurface *v5; // ebx
    int v6; // eax
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
        if ( sithCogVm_multiplayerFlags )
        {
            if ( (ctx->flags & 0x200) == 0 )
            {
                v6 = ctx->trigId;
                if ( v6 != SITH_MESSAGE_STARTUP && v6 != SITH_MESSAGE_SHUTDOWN )
                    sithSurface_PushSurface(v4);
            }
        }
        sithCogVm_PushInt(ctx, v5->index);
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogSurface_GetWallCel(sithCog *ctx)
{
    sithSurface* surface = sithCogVm_PopSurface(ctx);
    if ( surface && surface->surfaceInfo.face.material )
        sithCogVm_PushInt(ctx, surface->surfaceInfo.face.wallCel);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogSurface_SetWallCel(sithCog *ctx)
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
        if (sithCogVm_multiplayerFlags && (ctx->flags & 0x200) == 0 )
        {
            if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
                sithSurface_PushSurface(surface);
        }
        sithCogVm_PushInt(ctx, v4);
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogSurface_GetSurfaceMat(sithCog *ctx)
{
    rdMaterial *v2; // eax

    sithSurface* surface = sithCogVm_PopSurface(ctx);
    if ( surface && (v2 = surface->surfaceInfo.face.material) != 0 )
        sithCogVm_PushInt(ctx, v2 - sithWorld_pCurWorld->materials);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogSurface_SetSurfaceMat(sithCog *ctx)
{
    rdMaterial *v4; // eax

    rdMaterial* mat = sithCogVm_PopMaterial(ctx);
    sithSurface* surface = sithCogVm_PopSurface(ctx);
    if ( surface )
    {
        v4 = surface->surfaceInfo.face.material;
        surface->surfaceInfo.face.material = mat;
        if ( v4 )
            sithCogVm_PushInt(ctx, v4 - sithWorld_pCurWorld->materials);
        else
            sithCogVm_PushInt(ctx, -1);
        if ( sithCogVm_multiplayerFlags )
        {
            if ( (ctx->flags & 0x200) == 0 )
            {
                if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
                    sithSurface_PushSurface(surface);
            }
        }
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogSurface_SetSurfaceFlags(sithCog *ctx)
{
    uint32_t flags = sithCogVm_PopInt(ctx);
    sithSurface* surface = sithCogVm_PopSurface(ctx);

    if (surface && flags)
    {
        surface->surfaceFlags |= flags;
        if (sithCogVm_multiplayerFlags && (ctx->flags & 0x200) == 0 )
        {
            if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
                sithSurface_PushSurface(surface);
        }
    }
}

void sithCogSurface_ClearSurfaceFlags(sithCog *ctx)
{
    uint32_t flags = sithCogVm_PopInt(ctx);
    sithSurface* surface = sithCogVm_PopSurface(ctx);

    if (surface && flags)
    {
        surface->surfaceFlags &= ~flags;
        if (sithCogVm_multiplayerFlags && (ctx->flags & 0x200) == 0 )
        {
            if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
                sithSurface_PushSurface(surface);
        }
    }
}

void sithCogSurface_GetSurfaceFlags(sithCog *ctx)
{
    sithSurface* surface = sithCogVm_PopSurface(ctx);

    if ( surface )
        sithCogVm_PushInt(ctx, surface->surfaceFlags);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogSurface_SetAdjoinFlags(sithCog *ctx)
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
                if ( sithCogVm_multiplayerFlags )
                {
                    if ( (ctx->flags & 0x200) == 0 )
                    {
                        if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
                            sithSurface_PushSurface(surface);
                    }
                }
            }
        }
    }
}

void sithCogSurface_ClearAdjoinFlags(sithCog *ctx)
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
                if ( sithCogVm_multiplayerFlags )
                {
                    if ( (ctx->flags & 0x200) == 0 )
                    {
                        if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
                            sithSurface_PushSurface(surface);
                    }
                }
            }
        }
    }
}

void sithCogSurface_GetAdjoinFlags(sithCog *ctx)
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

void sithCogSurface_SetFaceType(sithCog *ctx)
{
    uint32_t type = sithCogVm_PopInt(ctx);
    sithSurface* surface = sithCogVm_PopSurface(ctx);
    if ( surface )
    {
        surface->surfaceInfo.face.type |= type;
        if (sithCogVm_multiplayerFlags && !(ctx->flags & 0x200))
        {
            if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
                sithSurface_PushSurface(surface);
        }
    }
}

void sithCogSurface_ClearFaceType(sithCog *ctx)
{
    uint32_t type = sithCogVm_PopInt(ctx);
    sithSurface* surface = sithCogVm_PopSurface(ctx);
    if ( surface )
    {
        surface->surfaceInfo.face.type &= ~type;
        if (sithCogVm_multiplayerFlags && !(ctx->flags & 0x200))
        {
            if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
                sithSurface_PushSurface(surface);
        }
    }
}

void sithCogSurface_GetFaceType(sithCog *ctx)
{
    sithSurface* surface = sithCogVm_PopSurface(ctx);
    if ( surface )
        sithCogVm_PushInt(ctx, surface->surfaceInfo.face.type);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogSurface_SetFaceGeoMode(sithCog *ctx)
{
    signed int v1; // edi
    sithSurface *v2; // eax
    int v3; // ecx
    int v4; // esi
    int v5; // ecx
    int v6; // esi

    v1 = sithCogVm_PopInt(ctx);
    v2 = sithCogVm_PopSurface(ctx);
    if ( v2 )
    {
        if ( v2->surfaceInfo.face.material )
        {
            v3 = sithCogVm_multiplayerFlags;
            v2->surfaceInfo.face.geometryMode = v1;
            if ( v3 )
            {
                if ( (ctx->flags & 0x200) == 0 )
                {
                    v4 = ctx->trigId;
                    if ( v4 != SITH_MESSAGE_STARTUP && v4 != SITH_MESSAGE_SHUTDOWN )
                    {
LABEL_12:
                        sithSurface_PushSurface(v2);
                        return;
                    }
                }
            }
        }
        else
        {
            v5 = sithCogVm_multiplayerFlags;
            v2->surfaceInfo.face.geometryMode = 0;
            if ( v5 )
            {
                if ( (ctx->flags & 0x200) == 0 )
                {
                    v6 = ctx->trigId;
                    if ( v6 != SITH_MESSAGE_STARTUP && v6 != SITH_MESSAGE_SHUTDOWN )
                        goto LABEL_12;
                }
            }
        }
    }
}

void sithCogSurface_GetFaceGeoMode(sithCog *ctx)
{
    sithSurface *v1; // eax

    v1 = sithCogVm_PopSurface(ctx);
    if ( v1 )
        sithCogVm_PushInt(ctx, v1->surfaceInfo.face.geometryMode);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogSurface_SetFaceLightMode(sithCog *ctx)
{
    signed int v1; // edi
    sithSurface *v2; // eax
    int v3; // ecx
    int v4; // esi

    v1 = sithCogVm_PopInt(ctx);
    v2 = sithCogVm_PopSurface(ctx);
    if ( v2 )
    {
        v3 = sithCogVm_multiplayerFlags;
        v2->surfaceInfo.face.lightingMode = v1;
        if ( v3 )
        {
            if ( (ctx->flags & 0x200) == 0 )
            {
                v4 = ctx->trigId;
                if ( v4 != SITH_MESSAGE_STARTUP && v4 != SITH_MESSAGE_SHUTDOWN )
                    sithSurface_PushSurface(v2);
            }
        }
    }
}

void sithCogSurface_GetFaceLightMode(sithCog *ctx)
{
    sithSurface *v1; // eax

    v1 = sithCogVm_PopSurface(ctx);
    if ( v1 )
        sithCogVm_PushInt(ctx, v1->surfaceInfo.face.lightingMode);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogSurface_SetFaceTexMode(sithCog *ctx)
{
    signed int v1; // edi
    sithSurface *v2; // eax
    int v3; // ecx
    int v4; // esi

    v1 = sithCogVm_PopInt(ctx);
    v2 = sithCogVm_PopSurface(ctx);
    if ( v2 )
    {
        v3 = sithCogVm_multiplayerFlags;
        v2->surfaceInfo.face.textureMode = v1;
        if ( v3 )
        {
            if ( (ctx->flags & 0x200) == 0 )
            {
                v4 = ctx->trigId;
                if ( v4 != SITH_MESSAGE_STARTUP && v4 != SITH_MESSAGE_SHUTDOWN )
                    sithSurface_PushSurface(v2);
            }
        }
    }
}

void sithCogSurface_GetFaceTexMode(sithCog *ctx)
{
    sithSurface *v1; // eax

    v1 = sithCogVm_PopSurface(ctx);
    if ( v1 )
        sithCogVm_PushInt(ctx, v1->surfaceInfo.face.textureMode);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogSurface_SetSurfaceLight(sithCog *ctx)
{
    sithSurface *v2; // ecx
    int v3; // esi
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
            if ( sithCogVm_multiplayerFlags )
            {
                if ( (ctx->flags & 0x200) == 0 )
                {
                    v3 = ctx->trigId;
                    if ( v3 != 3 && v3 != 22 )
                        sithSurface_PushSurface(v2);
                }
            }
        }
        else
        {
            sithSurface_SurfaceLightAnim(v2, a1, v4);
        }
    }
}

void sithCogSurface_GetSurfaceLight(sithCog *ctx)
{
    sithSurface *v1; // eax

    v1 = sithCogVm_PopSurface(ctx);
    if ( v1 )
        sithCogVm_PushFlex(ctx, v1->surfaceInfo.face.extraLight);
}

void sithCogSurface_GetSurfaceCenter(sithCog *ctx)
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

void sithCogSurface_GetSurfaceCount(sithCog *ctx)
{
    if ( sithWorld_pCurWorld )
        sithCogVm_PushInt(ctx, sithWorld_pCurWorld->numSurfaces);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogSurface_GetSurfaceNormal(sithCog *ctx)
{
    sithSurface *v1; // eax

    v1 = sithCogVm_PopSurface(ctx);
    if ( v1 )
        sithCogVm_PushVector3(ctx, &v1->surfaceInfo.face.normal);
    else
        sithCogVm_PushVector3(ctx, &rdroid_zeroVector3);
}

void sithCogSurface_SyncSurface(sithCog *ctx)
{
    sithSurface *v1; // eax

    v1 = sithCogVm_PopSurface(ctx);
    if ( v1 )
        sithSurface_PushSurface(v1);
}
