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

static void (*sithCogSurface_SetFaceGeoMode)(sithCog* ctx) = (void*)0x00500790;
static void (*sithCogSurface_GetFaceGeoMode)(sithCog* ctx) = (void*)0x00500820;
static void (*sithCogSurface_SetFaceLightMode)(sithCog* ctx) = (void*)0x00500850;
static void (*sithCogSurface_GetFaceLightMode)(sithCog* ctx) = (void*)0x005008A0;
static void (*sithCogSurface_SetFaceTexMode)(sithCog* ctx) = (void*)0x005008D0;
static void (*sithCogSurface_GetFaceTexMode)(sithCog* ctx) = (void*)0x00500920;
static void (*sithCogSurface_SetSurfaceLight)(sithCog* ctx) = (void*)0x00500950;
static void (*sithCogSurface_GetSurfaceLight)(sithCog* ctx) = (void*)0x005009F0;
static void (*sithCogSurface_GetSurfaceCenter)(sithCog* ctx) = (void*)0x00500A20;
static void (*sithCogSurface_GetSurfaceCount)(sithCog* ctx) = (void*)0x00500A70;
static void (*sithCogSurface_GetSurfaceNormal)(sithCog* ctx) = (void*)0x00500AA0;
static void (*sithCogSurface_SyncSurface)(sithCog* ctx) = (void*)0x00500AE0;


void sithCogSurface_Initialize(void* ctx)
{
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_GetSurfaceAdjoin, "getsurfaceadjoin");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_GetSurfaceSector, "getsurfacesector");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_GetNumSurfaceVertices, "getnumsurfacevertices");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_GetSurfaceVertexPos, "getsurfacevertexpos");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_SetHorizonSkyOffset, "sethorizonskyoffset");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_GetHorizonSkyOffset, "gethorizonskyoffset");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_SetCeilingSkyOffset, "setceilingskyoffset");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_GetCeilingSkyOffset, "getceilingskyoffset");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_SlideHorizonSky, "slidehorizonsky");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_SlideCeilingSky, "slideceilingsky");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_GetSurfaceCount, "getsurfacecount");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_SlideWallSurface, "slidewall");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_SlideWallSurface, "slidesurface");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_GetWallCel, "getwallcel");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_SetWallCel, "setwallcel");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_GetWallCel, "getsurfacecel");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_SetWallCel, "setsurfacecel");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_GetSurfaceMat, "getsurfacemat");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_SetSurfaceMat, "setsurfacemat");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_GetSurfaceFlags, "getsurfaceflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_SetSurfaceFlags, "setsurfaceflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_ClearSurfaceFlags, "clearsurfaceflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_GetAdjoinFlags, "getadjoinflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_SetAdjoinFlags, "setadjoinflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_ClearAdjoinFlags, "clearadjoinflags");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_SetFaceType, "setfacetype");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_ClearFaceType, "clearfacetype");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_GetFaceType, "getfacetype");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_SetFaceGeoMode, "setfacegeomode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_GetFaceGeoMode, "getfacegeomode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_SetFaceLightMode, "setfacelightmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_GetFaceLightMode, "getfacelightmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_SetFaceTexMode, "setfacetexmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_GetFaceTexMode, "getfacetexmode");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_GetSurfaceLight, "getsurfacelight");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_SetSurfaceLight, "setsurfacelight");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_SetSurfaceLight, "surfacelight");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_GetSurfaceCenter, "getsurfacecenter");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_GetSurfaceCenter, "surfacecenter");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_SurfaceLightAnim, "surfacelightanim");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_GetSurfaceNormal, "getsurfacenormal");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSurface_SyncSurface, "syncsurface");
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
