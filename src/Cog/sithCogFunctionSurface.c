#include "sithCogFunctionSurface.h"

#include "Cog/sithCogExec.h"
#include "World/sithWorld.h"
#include "World/sithSector.h"
#include "World/sithSurface.h"
#include "Main/Main.h"


void sithCogFunctionSurface_GetSurfaceAdjoin(sithCog *ctx)
{
    sithSurface *surface; // eax
    uint32_t *v2; // eax

    surface = sithCogExec_PopSurface(ctx);
    if ( surface && (v2 = &surface->adjoin->mirror->surface->field_0) != 0 )
        sithCogExec_PushInt(ctx, *v2);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_GetSurfaceSector(sithCog *ctx)
{
    sithSurface *v1; // eax
    uint32_t *v2; // eax

    v1 = sithCogExec_PopSurface(ctx);
    if ( v1 && (v2 = &v1->parent_sector->id) != 0 )
        sithCogExec_PushInt(ctx, *v2);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_GetNumSurfaceVertices(sithCog *ctx)
{
    sithSurface *surface; // eax

    surface = sithCogExec_PopSurface(ctx);
    if ( surface )
        sithCogExec_PushInt(ctx, surface->surfaceInfo.face.numVertices);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_GetSurfaceVertexPos(sithCog *ctx)
{
    uint32_t vtx_idx; // edi
    sithSurface *surface; // eax

    vtx_idx = sithCogExec_PopInt(ctx);
    surface = sithCogExec_PopSurface(ctx);
    if ( surface && vtx_idx < surface->surfaceInfo.face.numVertices && (vtx_idx & 0x80000000) == 0 )
        sithCogExec_PushVector3(ctx, &sithWorld_pCurrentWorld->vertices[surface->surfaceInfo.face.vertexPosIdx[vtx_idx]]);
    else
        sithCogExec_PushVector3(ctx, &rdroid_zeroVector3);
}

void sithCogFunctionSurface_SetHorizonSkyOffset(sithCog *ctx)
{
    rdVector3 offs;

    // TODO add valid check?
    sithCogExec_PopVector3(ctx, &offs);
    sithWorld_pCurrentWorld->horizontalSkyOffs.x = offs.x;
    sithWorld_pCurrentWorld->horizontalSkyOffs.y = offs.y;
}

void sithCogFunctionSurface_GetHorizonSkyOffset(sithCog *ctx)
{
    rdVector3 offs;

    offs.x = sithWorld_pCurrentWorld->horizontalSkyOffs.x;
    offs.y = sithWorld_pCurrentWorld->horizontalSkyOffs.y;
    offs.z = 0.0;
    sithCogExec_PushVector3(ctx, &offs);
}

void sithCogFunctionSurface_SetCeilingSkyOffset(sithCog *ctx)
{
    rdVector3 offs;

    // TODO add valid check?
    sithCogExec_PopVector3(ctx, &offs);
    sithWorld_pCurrentWorld->ceilingSkyOffs.x = offs.x;
    sithWorld_pCurrentWorld->ceilingSkyOffs.y = offs.y;
}

void sithCogFunctionSurface_GetCeilingSkyOffset(sithCog *ctx)
{
    rdVector3 offs;

    offs.x = sithWorld_pCurrentWorld->ceilingSkyOffs.x;
    offs.y = sithWorld_pCurrentWorld->ceilingSkyOffs.y;
    offs.z = 0.0;
    sithCogExec_PushVector3(ctx, &offs);
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

    float v5 = sithCogExec_PopFlex(ctx);
    float v6 = sithCogExec_PopFlex(ctx);
    float a1 = sithCogExec_PopFlex(ctx);
    sithSurface* v2 = sithCogExec_PopSurface(ctx);
    if ( v2 && v6 >= (double)a1 && v5 > 0.0 && (v4 = v5 * 0.5, v2->surfaceInfo.face.extraLight = a1, (v3 = sithSurface_SurfaceLightAnim(v2, v6, v4)) != 0) )
        sithCogExec_PushInt(ctx, v3->index);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SlideWallSurface(sithCog *ctx)
{
    signed int pop_vec; // ebx
    sithSurface *surface; // eax
    sithSurface *v4; // edi
    rdSurface *v5; // ebx
    rdVector3 v7; // [esp+Ch] [ebp-Ch] BYREF
    float scale; // [esp+1Ch] [ebp+4h]

    scale = sithCogExec_PopFlex(ctx) * 0.1;
    pop_vec = sithCogExec_PopVector3(ctx, &v7);
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
    sithSurface* surface = sithCogExec_PopSurface(ctx);
    if ( surface && surface->surfaceInfo.face.material )
        sithCogExec_PushInt(ctx, surface->surfaceInfo.face.wallCel);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetWallCel(sithCog *ctx)
{
    int wallCel; // esi
    sithSurface *surface; // eax
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

void sithCogFunctionSurface_GetSurfaceMat(sithCog *ctx)
{
    rdMaterial *v2; // eax

    sithSurface* surface = sithCogExec_PopSurface(ctx);
    if ( surface && (v2 = surface->surfaceInfo.face.material) != 0 )
        sithCogExec_PushInt(ctx, v2 - sithWorld_pCurrentWorld->materials);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetSurfaceMat(sithCog *ctx)
{
    rdMaterial *v4; // eax

    rdMaterial* mat = sithCogExec_PopMaterial(ctx);
    sithSurface* surface = sithCogExec_PopSurface(ctx);
    if ( surface )
    {
        v4 = surface->surfaceInfo.face.material;
        surface->surfaceInfo.face.material = mat;
        if ( v4 )
            sithCogExec_PushInt(ctx, v4 - sithWorld_pCurrentWorld->materials);
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
    sithSurface* surface = sithCogExec_PopSurface(ctx);

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
    sithSurface* surface = sithCogExec_PopSurface(ctx);

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
    sithSurface* surface = sithCogExec_PopSurface(ctx);

    if ( surface )
        sithCogExec_PushInt(ctx, surface->surfaceFlags);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetAdjoinFlags(sithCog *ctx)
{
    uint32_t flags = sithCogExec_PopInt(ctx);
    sithSurface* surface = sithCogExec_PopSurface(ctx);

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
    uint32_t flags = sithCogExec_PopInt(ctx);
    sithSurface* surface = sithCogExec_PopSurface(ctx);

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
    sithSurface* surface = sithCogExec_PopSurface(ctx);
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
    sithSurface* surface = sithCogExec_PopSurface(ctx);
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
    sithSurface* surface = sithCogExec_PopSurface(ctx);
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
    sithSurface* surface = sithCogExec_PopSurface(ctx);
    if ( surface )
        sithCogExec_PushInt(ctx, surface->surfaceInfo.face.type);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetFaceGeoMode(sithCog *ctx)
{
    rdGeoMode_t geoMode; // edi
    sithSurface *v2; // eax

    geoMode = (rdGeoMode_t)sithCogExec_PopInt(ctx);
    v2 = sithCogExec_PopSurface(ctx);
    if ( v2 )
    {
        if ( v2->surfaceInfo.face.material )
        {
            // MoTS added
            if (!v2->surfaceInfo.face.vertexUVIdx && geoMode == RD_GEOMODE_TEXTURED) {
                geoMode = RD_GEOMODE_SOLIDCOLOR;
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

    v1 = sithCogExec_PopSurface(ctx);
    if ( v1 )
        sithCogExec_PushInt(ctx, (int)v1->surfaceInfo.face.geometryMode);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetFaceLightMode(sithCog *ctx)
{
    rdLightMode_t lightMode; // edi
    sithSurface *v2; // eax

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
    sithSurface *v1; // eax

    v1 = sithCogExec_PopSurface(ctx);
    if ( v1 )
        sithCogExec_PushInt(ctx, (int)v1->surfaceInfo.face.lightingMode);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetFaceTexMode(sithCog *ctx)
{
    rdTexMode_t texMode; // edi
    sithSurface *v2; // eax

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
    sithSurface *v1; // eax

    v1 = sithCogExec_PopSurface(ctx);
    if ( v1 )
        sithCogExec_PushInt(ctx, (int)v1->surfaceInfo.face.textureMode);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_SetSurfaceLight(sithCog *ctx)
{
    sithSurface *v2; // ecx
    float v4; // [esp+4h] [ebp-4h]
    float a1; // [esp+Ch] [ebp+4h]

    v4 = sithCogExec_PopFlex(ctx);
    a1 = sithCogExec_PopFlex(ctx);
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
    sithSurface *v1; // eax

    v1 = sithCogExec_PopSurface(ctx);
    if ( v1 ) {
        sithCogExec_PushFlex(ctx, v1->surfaceInfo.face.extraLight);
    }
    // TODO: Always return *something*?
}

void sithCogFunctionSurface_GetSurfaceCenter(sithCog *ctx)
{
    sithSurface *v1; // eax
    rdVector3 a2; // [esp+4h] [ebp-Ch] BYREF

    v1 = sithCogExec_PopSurface(ctx);
    if ( v1 )
    {
        sithSurface_GetCenter(v1, &a2);
        sithCogExec_PushVector3(ctx, &a2);
    }
    else
    {
        sithCogExec_PushVector3(ctx, &rdroid_zeroVector3);
    }
}

void sithCogFunctionSurface_GetSurfaceCount(sithCog *ctx)
{
    if ( sithWorld_pCurrentWorld )
        sithCogExec_PushInt(ctx, sithWorld_pCurrentWorld->numSurfaces);
    else
        sithCogExec_PushInt(ctx, -1);
}

void sithCogFunctionSurface_GetSurfaceNormal(sithCog *ctx)
{
    sithSurface *v1; // eax

    v1 = sithCogExec_PopSurface(ctx);
    if ( v1 )
        sithCogExec_PushVector3(ctx, &v1->surfaceInfo.face.normal);
    else
        sithCogExec_PushVector3(ctx, &rdroid_zeroVector3);
}

void sithCogFunctionSurface_SyncSurface(sithCog *ctx)
{
    sithSurface *v1; // eax

    v1 = sithCogExec_PopSurface(ctx);
    if ( v1 )
        sithSurface_SyncSurface(v1);
}

// MOTS added
void sithCogFunctionSurface_GetSurfaceVertexLight(sithCog *ctx)
{
    int num = sithCogExec_PopInt(ctx);
    sithSurface* pSurface = sithCogExec_PopSurface(ctx);
    
    if ((pSurface && (num < (pSurface->surfaceInfo).face.numVertices)) && num > -1) {
        sithCogExec_PushFlex(ctx,(pSurface->surfaceInfo).intensities[num]);
        return;
    }
    
    sithCogExec_PushFlex(ctx,-1.0);
}

// MOTS added
void sithCogFunctionSurface_SetSurfaceVertexLight(sithCog *ctx)
{
    float val = sithCogExec_PopFlex(ctx);
    int num = sithCogExec_PopInt(ctx);
    sithSurface* pSurface = sithCogExec_PopSurface(ctx);

    if ((pSurface && ((uint32_t)num < (pSurface->surfaceInfo).face.numVertices)) && num > -1) {
        (pSurface->surfaceInfo).intensities[num] = val;
    }
}

// MOTS added
void sithCogFunctionSurface_GetSurfaceVertexLightRGB(sithCog *ctx)
{
    rdVector3 tmp;

    int num = sithCogExec_PopInt(ctx);
    sithSurface* pSurface = sithCogExec_PopSurface(ctx);
    if (pSurface == (sithSurface *)0x0) {
        tmp.x = -1.0;
        tmp.y = -1.0;
        tmp.z = -1.0;
        sithCogExec_PushVector3(ctx,&tmp);
        return;
    }

    uint32_t numVerts = (pSurface->surfaceInfo).face.numVertices;
    if ((num < numVerts) && (-1 < num)) {
        if ((pSurface->surfaceFlags & SITH_SURFACE_1000000) == 0) {
            tmp.x = -1.0;
            tmp.y = -1.0;
            tmp.z = -1.0;
            sithCogExec_PushVector3(ctx,&tmp);
            return;
        }
        tmp.x = (pSurface->surfaceInfo).intensities[num + numVerts];
        tmp.y = (pSurface->surfaceInfo).intensities[num + (pSurface->surfaceInfo).face.numVertices * 2];
        tmp.z = (pSurface->surfaceInfo).intensities[num + (pSurface->surfaceInfo).face.numVertices * 3];
        sithCogExec_PushVector3(ctx,&tmp);
        return;
    }

    tmp.x = -1.0;
    tmp.y = -1.0;
    tmp.z = -1.0;
    sithCogExec_PushVector3(ctx,&tmp);
}

// MOTS added
void sithCogFunctionSurface_SetSurfaceVertexLightRGB(sithCog *ctx)
{
    rdVector3 valRGB;
    uint32_t uVar1;
    
    sithCogExec_PopVector3(ctx, &valRGB);
    int num = sithCogExec_PopInt(ctx);
    sithSurface* pSurface = sithCogExec_PopSurface(ctx);

    if ((((pSurface != (sithSurface *)0x0) 
        && (uVar1 = (pSurface->surfaceInfo).face.numVertices, (uint32_t)num < uVar1)) && (-1 < num)) 
        && ((pSurface->surfaceFlags & SITH_SURFACE_1000000) != 0)) {
        (pSurface->surfaceInfo).intensities[num + uVar1] = valRGB.x;
        (pSurface->surfaceInfo).intensities[num + (pSurface->surfaceInfo).face.numVertices * 2] = valRGB.y;
        (pSurface->surfaceInfo).intensities[num + (pSurface->surfaceInfo).face.numVertices * 3] = valRGB.z;
    }
}

void sithCogFunctionSurface_Startup(void* ctx)
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
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetSurfaceVertexLight, "getsurfacevertexlight");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SetSurfaceVertexLight, "setsurfacevertexlight");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetSurfaceVertexLightRGB, "getsurfacevertexlightrgb");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SetSurfaceVertexLightRGB, "setsurfacevertexlightrgb");
    }
}
