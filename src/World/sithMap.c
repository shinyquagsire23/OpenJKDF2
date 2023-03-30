#include "sithMap.h"

#include "World/sithThing.h"
#include "Main/sithMain.h"
#include "Engine/rdroid.h"
#include "Dss/sithMulti.h"
#include "Primitives/rdPrimit2.h"
#include "Primitives/rdPrimit3.h"
#include "Engine/rdClip.h"
#include "World/sithSector.h"
#include "jk.h"

#include <math.h>
#include <float.h>

int sithMap_Startup(sithMap *map)
{
    if ( sithMap_bInitted )
        return 0;

    _memcpy(&sithMap_ctx, map, sizeof(sithMap_ctx));
    sithMap_bInitted = 1;
    return 1;
}

int sithMap_Shutdown()
{
    if ( sithMap_bInitted )
    {
        sithMap_bInitted = 0;
        return 1;
    }

    return 0;
}

void sithMap_DrawCircle(rdCamera *camera, rdMatrix34 *viewMat)
{
    sithThing *v2; // edx
    sithSector *v3; // esi
    int v5; // eax
    sithAdjoin *i; // esi
    int color; // esi
    float a2a; // [esp+0h] [ebp-20h]
    rdVector3 vertex_out; // [esp+14h] [ebp-Ch] BYREF

    sithMain_sub_4C4D80();
    rdSetGeometryMode(2);
    rdSetLightingMode(1);
    sithMap_pCurCamera = camera;
    sithMap_pCurWorld = sithWorld_pCurrentWorld;
    sithMap_pPlayerThing = sithWorld_pCurrentWorld->playerThing;
    rdMatrix_Multiply34(&sithMap_camera, &camera->view_matrix, viewMat);
    rdMatrix_InvertOrtho34(&sithMap_invMatrix, &sithMap_camera);
    v2 = sithMap_pPlayerThing;
    sithMap_var = 1;
    v3 = sithMap_pPlayerThing->sector;
    if ( v3->renderTick == sithRender_lastRenderTick )
    {
LABEL_10:
        v2 = sithMap_pPlayerThing;
        --sithMap_var;
        goto LABEL_11;
    }

    if ( (v3->flags & SITH_SECTOR_AUTOMAPVISIBLE) != 0 || (g_mapModeFlags & 2) != 0 )
    {
        v3->renderTick = sithRender_lastRenderTick;
        if ( (v3->flags & 0x10) != 0 )
            v5 = 1;
        else
            v5 = sithMap_Draw(v3);
        if ( v5 )
        {
            for ( i = v3->adjoins; i; i = i->next )
                sithMap_sub_4EC4D0(i->sector);
        }
        goto LABEL_10;
    }
LABEL_11:
    if ( sithNet_isMulti && (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) != 0 )
        color = sithMap_ctx.teamColors[v2->actorParams.playerinfo->teamNum];
    else
        color = sithMap_ctx.playerColor;
    rdMatrix_TransformPoint34(&vertex_out, &v2->position, &sithMap_camera);
    a2a = sithMap_pPlayerThing->moveSize + sithMap_pPlayerThing->moveSize;
    rdPrimit3_DrawCircle(&vertex_out, a2a, 20.0, color, -1);
}

void sithMap_sub_4EC4D0(sithSector *sector)
{
    int v2; // eax
    sithAdjoin *i; // esi

    if ( ++sithMap_var >= 20 || sector->renderTick == sithRender_lastRenderTick )
    {
LABEL_11:
        --sithMap_var;
        return;
    }

    if ( (sector->flags & SITH_SECTOR_AUTOMAPVISIBLE) != 0 || (g_mapModeFlags & 2) != 0 )
    {
        sector->renderTick = sithRender_lastRenderTick;
        if ( (sector->flags & SITH_SECTOR_AUTOMAPHIDE) != 0 )
            v2 = 1;
        else
            v2 = sithMap_Draw(sector);
        if ( v2 )
        {
            for ( i = sector->adjoins; i; i = i->next )
                sithMap_sub_4EC4D0(i->sector);
        }
        goto LABEL_11;
    }
}

int sithMap_Draw(sithSector *sector)
{
    sithSector *v1; // esi
    int v2; // ecx
    sithSurface *v3; // ebx
    sithWorld *v4; // ecx
    int v5; // edx
    sithSurface *surfaceIter; // ebx
    rdVector3 *v7; // esi
    int v8; // esi
    int v9; // eax
    int v10; // eax
    int v11; // esi
    unsigned int v12; // esi
    unsigned int v13; // edi
    unsigned int v14; // eax
    int *v15; // ecx
    int v16; // esi
    int v17; // edi
    int v18; // edi
    unsigned int v19; // ecx
    float *v20; // esi
    double v22; // st7
    int v24; // eax
    int v25; // ecx
    unsigned int v34; // edi
    sithThing *i; // edi
    int circleColor; // esi
    float xOffs; // [esp+0h] [ebp-94h]
    rdVector3 vertex_out; // [esp+1Ch] [ebp-78h] BYREF
    rdVector3 v43; // [esp+28h] [ebp-6Ch] BYREF
    rdVector3 point2; // [esp+34h] [ebp-60h] BYREF
    rdVector3 point1; // [esp+40h] [ebp-54h] BYREF
    rdVector3 v46; // [esp+4Ch] [ebp-48h] BYREF
    unsigned int v47; // [esp+58h] [ebp-3Ch]
    int a2; // [esp+5Ch] [ebp-38h]
    int a3; // [esp+60h] [ebp-34h]
    int a4; // [esp+64h] [ebp-30h]
    int a5; // [esp+68h] [ebp-2Ch]
    int v52; // [esp+6Ch] [ebp-28h]
    float v53; // [esp+70h] [ebp-24h]
    float v54; // [esp+74h] [ebp-20h]
    float v55; // [esp+78h] [ebp-1Ch]
    int v56; // [esp+7Ch] [ebp-18h]
    unsigned int v57; // [esp+80h] [ebp-14h]
    int v58; // [esp+84h] [ebp-10h]
    sithSurface *a1; // [esp+88h] [ebp-Ch]
    int out2; // [esp+8Ch] [ebp-8h] BYREF
    int out1; // [esp+90h] [ebp-4h] BYREF

    v1 = sector;
    v56 = 0;
    v2 = sector->numSurfaces;
    v3 = sector->surfaces;
    a1 = v3;
    v57 = 0;
    if ( v2 )
    {
        v4 = sithMap_pCurWorld;
        v5 = sithRender_lastRenderTick;
        surfaceIter = v3;
        do
        {
            if ( surfaceIter->surfaceInfo.face.geometryMode )
            {
                v7 = v4->vertices;
                if ( (sithMap_flt_84DEAC - v7[*surfaceIter->surfaceInfo.face.vertexPosIdx].z) * surfaceIter->surfaceInfo.face.normal.z
                   + (sithMap_flt_84DEA8 - v7[*surfaceIter->surfaceInfo.face.vertexPosIdx].y) * surfaceIter->surfaceInfo.face.normal.y
                   + (sithMap_invMatrix.scale.x - v7[*surfaceIter->surfaceInfo.face.vertexPosIdx].x) * surfaceIter->surfaceInfo.face.normal.x > 0.0 )
                {
                    if ( surfaceIter->field_4 != v5 )
                    {
                        v8 = surfaceIter->surfaceInfo.face.numVertices;
                        v9 = 0;
                        v58 = 0;
                        if ( v8 )
                        {
                            do
                            {
                                v10 = surfaceIter->surfaceInfo.face.vertexPosIdx[v9];
                                v11 = v10;
                                if ( sithWorld_pCurrentWorld->alloc_unk98[v10] != v5 )
                                {
                                    rdMatrix_TransformPoint34(&v4->verticesTransformed[v10], &v4->vertices[v10], &sithMap_camera);
                                    v4 = sithMap_pCurWorld;
                                    v5 = sithRender_lastRenderTick;
                                    sithMap_pCurWorld->alloc_unk98[v11] = sithRender_lastRenderTick;
                                }
                                v12 = surfaceIter->surfaceInfo.face.numVertices;
                                v9 = ++v58;
                            }
                            while ( v58 < v12 );
                        }
                        surfaceIter->field_4 = v5;
                    }
                    v13 = surfaceIter->surfaceInfo.face.numVertices;
                    v14 = 0;
                    if ( v13 )
                    {
                        do
                        {
                            v15 = surfaceIter->surfaceInfo.face.vertexPosIdx;
                            v47 = v14 + 1;
                            v16 = v15[v14];
                            v17 = v15[(v14 + 1) % v13];
                            if ( sithMap_IsSurfaceDrawable(a1, v16, v17) )
                            {
                                point1 = sithMap_pCurWorld->verticesTransformed[v16];
                                point2 = sithMap_pCurWorld->verticesTransformed[v17];
                                if ( rdClip_Line3Project(sithMap_pCurCamera->pClipFrustum, &point1, &point2, &out1, &out2) )
                                {
                                    sithMap_pCurCamera->fnProject(&v46, &point1);
                                    sithMap_pCurCamera->fnProject(&v43, &point2);
                                    v18 = 0;
                                    v19 = 0;
                                    if ( sithMap_ctx.numArr )
                                    {
                                        v20 = sithMap_ctx.unkArr;
                                        while ( 1 )
                                        {
                                            v22 = v46.z;
                                            if ( v22 < 0.0 )
                                                v22 = -v22;
                                            if ( v22 < *v20 )
                                                break;
                                            ++v19;
                                            ++v20;
                                            if ( v19 >= sithMap_ctx.numArr )
                                                goto LABEL_22;
                                        }
                                        v18 = 1;
                                    }
LABEL_22:
                                    if ( v18 )
                                    {
                                        v24 = -1;
                                        v25 = sithMap_ctx.anonymous_1[v19];
                                    }
                                    else
                                    {
                                        v25 = sithMap_ctx.anonymous_1[sithMap_ctx.numArr - 1];
                                        v24 = 0xCCCCCCCC;
                                    }
                                    if ( rdPrimit2_DrawClippedLine(sithMap_pCurCamera->canvas, ceilf(v46.x), ceilf(v46.y), ceilf(v43.x), ceilf(v43.y), (uint8_t)v25, v24) )
                                        v56 = 1;
                                }
                            }
                            v14 = v47;
                            v13 = surfaceIter->surfaceInfo.face.numVertices;
                        }
                        while ( v47 < v13 );
                        v4 = sithMap_pCurWorld;
                        v5 = sithRender_lastRenderTick;
                    }
                }
            }
            v1 = sector;
            ++surfaceIter;
            v34 = sector->numSurfaces;
            ++a1;
            ++v57;
        }
        while ( v57 < v34 );
    }
    if ( (g_mapModeFlags & 0x4C) != 0 )
    {
        for ( i = v1->thingsList; i; i = i->nextThing )
        {
            if ( i != sithWorld_pCurrentWorld->cameraFocus && (i->thingflags & (SITH_TF_DISABLED|SITH_TF_10|SITH_TF_WILLBEREMOVED)) == 0 )
            {
                int v37 = (g_mapModeFlags & 0x40) != 0;
                switch ( i->thingtype )
                {
                    case SITH_THING_PLAYER:
                        if ( (g_mapModeFlags & 0xC) != 0 )
                            v37 = 1;
                        if ( sithNet_isMulti && (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) != 0 )
                            circleColor = sithMap_ctx.teamColors[i->actorParams.playerinfo->teamNum];
                        else
                            circleColor = sithMap_ctx.playerColor & 0xFF;
                        break;
                    case SITH_THING_ACTOR:
                        if ( (g_mapModeFlags & 8) != 0 )
                            v37 = 1;
                        circleColor = sithMap_ctx.actorColor & 0xFF;
                        break;
                    case SITH_THING_ITEM:
                        if ( (g_mapModeFlags & 0x10) != 0 )
                            v37 = 1;
                        circleColor = sithMap_ctx.itemColor & 0xFF;
                        break;
                    case SITH_THING_WEAPON:
                        if ( (g_mapModeFlags & 0x20) != 0 )
                            v37 = 1;
                        circleColor = sithMap_ctx.weaponColor & 0xFF;
                        break;
                    default:
                        circleColor = sithMap_ctx.otherColor & 0xFF;
                        break;
                }
                if ( v37 )
                {
                    rdMatrix_TransformPoint34(&vertex_out, &i->position, &sithMap_camera);
                    xOffs = i->moveSize + i->moveSize;
                    rdPrimit3_DrawCircle(&vertex_out, xOffs, 20.0, (uint8_t)circleColor, -1);
                }
            }
        }
    }
    return v56;
}

int sithMap_IsSurfaceDrawable(sithSurface *pSurface, int idx, int idx2)
{
    sithSector *v3; // eax
    unsigned int v4; // edx
    sithSurface *v5; // ecx
    sithSurface *surfaceIter; // ebx
    unsigned int v7; // esi
    int v8; // eax
    int *v9; // edi
    unsigned int v10; // ecx
    sithSector *v12; // eax
    unsigned int v13; // ecx
    sithSurface *surfaceIter_2; // ebp
    unsigned int v15; // esi
    int v16; // eax
    int *v17; // edi
    unsigned int v18; // ecx
    int v20; // [esp+10h] [ebp-10h]
    int v21; // [esp+10h] [ebp-10h]
    sithSurface *v22; // [esp+14h] [ebp-Ch]
    sithAdjoin *v23; // [esp+14h] [ebp-Ch]
    unsigned int v24; // [esp+18h] [ebp-8h]
    sithSector *v25; // [esp+1Ch] [ebp-4h]
    unsigned int v26; // [esp+1Ch] [ebp-4h]

    v3 = pSurface->parent_sector;
    v25 = v3;
    v20 = 0;
    v4 = v3->numSurfaces;
    v5 = v3->surfaces;
    v22 = v5;
    v24 = v4;
    if ( v4 )
    {
        surfaceIter = v5;
        while ( 1 )
        {
            if ( v5 != pSurface && !surfaceIter->adjoin )
            {
                v7 = surfaceIter->surfaceInfo.face.numVertices;
                v8 = 0;
                if ( surfaceIter->surfaceInfo.face.numVertices )
                    break;
            }
LABEL_12:
            ++v5;
            ++surfaceIter;
            int v11 = v20 + 1 < v4;
            v22 = v5;
            ++v20;
            if ( !v11 )
            {
                v3 = v25;
                goto LABEL_14;
            }
        }
        v9 = surfaceIter->surfaceInfo.face.vertexPosIdx;
        while ( 1 )
        {
            v10 = v8 + 1;
            if ( *v9 == idx2
              && surfaceIter->surfaceInfo.face.vertexPosIdx[(v8 + 1) % v7] == idx
              && surfaceIter->surfaceInfo.face.normal.y * pSurface->surfaceInfo.face.normal.y
               + surfaceIter->surfaceInfo.face.normal.x * pSurface->surfaceInfo.face.normal.x
               + surfaceIter->surfaceInfo.face.normal.z * pSurface->surfaceInfo.face.normal.z > 0.98000002 )
            {
                return 0;
            }
            ++v8;
            ++v9;
            if ( v10 >= v7 )
            {
                v4 = v24;
                v5 = v22;
                goto LABEL_12;
            }
        }
    }
LABEL_14:
    v23 = v3->adjoins;
    if ( v23 )
    {
        while ( 1 )
        {
            v21 = 0;
            v12 = v23->sector;
            v13 = v12->numSurfaces;
            v26 = v13;
            if ( v13 )
                break;
LABEL_25:
            v23 = v23->next;
            if ( !v23 )
                return 1;
        }
        surfaceIter_2 = v12->surfaces;
        while ( 1 )
        {
            v15 = surfaceIter_2->surfaceInfo.face.numVertices;
            v16 = 0;
            if ( surfaceIter_2->surfaceInfo.face.numVertices )
                break;
LABEL_24:
            ++surfaceIter_2;
            if ( ++v21 >= v13 )
                goto LABEL_25;
        }
        v17 = surfaceIter_2->surfaceInfo.face.vertexPosIdx;
        while ( 1 )
        {
            v18 = v16 + 1;
            if ( *v17 == idx2
              && surfaceIter_2->surfaceInfo.face.vertexPosIdx[(v16 + 1) % v15] == idx
              && surfaceIter_2->surfaceInfo.face.normal.y * pSurface->surfaceInfo.face.normal.y
               + surfaceIter_2->surfaceInfo.face.normal.x * pSurface->surfaceInfo.face.normal.x
               + surfaceIter_2->surfaceInfo.face.normal.z * pSurface->surfaceInfo.face.normal.z > 0.98000002 )
            {
                return 0;
            }
            ++v16;
            ++v17;
            if ( v18 >= v15 )
            {
                v13 = v26;
                goto LABEL_24;
            }
        }
    }
    return 1;
}