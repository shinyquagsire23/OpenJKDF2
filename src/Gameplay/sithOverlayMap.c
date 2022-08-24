#include "sithOverlayMap.h"

#include "Engine/sithSurface.h"
#include "World/sithSector.h"
#include "Engine/sithAdjoin.h"
#include "Engine/rdroid.h"
#include "Primitives/rdPrimit2.h"
#include "Engine/sith.h"
#include "jk.h"

int sithOverlayMap_Initialize(const sithMapViewConfig *config)
{
    if (sithOverlayMap_bInitted)
        return 0;

    _memcpy(&sithOverlayMap_inst.config, config, sizeof(sithMapViewConfig));
    sithOverlayMap_bInitted = 1;
    return 1;
}

int sithOverlayMap_Shutdown()
{
    if (sithOverlayMap_bInitted)
    {
        sithOverlayMap_bShowMap = 0;
        sithOverlayMap_bInitted = 0;
    }
    return 0;
}

void sithOverlayMap_ToggleMapDrawn()
{
    sithOverlayMap_bShowMap = !sithOverlayMap_bShowMap;
}

void sithOverlayMap_FuncIncrease()
{
    double v0; // st7

    if ( sithOverlayMap_bShowMap )
    {
        v0 = (sithOverlayMap_flMapSize - 10.0) * 0.0034482758 * 20.0;
        if ( v0 <= 1.0 )
            v0 = 1.0;
        sithOverlayMap_flMapSize = sithOverlayMap_flMapSize + v0;
        if ( sithOverlayMap_flMapSize >= 300.0 )
            sithOverlayMap_flMapSize = 300.0;
    }
}

void sithOverlayMap_FuncDecrease()
{
    double v0; // st7
    double v1; // st7

    if ( sithOverlayMap_bShowMap )
    {
        v0 = (sithOverlayMap_flMapSize - 10.0) * 0.0034482758 * 20.0;
        if ( v0 <= 1.0 )
            v0 = 1.0;
        v1 = sithOverlayMap_flMapSize - v0;
        sithOverlayMap_flMapSize = v1;
        if ( v1 <= 10.0 )
            sithOverlayMap_flMapSize = 10.0;
    }
}

int sithOverlayMap_Render1(rdCanvas *canvas)
{
    int result; // eax
    sithThing *v2; // ecx
    float v3; // edx
    sithSector *v4; // esi
    int v5; // ecx
    sithAdjoin *i; // esi
    int v8; // eax
    __int16 v9; // si
    rdVector3 a3; // [esp+4h] [ebp-1Ch] BYREF
    rdVector3 a1; // [esp+10h] [ebp-10h] BYREF
    int v12; // [esp+1Ch] [ebp-4h]
    float canvasa; // [esp+28h] [ebp+8h]

    result = sithOverlayMap_bShowMap;
    if (!sithOverlayMap_bShowMap)
        return 0;

    sith_sub_4C4D80();
    rdSetGeometryMode(2);
    rdSetLightingMode(1);
    sithOverlayMap_inst.world = sithWorld_pCurrentWorld;
    v2 = sithWorld_pCurrentWorld->playerThing;
    v3 = canvas->screen_height_half;
    sithOverlayMap_pCanvas = canvas;
    sithOverlayMap_pPlayer = v2;
    v12 = (int)v3;
    sithOverlayMap_x1 = v12;
    v12 = (int)canvas->screen_width_half;
    a3.x = 0.0;
    a3.y = -sithCamera_currentCamera->vec3_2.y;
    sithOverlayMap_y1 = v12;
    a3.z = 0.0;
    rdMatrix_BuildRotate34(&sithOverlayMap_matrix, &a3);
    v4 = sithOverlayMap_pPlayer->sector;
    if ( v4->field_8C != sithRender_lastRenderTick )
    {
        v5 = v4->flags;
        if ( (v5 & 0x4000) != 0 || (g_mapModeFlags & 2) != 0 )
        {
            v4->field_8C = sithRender_lastRenderTick;
            if ( (v5 & 0x10) != 0 ? 1 : sithOverlayMap_Render3(v4) )
            {
                for ( i = v4->adjoins; i; i = i->next )
                    sithOverlayMap_Render2(i->sector);
            }
        }
    }
    if ( sithNet_isMulti && (sithNet_MultiModeFlags & 1) != 0 )
    {
        v8 = sithOverlayMap_inst.config.aTeamColors[sithOverlayMap_pPlayer->actorParams.playerinfo->teamNum];
        v9 = v8;
    }
    else
    {
        v8 = sithOverlayMap_inst.config.playerColor & 0xFFFF;
        v9 = sithOverlayMap_inst.config.playerLineColor;
    }
    canvasa = sithOverlayMap_pPlayer->moveSize * sithOverlayMap_flMapSize;
    rdPrimit2_DrawCircle(sithOverlayMap_pCanvas, sithOverlayMap_x1, sithOverlayMap_y1, canvasa, 20.0, v8, -1);
    if ( sithOverlayMap_inst.config.bRotateOverlayMap )
    {
        result = rdPrimit2_DrawClippedLine(
                     sithOverlayMap_pCanvas,
                     sithOverlayMap_x1,
                     sithOverlayMap_y1,
                     sithOverlayMap_x1,
                     sithOverlayMap_y1 - (__int64)(canvasa + canvasa),
                     v9,
                     -1);
    }
    else
    {
        a1.x = 0.0;
        a1.y = -(canvasa + canvasa);
        a1.z = 0.0;
        rdMatrix_TransformVector34Acc(&a1, &sithOverlayMap_matrix);
        result = rdPrimit2_DrawClippedLine(
                     sithOverlayMap_pCanvas,
                     sithOverlayMap_x1,
                     sithOverlayMap_y1,
                     sithOverlayMap_x1 + (__int64)(a1.x - -0.5),
                     sithOverlayMap_y1 + (__int64)(a1.y - -0.5),
                     v9,
                     -1);
    }
    
    return result;
}

void sithOverlayMap_Render2(sithSector *sector)
{
    int v1; // eax
    signed int v2; // eax
    sithAdjoin *i; // esi

    if ( sector->field_8C != sithRender_lastRenderTick )
    {
        v1 = sector->flags;
        if ( (v1 & 0x4000) != 0 || (g_mapModeFlags & 2) != 0 )
        {
            sector->field_8C = sithRender_lastRenderTick;
            if ( (v1 & 0x10) != 0 )
                v2 = 1;
            else
                v2 = sithOverlayMap_Render3(sector);
            if ( v2 )
            {
                for ( i = sector->adjoins; i; i = i->next )
                    sithOverlayMap_Render2(i->sector);
            }
        }
    }
}

int sithOverlayMap_Render3(sithSector *pSector)
{
    sithThing *v1; // edx
    sithSector *v2; // esi
    int v3; // ecx
    sithSurface *v4; // ebx
    unsigned int v5; // edi
    unsigned int v6; // eax
    int *v7; // ecx
    int v8; // esi
    int v9; // edi
    int v10; // ebx
    unsigned int v11; // ecx
    float *v12; // edi
    double v14; // st7
    char v15; // c0
    int v16; // eax
    int v17; // ecx
    unsigned int v18; // ecx
    int v19; // cf
    double v20; // st7
    double v21; // st7
    double v23; // st7
    int v24; // eax
    char v25; // cl
    sithThing *i; // ebx
    int v27; // esi
    int v28; // eax
    __int16 v29; // ax
    int v30; // esi
    int v31; // edi
    int v32; // eax
    signed int result; // eax
    float a4; // [esp+0h] [ebp-64h]
    rdVector3 v35; // [esp+1Ch] [ebp-48h] BYREF
    rdVector3 a1a; // [esp+28h] [ebp-3Ch] BYREF
    unsigned int v37; // [esp+34h] [ebp-30h]
    float v38; // [esp+38h] [ebp-2Ch]
    float v39; // [esp+3Ch] [ebp-28h]
    float v40; // [esp+40h] [ebp-24h]
    int v41; // [esp+44h] [ebp-20h]
    int v42; // [esp+48h] [ebp-1Ch]
    int v43; // [esp+4Ch] [ebp-18h]
    int v44; // [esp+50h] [ebp-14h]
    int v45; // [esp+54h] [ebp-10h]
    int v46; // [esp+58h] [ebp-Ch]
    int v47; // [esp+5Ch] [ebp-8h]
    sithSurface *a6; // [esp+60h] [ebp-4h]
    float v49; // [esp+6Ch] [ebp+8h]
    int circleColor; // [esp+6Ch] [ebp+8h]

    int a6_;

    v1 = sithOverlayMap_pPlayer;
    v2 = pSector;
    v3 = pSector->numSurfaces;
    v4 = pSector->surfaces;
    v47 = 0;
    v44 = 0;
    a6 = v4;
    v45 = 0;
    if ( v3 )
    {
        while ( 1 )
        {
            if ( (v4->surfaceFlags & 1) != 0 )
            {
                v5 = v4->surfaceInfo.face.numVertices;
                v6 = 0;
                if ( v5 )
                    break;
            }
LABEL_29:
            v18 = v2->numSurfaces;
            v4->field_4 = sithRender_lastRenderTick;
            ++v4;
            v19 = v45 + 1 < v18;
            a6 = v4;
            ++v45;
            if ( !v19 )
                goto LABEL_30;
        }
        while ( 1 )
        {
            v7 = v4->surfaceInfo.face.vertexPosIdx;
            v37 = v6 + 1;
            v8 = v7[v6];
            v9 = v7[(v6 + 1) % v5];
            v10 = sithOverlayMap_Render4(v4, v8, v9);
            if ( v10 )
            {
                v44 = 1;
                a1a = sithOverlayMap_inst.world->vertices[v8];
                v35 = sithOverlayMap_inst.world->vertices[v9];
                v1 = sithOverlayMap_pPlayer;
                a1a.x = a1a.x - sithOverlayMap_pPlayer->position.x;
                a1a.y = a1a.y - sithOverlayMap_pPlayer->position.y;
                a1a.z = a1a.z - sithOverlayMap_pPlayer->position.z;
                v35.x = v35.x - sithOverlayMap_pPlayer->position.x;
                v35.y = v35.y - sithOverlayMap_pPlayer->position.y;
                v35.z = v35.z - sithOverlayMap_pPlayer->position.z;
                if ( sithOverlayMap_inst.config.bRotateOverlayMap )
                {
                    rdMatrix_TransformVector34Acc(&a1a, &sithOverlayMap_matrix);
                    rdMatrix_TransformVector34Acc(&v35, &sithOverlayMap_matrix);
                    v1 = sithOverlayMap_pPlayer;
                }
                v11 = 0;
                v46 = 0;
                if ( sithOverlayMap_inst.config.numArr )
                {
                    v12 = sithOverlayMap_inst.config.unkArr;
                    while ( 1 )
                    {
                        v14 = a1a.z;
                        if ( v14 < 0.0 )
                            v14 = -v14;
                        if ( v14 < *v12 )
                            break;
                        ++v11;
                        ++v12;
                        if ( v11 >= sithOverlayMap_inst.config.numArr )
                            goto LABEL_17;
                    }
                    v46 = 1;
                }
LABEL_17:
                if ( v46 )
                {
                    if ( v10 == 2 )
                    {
                        v11 += 3;
                        if ( v11 >= sithOverlayMap_inst.config.numArr - 1 )
                            v11 = sithOverlayMap_inst.config.numArr - 1;
                    }
                    v16 = -1;
                    v17 = sithOverlayMap_inst.config.paColors[v11];
                }
                else
                {
                    if ( v10 == 2 )
                        goto LABEL_27;
                    v17 = sithOverlayMap_inst.config.paColors[sithOverlayMap_inst.config.numArr - 1];
                    v16 = 0xCCCCCCCC;
                }
                a1a.x = a1a.x * sithOverlayMap_flMapSize;
                a1a.y = a1a.y * sithOverlayMap_flMapSize;
                a1a.z = a1a.z * sithOverlayMap_flMapSize;
                v35.x = v35.x * sithOverlayMap_flMapSize;
                v35.y = v35.y * sithOverlayMap_flMapSize;
                v35.z = v35.z * sithOverlayMap_flMapSize;
                int v40_ = (int)a1a.x;
                v41 = (int)a1a.y;
                v42 = (int)v35.x;
                v43 = (int)v35.y;
                if ( rdPrimit2_DrawClippedLine(
                         sithOverlayMap_pCanvas,
                         sithOverlayMap_x1 + v40_,
                         sithOverlayMap_y1 - v41,
                         sithOverlayMap_x1 + v42,
                         sithOverlayMap_y1 - v43,
                         v17,
                         v16) )
                {
                    v47 = 1;
                }
            }
            v1 = sithOverlayMap_pPlayer;
LABEL_27:
            v6 = v37;
            v5 = a6->surfaceInfo.face.numVertices;
            if ( v37 >= v5 )
            {
                v2 = pSector;
                v4 = a6;
                goto LABEL_29;
            }
            v4 = a6;
        }
    }
LABEL_30:
    if ( !v47 )
    {
        v38 = v2->center.x;
        v39 = v2->center.y;
        v38 = v38 * sithOverlayMap_flMapSize;
        v40 = v2->center.z;
        v39 = v39 * sithOverlayMap_flMapSize;
        v40 = v40 * sithOverlayMap_flMapSize;
        v37 = (int)v39;
        v20 = v2->radius * sithOverlayMap_flMapSize;
        int v39_ = sithOverlayMap_x1 + (int)v38;
        v49 = v20;
        v21 = (double)v39_;
        int v40_ = sithOverlayMap_y1 - v37;
        if ( v21 >= (double)sithOverlayMap_pCanvas->xStart - v49 && v21 <= (double)sithOverlayMap_pCanvas->widthMinusOne + v49
          || ((v23 = (double)v40_, v23 < (double)sithOverlayMap_pCanvas->yStart - v49) || v23 > (double)sithOverlayMap_pCanvas->heightMinusOne + v49 ? (v24 = 0) : (v24 = 1),
              v24) )
        {
            v47 = 1;
        }
        v1 = sithOverlayMap_pPlayer;
    }
    v25 = g_mapModeFlags;
    if ( (g_mapModeFlags & 0x4C) != 0 )
    {
        for ( i = v2->thingsList; i; i = i->nextThing )
        {
            if ( i != sithWorld_pCurrentWorld->cameraFocus && (i->thingflags & (SITH_TF_DISABLED|SITH_TF_10|SITH_TF_WILLBEREMOVED)) == 0 )
            {
                v27 = (v25 & 0x40) != 0;
                v28 = i->type;
                if ( v28 == SITH_THING_PLAYER )
                {
                    if ( (v25 & 0xC) != 0 )
                        v27 = 1;
                    if ( sithNet_isMulti && (sithNet_MultiModeFlags & 1) != 0 )
                    {
                        circleColor = sithOverlayMap_inst.config.aTeamColors[i->actorParams.playerinfo->teamNum];
                        a6_ = circleColor;
                    }
                    else
                    {
                        circleColor = sithOverlayMap_inst.config.playerColor & 0xFFFF;
                        a6_ = sithOverlayMap_inst.config.playerLineColor;
                    }
                }
                else if ( v28 == SITH_THING_ACTOR )
                {
                    if ( (v25 & 8) != 0 )
                        v27 = 1;
                    circleColor = sithOverlayMap_inst.config.actorColor & 0xFFFF;
                    a6_ = sithOverlayMap_inst.config.actorLineColor;
                }
                else
                {
                    if ( v28 == SITH_THING_ITEM )
                    {
                        if ( (v25 & 0x10) != 0 )
                            v27 = 1;
                        v29 = sithOverlayMap_inst.config.itemColor;
                    }
                    else if ( v28 == SITH_THING_WEAPON )
                    {
                        if ( (v25 & 0x20) != 0 )
                            v27 = 1;
                        v29 = sithOverlayMap_inst.config.weaponColor;
                    }
                    else
                    {
                        v29 = sithOverlayMap_inst.config.otherColor;
                    }
                    circleColor = v29 & 0xFFFF;
                }
                if ( v27 )
                {
                    a1a.x = i->position.x - v1->position.x;
                    a1a.y = i->position.y - v1->position.y;
                    a1a.z = i->position.z - v1->position.z;
                    if ( sithOverlayMap_inst.config.bRotateOverlayMap )
                        rdMatrix_TransformVector34Acc(&a1a, &sithOverlayMap_matrix);
                    a1a.x = a1a.x * sithOverlayMap_flMapSize;
                    a1a.y = a1a.y * sithOverlayMap_flMapSize;
                    a1a.z = a1a.z * sithOverlayMap_flMapSize;
                    v37 = (int)a1a.x;
                    int v40_ = (int)a1a.y;
                    v30 = sithOverlayMap_y1 - v40_;
                    a4 = i->moveSize * sithOverlayMap_flMapSize;
                    v31 = v37 + sithOverlayMap_x1;
                    rdPrimit2_DrawCircle(sithOverlayMap_pCanvas, v37 + sithOverlayMap_x1, sithOverlayMap_y1 - v40_, a4, 20.0, circleColor, -1);
                    v32 = i->type;
                    if ( v32 == SITH_THING_ACTOR || v32 == SITH_THING_PLAYER )
                    {
                        v35.x = i->lookOrientation.lvec.x * (i->moveSize + i->moveSize);
                        v35.y = i->lookOrientation.lvec.y * (i->moveSize + i->moveSize);
                        v35.z = i->lookOrientation.lvec.z * (i->moveSize + i->moveSize);
                        v35.x = v35.x + i->position.x;
                        v35.y = v35.y + i->position.y;
                        v35.z = v35.z + i->position.z;
                        a1a.x = v35.x - sithOverlayMap_pPlayer->position.x;
                        a1a.y = v35.y - sithOverlayMap_pPlayer->position.y;
                        a1a.z = v35.z - sithOverlayMap_pPlayer->position.z;
                        if ( sithOverlayMap_inst.config.bRotateOverlayMap )
                            rdMatrix_TransformVector34Acc(&a1a, &sithOverlayMap_matrix);
                        a1a.x = a1a.x * sithOverlayMap_flMapSize;
                        a1a.y = a1a.y * sithOverlayMap_flMapSize;
                        a1a.z = a1a.z * sithOverlayMap_flMapSize;
                        v42 = (int)a1a.x;
                        v41 = (int)a1a.y;
                        rdPrimit2_DrawClippedLine(sithOverlayMap_pCanvas, v31, v30, sithOverlayMap_x1 + v42, sithOverlayMap_y1 - v41, a6_ & 0xFFFF, -1);
                    }
                    v1 = sithOverlayMap_pPlayer;
                    v25 = g_mapModeFlags;
                }
            }
        }
    }
    result = v47;
    if ( !v44 )
        result = 1;
    return result;
}

int sithOverlayMap_Render4(sithSurface *a1, int a2, int a3)
{
    sithSector *parent_sector; // eax
    unsigned int sector_numSurfaces; // edx
    sithSurface *sector_paSurfaces; // ecx
    sithSurface* v6; // ebx
    unsigned int v7; // esi
    int v8; // eax
    int *v9; // edi
    unsigned int v10; // ecx
    sithSector *v12; // eax
    unsigned int v13; // ecx
    sithSurface* v14; // ebx
    unsigned int v15; // esi
    int v16; // eax
    int *v17; // edi
    unsigned int v18; // ecx
    int result; // eax
    int v20; // [esp+10h] [ebp-14h]
    int v21; // [esp+10h] [ebp-14h]
    sithSurface *sector_paSurfaces_; // [esp+14h] [ebp-10h]
    unsigned int sector_numSurfaces_; // [esp+18h] [ebp-Ch]
    sithSector *v24; // [esp+1Ch] [ebp-8h]
    unsigned int v25; // [esp+1Ch] [ebp-8h]
    sithAdjoin *v26; // [esp+28h] [ebp+4h]

    parent_sector = a1->parent_sector;
    v24 = parent_sector;
    v20 = 0;
    sector_numSurfaces = parent_sector->numSurfaces;
    sector_paSurfaces = parent_sector->surfaces;
    sector_paSurfaces_ = sector_paSurfaces;
    sector_numSurfaces_ = sector_numSurfaces;
    if ( sector_numSurfaces )
    {
        v6 = &sector_paSurfaces[0];
        while ( 1 )
        {
            if ( sector_paSurfaces != a1 && !v6->adjoin )
            {
                v7 = v6->surfaceInfo.face.numVertices;
                v8 = 0;
                if ( v6->surfaceInfo.face.numVertices )
                    break;
            }
LABEL_11:
            ++sector_paSurfaces;
            ++v6;
            int v11 = v20 + 1 < sector_numSurfaces;
            sector_paSurfaces_ = sector_paSurfaces;
            ++v20;
            if ( !v11 )
            {
                parent_sector = v24;
                goto LABEL_13;
            }
        }
        v9 = v6->surfaceInfo.face.vertexPosIdx;
        while ( 1 )
        {
            v10 = v8 + 1;
            if ( *v9 == a3 && v6->surfaceInfo.face.vertexPosIdx[(v8 + 1) % v7] == a2 )
                break;
            ++v8;
            ++v9;
            if ( v10 >= v7 )
            {
                sector_numSurfaces = sector_numSurfaces_;
                sector_paSurfaces = sector_paSurfaces_;
                goto LABEL_11;
            }
        }
        result = (sector_paSurfaces_->surfaceFlags & SURFACEFLAGS_1) == 0;
    }
    else
    {
LABEL_13:
        v26 = parent_sector->adjoins;
        if ( v26 )
        {
            while ( 1 )
            {
                v21 = 0;
                v12 = v26->sector;
                v13 = v12->numSurfaces;
                v25 = v13;
                if ( v13 )
                    break;
LABEL_24:
                v26 = v26->next;
                if ( !v26 )
                    return 2;
            }
            v14 = &v12->surfaces[0];
            while ( 1 )
            {
                if ( (v14->surfaceFlags & SURFACEFLAGS_1) != 0 )
                {
                    v15 = v14->surfaceInfo.face.numVertices;
                    v16 = 0;
                    if ( v14->surfaceInfo.face.numVertices )
                        break;
                }
LABEL_23:
                ++v14;
                if ( ++v21 >= v13 )
                    goto LABEL_24;
            }
            v17 = v14->surfaceInfo.face.vertexPosIdx;
            while ( 1 )
            {
                v18 = v16 + 1;
                if ( *v17 == a3 && v14->surfaceInfo.face.vertexPosIdx[(v16 + 1) % v15] == a2 )
                    break;
                ++v16;
                ++v17;
                if ( v18 >= v15 )
                {
                    v13 = v25;
                    goto LABEL_23;
                }
            }
            result = 0;
        }
        else
        {
            result = 2;
        }
    }
    return result;
}
