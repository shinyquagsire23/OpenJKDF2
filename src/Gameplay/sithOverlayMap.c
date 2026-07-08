#include "sithOverlayMap.h"

#include "World/sithSurface.h"
#include "World/sithSector.h"
#include "Engine/rdroid.h"
#include "Dss/sithMulti.h"
#include "Primitives/rdPrimit2.h"
#include "Main/sithMain.h"
#include "stdPlatform.h"
#include "jk.h"

int sithOverlayMap_Startup(const SithOverlayMapConfig *config)
{
    if (sithOverlayMap_bOpened)
        return 0;

    _memcpy(&sithOverlayMap_inst.config, config, sizeof(SithOverlayMapConfig));
    sithOverlayMap_bOpened = 1;
    return 1;
}

int sithOverlayMap_Close()
{
    if (sithOverlayMap_bOpened)
    {
        sithOverlayMap_bMapVisible = 0;
        sithOverlayMap_bOpened = 0;
    }
    return 0;
}

void sithOverlayMap_ToggleMap()
{
    sithOverlayMap_bMapVisible = !sithOverlayMap_bMapVisible;
}

void sithOverlayMap_ZoomIn()
{
    flex_d_t v0; // st7

    if ( sithOverlayMap_bMapVisible )
    {
        v0 = (sithOverlayMap_curScale - 10.0) * (1/290.0) * 20.0;
        if ( v0 <= 1.0 )
            v0 = 1.0;
        sithOverlayMap_curScale += v0;
        if ( sithOverlayMap_curScale >= 300.0 )
            sithOverlayMap_curScale = 300.0;
    }
}

void sithOverlayMap_ZoomOut()
{
    flex_d_t v0; // st7

    if ( sithOverlayMap_bMapVisible )
    {
        v0 = (sithOverlayMap_curScale - 10.0) * (1/290.0) * 20.0;
        if ( v0 <= 1.0 )
            v0 = 1.0;
        sithOverlayMap_curScale -= v0;
        if ( sithOverlayMap_curScale <= 10.0 )
            sithOverlayMap_curScale = 10.0;
    }
}

int sithOverlayMap_Draw(rdCanvas *canvas)
{
    int result; // eax
    SithThing *v2; // ecx
    flex_t v3; // edx
    int v5; // ecx
    SithSurfaceAdjoin *i; // esi
    int v8; // eax
    __int16 v9; // si
    rdVector3 a3; // [esp+4h] [ebp-1Ch] BYREF
    rdVector3 a1; // [esp+10h] [ebp-10h] BYREF
    int v12; // [esp+1Ch] [ebp-4h]
    flex_t canvasa; // [esp+28h] [ebp+8h]

    result = sithOverlayMap_bMapVisible;
    if (!sithOverlayMap_bMapVisible)
        return 0;

    sithAdvanceRenderTick();
    rdSetGeometryMode(2);
    rdSetLightingMode(1);
    sithOverlayMap_inst.world = sithWorld_g_pCurrentWorld;
    v2 = sithWorld_g_pCurrentWorld->pLocalPlayer;
    v3 = canvas->half_screen_width;
    sithOverlayMap_pCanvas = canvas;
    sithOverlayMap_pLocalPlayer = v2;
    v12 = (int)v3;
    sithOverlayMap_x1 = v12;
    v12 = (int)canvas->half_screen_height;
    a3.x = 0.0;
    a3.y = -sithCamera_g_pCurCamera->viewPYR.y;
    sithOverlayMap_y1 = v12;
    a3.z = 0.0;
    rdMatrix_BuildRotate34(&sithOverlayMap_mapOrient, &a3);

    sithOverlayMap_DrawSectors(sithOverlayMap_pLocalPlayer->sector);

    if ( sithNet_isMulti && (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) != 0 )
    {
        v8 = sithOverlayMap_inst.config.aTeamColors[sithOverlayMap_pLocalPlayer->actorParams.pPlayer->teamNum];
        v9 = v8;
    }
    else
    {
        v8 = sithOverlayMap_inst.config.playerColor & 0xFFFF;
        v9 = sithOverlayMap_inst.config.playerLineColor;
    }
    canvasa = sithOverlayMap_pLocalPlayer->moveSize * sithOverlayMap_curScale;
    rdPrimit2_DrawClippedCircle(sithOverlayMap_pCanvas, sithOverlayMap_x1, sithOverlayMap_y1, canvasa, 20.0, v8, -1);
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
        rdMatrix_TransformVector34Acc(&a1, &sithOverlayMap_mapOrient);
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

void sithOverlayMap_DrawSectors(SithSector *sector)
{
    signed int v2; // eax
    SithSurfaceAdjoin *i; // esi

    if ( sector->renderTick != sithRender_lastRenderTick
        && (sector->flags & SITH_SECTOR_SEEN || g_mapModeFlags & SITHMAPMODE_SHOWALLSECTORS))
    {
        sector->renderTick = sithRender_lastRenderTick;
        if ( (sector->flags & SITH_SECTOR_HIDEONMAP) != 0 )
            v2 = 1;
        else
            v2 = sithOverlayMap_DrawSector(sector);

        if ( v2 )
        {
            for ( i = sector->adjoins; i; i = i->next )
                sithOverlayMap_DrawSectors(i->sector);
        }
    }
}

int sithOverlayMap_DrawSector(SithSector *pSector)
{
    SithSector *v2; // esi
    int v3; // ecx
    SithSurface *v4; // ebx
    unsigned int v5; // edi
    unsigned int v6; // eax
    int *v7; // ecx
    int v8; // esi
    int v9; // edi
    int v10; // ebx
    unsigned int v11; // ecx
    flex_t *v12; // edi
    flex_d_t v14; // st7
    char v15; // c0
    int v16; // eax
    int v17; // ecx
    unsigned int v18; // ecx
    int v19; // cf
    flex_d_t v21; // st7
    flex_d_t v23; // st7
    int v24; // eax
    char v25; // cl
    SithThing *i; // ebx
    int v27; // esi
    int v28; // eax
    __int16 v29; // ax
    int v30; // esi
    int v31; // edi
    int v32; // eax
    signed int result; // eax
    flex_t a4; // [esp+0h] [ebp-64h]
    rdVector3 v35; // [esp+1Ch] [ebp-48h] BYREF
    rdVector3 a1a; // [esp+28h] [ebp-3Ch] BYREF
    unsigned int v37; // [esp+34h] [ebp-30h]
    int v44; // [esp+50h] [ebp-14h]
    int v45; // [esp+54h] [ebp-10h]
    int v46; // [esp+58h] [ebp-Ch]
    int v47; // [esp+5Ch] [ebp-8h]
    SithSurface *a6; // [esp+60h] [ebp-4h]
    flex_t v49; // [esp+6Ch] [ebp+8h]
    int circleColor; // [esp+6Ch] [ebp+8h]

    int a6_;

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
            if ( (v4->flags & SITH_SURFACE_FLOOR) != 0 )
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
            v10 = sithOverlayMap_CanDrawSurfaceEdge(v4, v8, v9);
            if ( v10 )
            {
                v44 = 1;
                a1a = sithOverlayMap_inst.world->aVertices[v8];
                v35 = sithOverlayMap_inst.world->aVertices[v9];
                rdVector_Sub3Acc(&a1a, &sithOverlayMap_pLocalPlayer->position);
                rdVector_Sub3Acc(&v35, &sithOverlayMap_pLocalPlayer->position);
                if ( sithOverlayMap_inst.config.bRotateOverlayMap )
                {
                    rdMatrix_TransformVector34Acc(&a1a, &sithOverlayMap_mapOrient);
                    rdMatrix_TransformVector34Acc(&v35, &sithOverlayMap_mapOrient);
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
                rdVector_Scale3Acc(&a1a, sithOverlayMap_curScale);
                rdVector_Scale3Acc(&v35, sithOverlayMap_curScale);
                if ( rdPrimit2_DrawClippedLine(
                         sithOverlayMap_pCanvas,
                         sithOverlayMap_x1 + (int)a1a.x,
                         sithOverlayMap_y1 - (int)a1a.y,
                         sithOverlayMap_x1 + (int)v35.x,
                         sithOverlayMap_y1 - (int)v35.y,
                         v17,
                         v16) )
                {
                    v47 = 1;
                }
            }
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
        rdVector3 tmp;
        rdVector_Scale3(&tmp, &v2->center, sithOverlayMap_curScale);
        v37 = (int)tmp.y;
        v49 = v2->radius * sithOverlayMap_curScale;
        v21 = (flex_d_t)((int)(sithOverlayMap_x1 + (int)tmp.x));
        if ( v21 >= (flex_d_t)sithOverlayMap_pCanvas->xStart - v49 && v21 <= (flex_d_t)sithOverlayMap_pCanvas->widthMinusOne + v49
          || ((v23 = (flex_d_t)((int)(sithOverlayMap_y1 - v37)), v23 < (flex_d_t)sithOverlayMap_pCanvas->yStart - v49) || v23 > (flex_d_t)sithOverlayMap_pCanvas->heightMinusOne + v49 ? (v24 = 0) : (v24 = 1),
              v24) )
        {
            v47 = 1;
        }
    }

    if ( (g_mapModeFlags & (SITHMAPMODE_SHOWALLTHINGS | SITHMAPMODE_SHOWACTORS | SITHMAPMODE_SHOWPLAYERS)) != 0 )
    {
        for ( i = v2->pFirstThingInSector; i; i = i->pNextThingInSector )
        {
            if ( i != sithWorld_g_pCurrentWorld->pCameraFocusThing && (i->flags & (SITH_TF_DISABLED|SITH_TF_10|SITH_TF_DESTROYED)) == 0 )
            {
                v27 = (g_mapModeFlags & SITHMAPMODE_SHOWALLTHINGS) != 0;
                v28 = i->type;
                if ( v28 == SITH_THING_PLAYER )
                {
                    if (g_mapModeFlags & (SITHMAPMODE_SHOWACTORS | SITHMAPMODE_SHOWPLAYERS))
                        v27 = 1;
                    if ( sithNet_isMulti && (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) != 0 )
                    {
                        circleColor = sithOverlayMap_inst.config.aTeamColors[i->actorParams.pPlayer->teamNum];
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
                    if (g_mapModeFlags & SITHMAPMODE_SHOWACTORS)
                        v27 = 1;
                    circleColor = sithOverlayMap_inst.config.actorColor & 0xFFFF;
                    a6_ = sithOverlayMap_inst.config.actorLineColor;
                }
                else
                {
                    if ( v28 == SITH_THING_ITEM )
                    {
                        if (g_mapModeFlags & SITHMAPMODE_SHOWITEMS)
                            v27 = 1;
                        v29 = sithOverlayMap_inst.config.itemColor;
                    }
                    else if ( v28 == SITH_THING_WEAPON )
                    {
                        if (g_mapModeFlags & SITHMAPMODE_SHOWWEAPONS)
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
                    rdVector_Sub3(&a1a, &i->position, &sithOverlayMap_pLocalPlayer->position);
                    if ( sithOverlayMap_inst.config.bRotateOverlayMap )
                        rdMatrix_TransformVector34Acc(&a1a, &sithOverlayMap_mapOrient);
                    rdVector_Scale3Acc(&a1a, sithOverlayMap_curScale);
                    v37 = (int)a1a.x;
                    int v40_ = (int)a1a.y;
                    v30 = sithOverlayMap_y1 - v40_;
                    a4 = i->moveSize * sithOverlayMap_curScale;
                    v31 = v37 + sithOverlayMap_x1;
                    rdPrimit2_DrawClippedCircle(sithOverlayMap_pCanvas, v37 + sithOverlayMap_x1, sithOverlayMap_y1 - v40_, a4, 20.0, circleColor, -1);
                    v32 = i->type;
                    if ( v32 == SITH_THING_ACTOR || v32 == SITH_THING_PLAYER )
                    {
                        rdVector_Scale3(&v35, &i->orient.lvec, i->moveSize + i->moveSize);
                        rdVector_Add3Acc(&v35, &i->position);
                        rdVector_Sub3(&a1a, &v35, &sithOverlayMap_pLocalPlayer->position);
                        if ( sithOverlayMap_inst.config.bRotateOverlayMap )
                            rdMatrix_TransformVector34Acc(&a1a, &sithOverlayMap_mapOrient);
                        rdVector_Scale3Acc(&a1a, sithOverlayMap_curScale);
                        rdPrimit2_DrawClippedLine(sithOverlayMap_pCanvas, v31, v30, sithOverlayMap_x1 + (int)a1a.x, sithOverlayMap_y1 - (int)a1a.y, a6_ & 0xFFFF, -1);
                    }
                }
            }
        }
    }
    result = v47;
    if ( !v44 )
        result = 1;
    return result;
}

int sithOverlayMap_CanDrawSurfaceEdge(SithSurface *a1, int a2, int a3)
{
    SithSector *pSector; // eax
    unsigned int sector_numSurfaces; // edx
    SithSurface *sector_paSurfaces; // ecx
    SithSurface* v6; // ebx
    unsigned int v7; // esi
    int v8; // eax
    int *v9; // edi
    unsigned int v10; // ecx
    SithSector *v12; // eax
    unsigned int v13; // ecx
    SithSurface* v14; // ebx
    unsigned int v15; // esi
    int v16; // eax
    int *v17; // edi
    unsigned int v18; // ecx
    int result; // eax
    int v20; // [esp+10h] [ebp-14h]
    int v21; // [esp+10h] [ebp-14h]
    SithSurface *sector_paSurfaces_; // [esp+14h] [ebp-10h]
    unsigned int sector_numSurfaces_; // [esp+18h] [ebp-Ch]
    SithSector *v24; // [esp+1Ch] [ebp-8h]
    unsigned int v25; // [esp+1Ch] [ebp-8h]
    SithSurfaceAdjoin *v26; // [esp+28h] [ebp+4h]

    pSector = a1->pSector;
    v24 = pSector;
    v20 = 0;
    sector_numSurfaces = pSector->numSurfaces;
    sector_paSurfaces = pSector->surfaces;
    sector_paSurfaces_ = sector_paSurfaces;
    sector_numSurfaces_ = sector_numSurfaces;
    if ( sector_numSurfaces )
    {
        v6 = &sector_paSurfaces[0];
        while ( 1 )
        {
            if ( sector_paSurfaces != a1 && !v6->pAdjoin )
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
                pSector = v24;
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
        result = (sector_paSurfaces_->flags & SITH_SURFACE_FLOOR) == 0;
    }
    else
    {
LABEL_13:
        v26 = pSector->adjoins;
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
                if (v14->flags & SITH_SURFACE_FLOOR)
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
