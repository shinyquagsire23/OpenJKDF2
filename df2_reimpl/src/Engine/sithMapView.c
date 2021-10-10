#include "sithMapView.h"

#include "Engine/sithSurface.h"
#include "World/sithSector.h"
#include "Engine/sithAdjoin.h"
#include "jk.h"

int sithMapView_Initialize(const void *a1)
{
    if (sithMapView_bInitted)
        return 0;

    _memcpy(&sithMapView_inst, a1, 0x40u);
    sithMapView_bInitted = 1;
    return 1;
}

int sithMapView_Shutdown()
{
    if (sithMapView_bInitted)
    {
        sithMapView_bShowMap = 0;
        sithMapView_bInitted = 0;
    }
    return 0;
}

void sithMapView_ToggleMapDrawn()
{
    sithMapView_bShowMap = !sithMapView_bShowMap;
}

void sithMapView_FuncIncrease()
{
    double v0; // st7

    if ( sithMapView_bShowMap )
    {
        v0 = (sithMapView_flMapSize - 10.0) * 0.0034482758 * 20.0;
        if ( v0 <= 1.0 )
            v0 = 1.0;
        sithMapView_flMapSize = sithMapView_flMapSize + v0;
        if ( sithMapView_flMapSize >= 300.0 )
            sithMapView_flMapSize = 300.0;
    }
}

void sithMapView_FuncDecrease()
{
    double v0; // st7
    double v1; // st7

    if ( sithMapView_bShowMap )
    {
        v0 = (sithMapView_flMapSize - 10.0) * 0.0034482758 * 20.0;
        if ( v0 <= 1.0 )
            v0 = 1.0;
        v1 = sithMapView_flMapSize - v0;
        sithMapView_flMapSize = v1;
        if ( v1 <= 10.0 )
            sithMapView_flMapSize = 10.0;
    }
}

// sithMapView_Render1
// sithMapView_Render2
// sithMapView_Render3

int sithMapView_Render4(sithSurface *a1, int a2, int a3)
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
