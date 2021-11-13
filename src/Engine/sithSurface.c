#include "sithSurface.h"

#include <math.h>

#include "General/stdHashTable.h"
#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "World/sithSector.h"
#include "Engine/sithIntersect.h"
#include "World/sithThing.h"
#include "Engine/sithAdjoin.h"
#include "Engine/sithMaterial.h"
#include "Engine/sithTime.h"
#include "Engine/sithNet.h"
#include "jk.h"

int sithSurface_Startup()
{
    _memset(sithSurface_aSurfaces, 0, sizeof(rdSurface) * 256); // sizeof(sithSurface_aSurfaces)

    for (int i = 0; i < 256; i++)
    {
        sithSurface_aAvail[i] = 255 - i;
    }

    sithSurface_numAvail = 256;
    sithSurface_numSurfaces = 0;
    return 1;
}

void sithSurface_Shutdown()
{
    ;
}

int sithSurface_Open()
{
    sithSurface_bOpened = 1;
    return 1;
}

int sithSurface_Startup2()
{
    sithSurface_Startup();
    return sithSurface_Open();
}

int sithSurface_Startup3()
{
    return sithSurface_Startup();
}

int sithSurface_Load(sithWorld *world)
{
    unsigned int numAdjoins; // ebp
    unsigned int allocSize; // esi
    sithAdjoin *adjoins; // eax
    unsigned int mirror; // eax
    sithSurface *surfaces; // esi
    int v20; // eax
    int adjoinIdx; // eax
    sithAdjoin *surfaceAdjoin; // ecx
    int wallCel; // edx
    double v32; // st7
    char *v33; // eax
    unsigned int v34; // eax
    unsigned int v35; // ebp
    unsigned int v40; // ebx
    unsigned int v43; // edi
    unsigned int v50; // edi
    int v52; // edx
    rdTexinfo *v53; // eax
    char *distStr; // [esp-4h] [ebp-30h]
    unsigned int numSurfaces; // [esp+18h] [ebp-14h] BYREF
    rdTexinfo *v66; // [esp+24h] [ebp-8h] BYREF
    int v61;

    if ( !stdConffile_ReadLine() || _sscanf(stdConffile_aLine, " world adjoins %d", &numAdjoins) != 1 )
        return 0;
    if ( numAdjoins )
    {
        allocSize = sizeof(sithAdjoin) * numAdjoins;
        adjoins = (sithAdjoin *)pSithHS->alloc(sizeof(sithAdjoin) * numAdjoins);
        world->adjoins = adjoins;
        if ( !adjoins )
            return 0;
        _memset(adjoins, 0, allocSize);
        world->numAdjoins = numAdjoins;
        world->numAdjoinsLoaded = 0;
    }
    else
    {
        world->adjoins = 0;
    }

    world->numAdjoinsLoaded = numAdjoins;
    for (int i = 0; i < world->numAdjoinsLoaded; i++)
    {
        if ( !stdConffile_ReadArgs() )
            return 0;
        if ( _sscanf(stdConffile_entry.args[1].value, "%x", &world->adjoins[i].flags) != 1 )
            return 0;

        mirror = _atoi(stdConffile_entry.args[2].value);
        if ( mirror >= world->numAdjoinsLoaded )
            return 0;
        distStr = stdConffile_entry.args[3].value;
        world->adjoins[i].mirror = &world->adjoins[mirror];
        world->adjoins[i].dist = _atof(distStr);
    }
    if (!stdConffile_ReadLine())
    {
        return 0;
    }
    
    if ( _sscanf(stdConffile_aLine, " world surfaces %d", &numSurfaces) != 1 )
    {
        return 0;
    }

    world->surfaces = (sithSurface *)pSithHS->alloc(sizeof(sithSurface) * numSurfaces);
    if (!world->surfaces)
    {
        return 0;
    }

    _memset(world->surfaces, 0, sizeof(sithSurface) * numSurfaces);
    world->numSurfaces = numSurfaces;
    for (int v14 = 0; v14 < numSurfaces; v14++)
    {
        rdFace_NewEntry(&world->surfaces[v14].surfaceInfo.face);
        world->surfaces[v14].field_0 = v14;
    }
    surfaces = world->surfaces;

    for (int v67 = 0; v67 < numSurfaces; v67++)
    {
        sithSurface* surfaceIter = &surfaces[v67];
        sithSurfaceInfo* surfaceInfo = &surfaceIter->surfaceInfo;
        rdFace* face = &surfaceInfo->face;

        if ( !stdConffile_ReadArgs() )
            return 0;
        v20 = _atoi(stdConffile_entry.args[1].value);
        if ( v20 >= 0 )
        {
            if ( v20 >= sithMaterial_numMaterials )
                return 0;
            face->material = sithMaterial_aMaterials[v20];
        }
        else
        {
            face->material = 0;
        }

        if ( _sscanf(stdConffile_entry.args[2].value, "%x", &surfaceIter->surfaceFlags) != 1 )
            return 0;

        if ( _sscanf(stdConffile_entry.args[3].value, "%x", &face->type) != 1 )
            return 0;
        if ( (sithSurface_byte_8EE668 & 1) == 0 )
        {
            face->type &= ~4;
        }
        face->geometryMode = _atoi(stdConffile_entry.args[4].value);

        if ( face->material )
        {
            if ( (face->material->tex_type & 2) == 0 )
            {
                face->geometryMode = 3;
                surfaceIter->surfaceFlags &= ~0x600;
            }
        }
        else
        {
            face->geometryMode = 0;
        }
        face->lightingMode = _atoi(stdConffile_entry.args[5].value);
        if ( (surfaceIter->surfaceFlags & 0x600) != 0 )
            face->lightingMode = 0;
        face->textureMode = _atoi(stdConffile_entry.args[6].value);
        adjoinIdx = _atoi(stdConffile_entry.args[7].value);
        if ( adjoinIdx == -1 )
        {
            surfaceIter->adjoin = 0;
        }
        else
        {
            surfaceAdjoin = &world->adjoins[adjoinIdx];
            surfaceIter->adjoin = surfaceAdjoin;
            surfaceAdjoin->surface = surfaceIter;
            if ( face->material )
            {
                wallCel = face->wallCel;
                if ( wallCel == -1 )
                    wallCel = face->material->celIdx;
                v66 = face->material->texinfos[wallCel];
            }
            if ( (world->adjoins[adjoinIdx].flags & 1) == 0
              || (face->material 
                  && face->geometryMode 
                  && (face->type & 2) == 0 
                  && ((v66->header.texture_type & 8) == 0 || (v66->texture_ptr->alpha_en & 1) == 0)))
            {
                surfaceAdjoin->flags |= 0x80;
            }
        }
        v32 = _atof(stdConffile_entry.args[8].value);
        v33 = stdConffile_entry.args[9].value;
        face->extraLight = v32;
        v34 = _atoi(v33);
        v35 = v34;
        if ( v34 < 3 )
            return 0;
        if ( v34 > stdConffile_entry.numArgs - 10 )
            return 0;
        if ( v34 > 0x18 )
            return 0;

        face->vertexPosIdx = pSithHS->alloc(sizeof(int) * v34);
        if ( !face->vertexPosIdx )
            return 0;

        surfaceInfo->intensities = pSithHS->alloc(sizeof(float) * v35);
        if ( !surfaceInfo->intensities )
            return 0;

        if (face->material && (face->material->tex_type & 2))
        {
            face->vertexUVIdx = pSithHS->alloc(sizeof(int) * v35);
            if ( !face->vertexUVIdx )
                return 0;

            v61 = 10;
            for (v40 = 0; v40 < v35; v40++)
            {
                face->vertexPosIdx[v40] = _atoi(stdConffile_entry.args[v61].value);
                face->vertexUVIdx[v40] = _atoi(stdConffile_entry.args[v61+1].value);
                v61 += 2;
            }
        }
        else
        {
            face->vertexUVIdx = 0;
            v61 = 10;
            for (v43 = 0; v43 < v35; v43++)
            {
                face->vertexPosIdx[v43] = _atoi(stdConffile_entry.args[v61].value);
                v61 += 2;
            }
        }

        for (int v45 = 0; v45 < v35; v45++)
        {
            surfaceInfo->intensities[v45] = _atof(stdConffile_entry.args[v61+v45].value);
        }
        face->numVertices = v35;
        face->num = v67;
    }

    for (int v50 = 0; v50 < numSurfaces; v50++)
    {
        if (!stdConffile_ReadLine())
            return 0;
        
        int idx_unused;
        float norm_x, norm_y, norm_z;
        if (_sscanf(stdConffile_aLine, "%d: %f %f %f", &idx_unused, &norm_x, &norm_y, &norm_z) != 4)
            return 0;
        
        //jk_printf("%u: %x\n", v50, &world->surfaces[0].surfaceFlags);
        
        world->surfaces[v50].surfaceInfo.face.normal.x = norm_x;
        world->surfaces[v50].surfaceInfo.face.normal.y = norm_y;
        world->surfaces[v50].surfaceInfo.face.normal.z = norm_z;
    }
    
    world->numSurfaces = numSurfaces;
    pSithHS->free(sithMaterial_aMaterials);
    sithMaterial_numMaterials = 0;
    return 1;
}

int sithSurface_Verify(sithWorld *world)
{
    for (int i = 0; i < world->numSurfaces; i++)
    {
        if (world->surfaces[i].parent_sector == (sithSector*)8 || !world->surfaces[i].parent_sector)
            return 0;
    }
    
    return 1;
}

int sithSurface_GetIdxFromPtr(sithSurface *surface)
{
    if ( surface )
        return (surface->parent_sector != 0);

    return 0;
}

void sithSurface_UnsetAdjoins(sithAdjoin *adjoin)
{
    if ( (adjoin->flags & 1) != 0 )
    {
        adjoin->flags &= ~0x1;
        adjoin->flags |= 0x20;
    }
}

void sithSurface_SetAdjoins(sithAdjoin *adjoin)
{
    if ( (adjoin->flags & 0x20) != 0 )
    {
        adjoin->flags &= ~0x20;
        adjoin->flags |= 0x1;
    }
}

void sithSurface_SetSectorLight(sithSector *sector, float extraLight, float a3, int a4)
{
    double v5; // st7
    rdSurface *v6; // eax
    int v7; // edx
    rdSurface *v8; // esi
    double v9; // st7
    float a1a; // [esp+4h] [ebp+4h]

    v5 = extraLight - sector->extraLight;
    if ( v5 != 0.0 )
    {
        //v6 = (rdSurface *)sithSurface_numAvail;
        // Added: fix undef behavior?
        v6 = NULL;
        if ( sithSurface_numAvail )
        {
            v7 = sithSurface_aAvail[sithSurface_numAvail--];
            if ( v7 > sithSurface_numSurfaces )
                sithSurface_numSurfaces = v7;
            v8 = &sithSurface_aSurfaces[v7];
            _memset(v8, 0, sizeof(rdSurface));
            v6 = v8;
            v8->index = ((playerThingIdx + 1) << 16) | (uint16_t)v7;
        }
        if ( v6 )
        {
            v6->sector = sector;
            v6->flags = a4 & 1 | 0x2400000;
            a1a = v5;
            v6->field_44 = a1a / a3;
            v9 = sector->extraLight;
            v6->field_3C = sector->extraLight;
            v6->field_48 = v9;
            v6->field_40 = extraLight;
        }
    }
}

rdSurface* sithSurface_SurfaceAnim(sithSurface *parent, float a2, uint16_t flags)
{
    rdMaterial *material; // ebp
    rdSurface *result; // eax
    int v5; // ebx
    rdSurface *rd_surf; // esi
    int v7; // edx
    int64_t v8; // rax
    int v9; // edx
    int v10; // eax
    int v11; // eax
    int v13; // ecx

    material = parent->surfaceInfo.face.material;
    if ( !material )
        return 0;
    v5 = sithSurface_numAvail;
    if ( sithSurface_numAvail )
    {
        v7 = sithSurface_aAvail[sithSurface_numAvail];
        v5 = --sithSurface_numAvail;
        if ( v7 > sithSurface_numSurfaces )
            sithSurface_numSurfaces = v7;
        rd_surf = &sithSurface_aSurfaces[v7];
        _memset(rd_surf, 0, sizeof(rdSurface));
        rd_surf->index = ((playerThingIdx + 1) << 16) | (uint16_t)v7;
    }
    else
    {
        rd_surf = 0;
    }
    if ( !rd_surf )
        return 0;
    if ( (flags & 4) != 0 )
        rd_surf->wallCel = 2;
    else
        rd_surf->wallCel = (flags & 2) != 0;
    rd_surf->flags = flags | 0x220000;
    rd_surf->sithSurfaceParent = parent;
    rd_surf->material = material;
    v8 = (int64_t)(1000.0 / a2);
    rd_surf->field_34 = v8;
    if (v8)
    {
        v13 = v8 + sithTime_curMs;
        result = rd_surf;
        rd_surf->field_30 = v13;
    }
    else
    {
        rd_surf->flags = 0;
        v9 = rd_surf - sithSurface_aSurfaces;
        v10 = sithSurface_numSurfaces;
        sithSurface_aAvail[v5 + 1] = v9;
        sithSurface_numAvail = v5 + 1;
        if ( v9 == v10 )
        {
            for (v11 = v9-1; v11 >= 0; v11--)
            {
                if (sithSurface_aSurfaces[v11].flags)
                    break;
            }
            sithSurface_numSurfaces = v11;
        }
        result = 0;
    }
    return result;
}

void sithSurface_Free(sithWorld *world)
{
    for (int i = 0; i < world->numSurfaces; i++)
    {
        sithSurface* surface = &world->surfaces[i];

        surface->surfaceInfo.face.numVertices = 0;
        if ( surface->surfaceInfo.face.vertexPosIdx )
            pSithHS->free(surface->surfaceInfo.face.vertexPosIdx);
        if ( surface->surfaceInfo.face.vertexUVIdx )
            pSithHS->free(surface->surfaceInfo.face.vertexUVIdx);
        if ( surface->surfaceInfo.intensities )
            pSithHS->free(surface->surfaceInfo.intensities);
        surface->surfaceInfo.lastTouchedMs = 0;
    }

    pSithHS->free(world->surfaces);
    world->surfaces = 0;
    world->numSurfaces = 0;
    sithSurface_numSurfaces_0 = 0;
    if ( world->adjoins )
    {
        pSithHS->free(world->adjoins);
        world->adjoins = 0;
        world->numAdjoins = 0;
        world->numAdjoinsLoaded = 0;
    }
}

void sithSurface_Tick(float deltaSecs)
{
    int v2; // ebx
    int flags; // ecx
    int v7; // edx
    int v8; // eax
    rdSurface *v9; // ecx
    sithSurface *v10; // edi
    unsigned int v13; // eax
    unsigned int v14; // edi
    int v15; // ebx
    unsigned int v16; // ecx
    unsigned int v17; // ecx
    int v19; // edi
    unsigned int v20; // eax
    int v22; // eax
    int v24; // ecx
    int v25; // edx
    int v27; // eax
    rdSurface *v28; // ecx
    int v29; // edx
    double v31; // st7
    int v33; // ecx
    sithSurface* v34; // eax
    sithThing* v35; // eax
    double v37; // st7

    v2 = 0;
    for (v2 = 0; v2 <= sithSurface_numSurfaces; v2++)
    {
        rdSurface* surface = &sithSurface_aSurfaces[v2];
        flags = surface->flags;
        if (!flags)
            continue;

        sithThing* parent_thing = surface->parent_thing;
        if ( !parent_thing || parent_thing->type && parent_thing->signature == surface->signature )
        {
            if ( (flags & SURFACEFLAGS_100000) != 0 )
            {
                if ( (flags & SURFACEFLAGS_WATER) != 0 )
                {
                    v10 = surface->sithSurfaceParent;
                    if ( v10 )
                    {
                        float scroll_x = surface->field_1C.x * deltaSecs;
                        float scroll_y = surface->field_1C.y * deltaSecs;

                        v10->surfaceInfo.face.clipIdk.x = scroll_x + v10->surfaceInfo.face.clipIdk.x;
                        v10->surfaceInfo.face.clipIdk.y = scroll_y + v10->surfaceInfo.face.clipIdk.y;

                        if ( ((v2 + bShowInvisibleThings) & 0xF) == 0 )
                        {
                            v10->surfaceInfo.face.clipIdk.x = fmod(v10->surfaceInfo.face.clipIdk.x, 1024.0);
                            v10->surfaceInfo.face.clipIdk.y = fmod(v10->surfaceInfo.face.clipIdk.y, 1024.0);
                        }
                    }
                }
                else if ( (flags & SURFACEFLAGS_800000) != 0 )
                {
                    sithSurface_ScrollSky(surface, SITH_SURFACE_HORIZONSKY, deltaSecs, v2);
                }
                else if ( (flags & SURFACEFLAGS_1000000) != 0 )
                {
                    sithSurface_ScrollSky(surface, SITH_SURFACE_CEILINGSKY, deltaSecs, v2);
                }
            }
            else if ( (flags & SURFACEFLAGS_200000) != 0 && (v13 = surface->field_30, v13 <= sithTime_curMs) )
            {
                v14 = surface->field_34;
                v15 = 0;
                v16 = sithTime_curMs - v13;
                if ( v14 && surface->material )
                {
                    surface->wallCel += v16 / v14 + 1;
                    surface->field_30 = surface->field_34 + sithTime_curMs - v16 % surface->field_34;
                    v17 = surface->material->num_texinfo;
                    if ( surface->wallCel >= v17 )
                    {
                        if ( (flags & 1) != 0 )
                        {
                            v19 = 0;
                            if ( (flags & 2) != 0 )
                            {
                                v19 = 1;
                            }
                            else if ( (flags & 4) != 0 )
                            {
                                v19 = 2;
                            }
                            v20 = (surface->wallCel - v19) % (v17 - v19) + v19;
                            surface->wallCel = v20;
                            rdMaterial* v21 = surface->material;
                            if ( v20 > v21->num_texinfo - 1 )
                                v20 = v21->num_texinfo - 1;
                            surface->wallCel = v20;
                        }
                        else
                        {
                            if ( (flags & 8) != 0 )
                                surface->wallCel = 0;
                            else
                                surface->wallCel = v17 - 1;
                            v15 = 1;
                        }
                    }
                    v22 = surface->flags;
                    if ( (v22 & 0x80000) != 0 )
                    {
                        surface->parent_thing->rdthing.wallCel = surface->wallCel;
                    }
                    else if ( (v22 & 0x20000) != 0 )
                    {
                        sithSurface* v23 = surface->sithSurfaceParent;
                        v23->surfaceInfo.face.wallCel = surface->wallCel;
                        v23->surfaceFlags |= 0x8000;
                    }
                    else if ( (v22 & 0x10000) != 0 )
                    {
                        surface->material->celIdx = surface->wallCel;
                    }
                    if ( v15 )
                    {
                        // TODO inlined?
                        surface->flags = 0;
                        v25 = ((intptr_t)surface - (intptr_t)sithSurface_aSurfaces) / sizeof(rdSurface);
                        sithSurface_aAvail[++sithSurface_numAvail] = v25;
                        if ( v25 == sithSurface_numSurfaces )
                        {
                            for (v27 = v25 - 1; v27 >= 0; v27--)
                            {
                                v28 = &sithSurface_aSurfaces[v27];
                                if ( v28->flags )
                                    break;
                            }
                            sithSurface_numSurfaces = v27;
                        }
                    }
                }
            }
            else if ( (flags & 0x400000) != 0 )
            {
                v29 = 0;
                v31 = surface->field_44 * deltaSecs + surface->field_3C;
                if ( surface->field_44 < 0.0 && v31 < surface->field_40 || surface->field_44 > 0.0 && v31 > surface->field_40 ) // TODO verify `surface->field_44 < 0.0`
                {
                    v31 = surface->field_40;
                    v29 = 1;
                }
                surface->field_3C = v31;
                v33 = surface->flags;
                if ( (v33 & 0x20000) != 0 && (v34 = surface->sithSurfaceParent) != 0 )
                {
                    v34->surfaceInfo.face.extraLight = v31;
                }
                else if ( (v33 & 0x40000) != 0 && (v35 = surface->parent_thing) != 0 )
                {
                    v35->light = v31;
                }
                else if ( (v33 & 0x2000000) != 0 )
                {
                    if ( surface->sector )
                        surface->sector->extraLight = v31;
                }
                if ( v29 )
                {
                    if ( (v33 & 1) != 0 )
                    {
                        surface->field_44 = -surface->field_44;
                        v37 = surface->field_40;
                        surface->field_40 = surface->field_48;
                        surface->field_48 = v37;
                    }
                    else
                    {
                        sithSurface_StopAnim(surface);
                    }
                }
            }
        }
        else
        {
            // TODO inlined?
            surface->flags = 0;
            v7 = ((intptr_t)surface - (intptr_t)sithSurface_aSurfaces) / sizeof(rdSurface);
            sithSurface_aAvail[++sithSurface_numAvail] = v7;
            if ( v7 == sithSurface_numSurfaces )
            {
                for (v8 = v7 - 1; v8 >= 0; v8--)
                {
                    v9 = &sithSurface_aSurfaces[v8];
                    if ( v9->flags )
                        break;
                }
                sithSurface_numSurfaces = v8;
            }
        }
    }
}

void sithSurface_ScrollSky(rdSurface *surface, int skyType, float deltaSecs, uint8_t a4)
{
    float scroll_x = surface->field_1C.x * deltaSecs;
    float scroll_y = surface->field_1C.y * deltaSecs;

    if ( skyType == SITH_SURFACE_HORIZONSKY )
    {
        float offs_x = scroll_x + sithWorld_pCurWorld->horizontalSkyOffs.x;
        float offs_y = scroll_y + sithWorld_pCurWorld->horizontalSkyOffs.y;

        sithWorld_pCurWorld->horizontalSkyOffs.x = offs_x;
        sithWorld_pCurWorld->horizontalSkyOffs.y = offs_y;

        if ( ((bShowInvisibleThings + a4) & 0xF) == 0 )
        {
            sithWorld_pCurWorld->horizontalSkyOffs.x = fmod(offs_x, 1024.0);
            sithWorld_pCurWorld->horizontalSkyOffs.y = fmod(offs_y, 1024.0);
        }
    }
    else
    {
        float offs_x = scroll_x + sithWorld_pCurWorld->ceilingSkyOffs.x;
        float offs_y = scroll_y + sithWorld_pCurWorld->ceilingSkyOffs.y;

        sithWorld_pCurWorld->ceilingSkyOffs.x = offs_x;
        sithWorld_pCurWorld->ceilingSkyOffs.y = offs_y;

        if ( ((bShowInvisibleThings + a4) & 0xF) == 0 )
        {
            sithWorld_pCurWorld->ceilingSkyOffs.x = fmod(offs_x, 1024.0);
            sithWorld_pCurWorld->ceilingSkyOffs.y = fmod(offs_y, 1024.0);
        }
    }
}

int sithSurface_StopAnim(rdSurface *surface)
{
    sithSurface *v2; // eax
    int v4; // eax
    int v5; // edx
    int v6; // eax

    if ( (surface->flags & SURFACEFLAGS_WATER) != 0 && (surface->flags & SURFACEFLAGS_100000) != 0 )
    {
        v2 = surface->sithSurfaceParent;
        v2->surfaceFlags &= 0x800;
        surface->field_24.x = 0.0;
        surface->field_24.y = 0.0;
        surface->field_24.z = 0.0;
        surface->field_1C.x = 0.0;
        surface->field_1C.y = 0.0;
    }
    surface->flags = 0;
    v4 = sithSurface_numAvail;
    v5 = surface - sithSurface_aSurfaces;
    sithSurface_aAvail[sithSurface_numAvail + 1] = v5;
    sithSurface_numAvail = v4 + 1;
    if ( v5 == sithSurface_numSurfaces )
    {
        for (v6 = v5 - 1; v6 >= 0; v6--)
        {
            if (sithSurface_aSurfaces[v6].flags)
                break;
        }
        sithSurface_numSurfaces = v6;
    }
    return 1;
}

uint32_t sithSurface_GetSurfaceAnim(sithSurface *surface)
{
    int v1; // ecx
    rdSurface *i; // eax
    rdSurface* v3; // eax

    v1 = 0;
    for ( i = sithSurface_aSurfaces; v1 <= sithSurface_numSurfaces; ++i )
    {
        if ( (i->flags & SURFACEFLAGS_WATER) != 0 && i->sithSurfaceParent == surface )
            break;
        ++v1;
    }
    v3 = v1 > sithSurface_numSurfaces ? 0 : i;
    if ( !v3 )
        return -1;

    // div 19 div 4?
    return ((intptr_t)v3 - (intptr_t)sithSurface_aSurfaces) / sizeof(rdSurface);
}

rdSurface* sithSurface_SurfaceLightAnim(sithSurface *surface, float a2, float a3)
{
    double v3; // st7
    rdSurface *result; // eax
    int v5; // edx
    rdSurface *v6; // esi
    float v7; // edx
    float surfacea; // [esp+4h] [ebp+4h]

    v3 = a2 - surface->surfaceInfo.face.extraLight;
    if ( v3 == 0.0 )
        return 0;
    //result = (rdSurface *)sithSurface_numAvail;
    // Added: fix undef behavior?
    result = NULL;
    if ( sithSurface_numAvail )
    {
        v5 = sithSurface_aAvail[sithSurface_numAvail--];
        if ( v5 > sithSurface_numSurfaces )
            sithSurface_numSurfaces = v5;
        v6 = &sithSurface_aSurfaces[v5];
        _memset(v6, 0, sizeof(rdSurface));
        result = v6;
        v6->index = ((playerThingIdx + 1) << 16) | (uint16_t)v5;
    }
    if ( result )
    {
        v7 = surface->surfaceInfo.face.extraLight;
        result->sithSurfaceParent = surface;
        result->flags = SURFACEFLAGS_400000|SURFACEFLAGS_WATER;
        surfacea = v3;
        result->field_44 = surfacea / a3;
        result->field_3C = v7;
        result->field_40 = a2;
    }
    return result;
}

rdSurface* sithSurface_SlideWall(sithSurface *surface, rdVector3 *a2)
{
    rdMaterial *v2; // eax
    rdSurface *v3; // eax
    int v4; // edx
    rdSurface *v5; // ebx
    sithWorld *v6; // edi
    int v7; // ebp
    float v8; // edx
    int *v9; // eax
    rdVector3 *v10; // ecx
    rdVector2 *v11; // eax
    int *v12; // ecx
    int v13; // edx
    int v14; // ecx
    float v15; // eax
    int v16; // ecx
    rdVector2 *v17; // edx
    double v18; // st7
//    char v20; // c3
//    char v22; // c0
    rdSurface *result; // eax
    float v25; // [esp+10h] [ebp-BCh]
    float v26; // [esp+10h] [ebp-BCh]
    float v27; // [esp+10h] [ebp-BCh]
    float v28; // [esp+14h] [ebp-B8h]
    float v29; // [esp+14h] [ebp-B8h]
    rdVector3 v30; // [esp+18h] [ebp-B4h]
    rdVector3 v31; // [esp+24h] [ebp-A8h]
    rdSurface *v32; // [esp+30h] [ebp-9Ch]
    rdMatrix34 in; // [esp+34h] [ebp-98h] BYREF
    int v34; // [esp+64h] [ebp-68h]
    rdVector2 v35; // [esp+68h] [ebp-64h]
    rdVector3 a1; // [esp+70h] [ebp-5Ch] BYREF
    rdVector3 a1a; // [esp+7Ch] [ebp-50h] BYREF
    rdVector3 rot; // [esp+90h] [ebp-3Ch] BYREF
    rdMatrix34 a3; // [esp+9Ch] [ebp-30h] BYREF

    v2 = surface->surfaceInfo.face.material;
    if ( !v2 || (v2->tex_type & 2) == 0 )
        return 0;
    v3 = NULL;
    if ( sithSurface_numAvail )
    {
        v4 = sithSurface_aAvail[sithSurface_numAvail--];
        if ( v4 > sithSurface_numSurfaces )
            sithSurface_numSurfaces = v4;
        v5 = &sithSurface_aSurfaces[v4];
        _memset(v5, 0, sizeof(rdSurface));
        v3 = v5;
        v5->index = ((playerThingIdx + 1) << 16) | (uint16_t)v4;
    }
    v32 = v3;
    if ( !v3 )
        return 0;
    v3->flags = SURFACEFLAGS_100000|SURFACEFLAGS_WATER;
    v3->sithSurfaceParent = surface;
    v6 = sithWorld_pCurWorld;
    v3->field_24 = *a2;
    v7 = 1;
    v8 = surface->surfaceInfo.face.normal.x;
    v34 = surface->surfaceFlags;
    in.uvec.x = v8;
    in.uvec.y = surface->surfaceInfo.face.normal.y;
    v9 = surface->surfaceInfo.face.vertexPosIdx;
    in.uvec.z = surface->surfaceInfo.face.normal.z;
    v10 = v6->vertices;
    v31 = v10[*v9];
    v30 = v10[v9[1]];
    v11 = v6->vertexUVs;
    v12 = surface->surfaceInfo.face.vertexUVIdx;
    v13 = *v12;
    v14 = v12[1];
    v35 = v11[v13];
    v25 = v11[v14].x;
    v15 = v11[v14].y;
    a1.x = v31.x - v30.x;
    v28 = v15;
    a1.y = v31.y - v30.y;
    for ( a1.z = v31.z - v30.z; rdVector_Len3(&a1) < 0.000099999997; v28 = v17[v16].y )
    {
        if ( ++v7 == surface->surfaceInfo.face.numVertices )
            v7 = 0;
        v30 = v6->vertices[surface->surfaceInfo.face.vertexPosIdx[v7]];
        v16 = surface->surfaceInfo.face.vertexUVIdx[v7];
        v17 = v6->vertexUVs;
        v25 = v17[v16].x;
    }
    v30.x = v30.x - v31.x;
    v30.y = v30.y - v31.y;
    v30.z = v30.z - v31.z;
    v26 = v25 - v35.x;
    in.rvec = v30;
    v29 = v28 - v35.y;
    rdVector_Normalize3Acc(&in.uvec);
    rdVector_Normalize3Acc(&in.rvec);
    in.scale = v31;
    in.lvec.x = in.uvec.y * in.rvec.z - in.uvec.z * in.rvec.y;
    in.lvec.y = in.uvec.z * in.rvec.x - in.uvec.x * in.rvec.z;
    in.lvec.z = in.uvec.x * in.rvec.y - in.uvec.y * in.rvec.x;
    rdMatrix_InvertOrtho34(&a3, &in);
    if ( v26 == 0.0 && v29 == 0.0 )
    {
        v18 = 0.0;
    }
    else if ( v26 == 0.0 )
    {
        if ( v29 <= 0.0 )
            v18 = -90.0;
        else
            v18 = 90.0;
    }
    else if ( v29 == 0.0 )
    {
        if ( v26 <= 0.0 )
            v18 = 180.0;
        else
            v18 = 0.0;
    }
    else
    {
        v18 = atan2(v29 / v26, 1.0) * 57.295784;
        if ( v26 < 0.0 && v29 > 0.0 )
            v18 = v18 - -180.0;
        if ( v26 < 0.0 && v29 < 0.0 )
            v18 = v18 - 180.0;
    }
    v27 = 320.0;
    if ( (v34 & SURFACEFLAGS_20) != 0 )
    {
        v27 = 160.0;
    }
    else if ( (v34 & SURFACEFLAGS_10) != 0 )
    {
        v27 = 640.0;
    }
    else if ( (v34 & SURFACEFLAGS_40) != 0 )
    {
        v27 = 40.0;
    }
    rot.y = v18;
    rot.x = 0.0;
    rot.z = 0.0;
    rdMatrix_PostRotate34(&a3, &rot);
    
    rdVector3 a1a_2;
    a1a_2.x = v27;
    a1a_2.y = v27;
    a1a_2.z = 1.0;
    rdMatrix_PostScale34(&a3, &a1a_2);
    rdMatrix_TransformVector34(&a1a, a2, &a3);
    result = v32;
    v32->field_1C.x = -a1a.x;
    v32->field_1C.y = -a1a.y;
    surface->surfaceFlags |= 0x800;
    return result;
}

rdSurface* sithSurface_MaterialAnim(rdMaterial *material, float a2, int a3)
{
    int v3; // ebx
    rdSurface *v4; // esi
    int v5; // edx
    rdSurface *result; // eax
    int64_t v7; // rax
    int v8; // edx
    int v9; // eax
    int v10; // eax
    int v12; // ecx

    v3 = sithSurface_numAvail;
    if ( sithSurface_numAvail )
    {
        v5 = sithSurface_aAvail[sithSurface_numAvail];
        v3 = --sithSurface_numAvail;
        if ( v5 > sithSurface_numSurfaces )
            sithSurface_numSurfaces = v5;
        v4 = &sithSurface_aSurfaces[v5];
        _memset(v4, 0, sizeof(rdSurface));
        v4->index = ((playerThingIdx + 1) << 16) | (uint16_t)v5;
    }
    else
    {
        v4 = 0;
    }
    if ( !v4 )
        return 0;
    if ( (a3 & 4) != 0 )
        v4->wallCel = 2;
    else
        v4->wallCel = (a3 & 2) != 0;
    v4->material = material;
    v4->flags = (uint16_t)a3 | SURFACEFLAGS_200000|SURFACEFLAGS_METAL;
    v7 = (int64_t)(1000.0 / a2);
    v4->field_34 = v7;
    if (v7)
    {
        v12 = v7 + sithTime_curMs;
        result = v4;
        v4->field_30 = v12;
    }
    else
    {
        v4->flags = 0;
        v8 = v4 - sithSurface_aSurfaces;
        v9 = sithSurface_numSurfaces;
        sithSurface_aAvail[v3 + 1] = v8;
        sithSurface_numAvail = v3 + 1;
        if ( v8 == v9 )
        {
            v10 = v8 - 1;
            if ( v8 - 1 >= 0 )
            {
                do
                {
                    if ( sithSurface_aSurfaces[v10].flags )
                        break;
                    --v10;
                }
                while ( v10 >= 0 );
            }
            sithSurface_numSurfaces = v10;
        }
        result = 0;
    }
    return result;
}

void sithSurface_DetachThing(sithSurface *a1, rdVector3 *out)
{
    int v2; // ecx
    rdSurface *i; // eax
    rdSurface *v4; // eax

    v2 = 0;
    for ( i = sithSurface_aSurfaces; v2 <= sithSurface_numSurfaces; ++i )
    {
        if ( (i->flags & SURFACEFLAGS_WATER) != 0 && i->sithSurfaceParent == a1 )
            break;
        ++v2;
    }
    v4 = (v2 > sithSurface_numSurfaces ? NULL : i);
    if ( v4 )
    {
        *out = v4->field_24;
    }
    else
    {
        out->x = 0.0;
        out->y = 0.0;
        out->z = 0.0;
    }
}

int sithSurface_GetCenter(sithSurface *surface, rdVector3 *out)
{
    float v6; // [esp+0h] [ebp-2Ch]
    rdVector3 a1a; // [esp+14h] [ebp-18h] BYREF
    rdVector3 a2a; // [esp+20h] [ebp-Ch] BYREF

    a1a.x = 0.0;
    a1a.y = 0.0;
    a1a.z = 0.0;
    for (uint32_t i = 0; i < surface->surfaceInfo.face.numVertices; ++i )
        rdVector_Add3Acc(&a1a, &sithWorld_pCurWorld->vertices[surface->surfaceInfo.face.vertexPosIdx[i]]);

    v6 = (float)(unsigned int)surface->surfaceInfo.face.numVertices;
    rdVector_InvScale3(out, &a1a, v6);

    if ( !sithIntersect_IsSphereInSector(out, 0.0, surface->parent_sector) )
    {
        a2a.x = surface->surfaceInfo.face.normal.x * 0.00019999999;
        a2a.y = surface->surfaceInfo.face.normal.y * 0.00019999999;
        a2a.z = surface->surfaceInfo.face.normal.z * 0.00019999999;
        rdVector_Add3Acc(out, &a2a);
    }
    return sithIntersect_IsSphereInSector(out, 0.0, surface->parent_sector);
}

rdSurface* sithSurface_SlideHorizonSky(int skyType, rdVector2 *a2)
{
    rdSurface *result; // eax
    int v3; // edx
    rdSurface *v4; // esi
    float v5; // ecx
    float v6; // ecx

    //result = (rdSurface *)sithSurface_numAvail;
    // Added: fix undef behavior?
    result = NULL;
    if ( sithSurface_numAvail )
    {
        v3 = sithSurface_aAvail[sithSurface_numAvail--];
        if ( v3 > sithSurface_numSurfaces )
            sithSurface_numSurfaces = v3;
        v4 = &sithSurface_aSurfaces[v3];
        _memset(v4, 0, sizeof(rdSurface));
        result = v4;
        v4->index = ((playerThingIdx + 1) << 16) | (uint16_t)v3;
    }
    if ( result )
    {
        if ( skyType == SITH_SURFACE_HORIZONSKY )
        {
            result->flags = 0x900000;
            v5 = a2->y;
            result->field_1C.x = a2->x;
            result->field_1C.y = v5;
        }
        else
        {
            if ( skyType == SITH_SURFACE_CEILINGSKY )
                result->flags = 0x1100000;
            v6 = a2->y;
            result->field_1C.x = a2->x;
            result->field_1C.y = v6;
        }
    }
    return result;
}

rdSurface* sithSurface_sub_4F00A0(sithThing *thing, float a2, uint16_t a3)
{
    rdSurface *v3; // esi
    int v4; // edx
    rdSurface *result; // eax
    int v6; // edx
    rdSprite *v7; // eax
    uint32_t v8; // rax

    if ( sithSurface_numAvail )
    {
        v4 = sithSurface_aAvail[sithSurface_numAvail--];
        if ( v4 > sithSurface_numSurfaces )
            sithSurface_numSurfaces = v4;
        v3 = &sithSurface_aSurfaces[v4];
        _memset(v3, 0, sizeof(rdSurface));
        v3->index = ((playerThingIdx + 1) << 16) | (uint16_t)v4;
    }
    else
    {
        v3 = 0;
    }
    if ( !v3 )
        return 0;
    thing->rdthing.wallCel = 0;
    if ( (a3 & 4) != 0 )
        v3->wallCel = 2;
    else
        v3->wallCel = (a3 & 2) != 0;
    v6 = thing->signature;
    v3->flags = a3 | SURFACEFLAGS_200000|SURFACEFLAGS_EARTH;
    v7 = thing->rdthing.sprite3;
    v3->parent_thing = thing;
    v3->signature = v6;
    v3->material = v7->face.material;
    v8 = (uint32_t)(1000.0 / a2);
    uint32_t v8_hi = sithTime_curMs;
    v3->field_34 = v8;
    v8_hi += v8;
    result = v3;
    v3->field_30 = v8_hi;
    return result;
}

rdSurface* sithSurface_SetThingLight(sithThing *thing, float a2, float a3, int a4)
{
    double v5; // st7
    rdSurface *result; // eax
    int v7; // edx
    rdSurface *v8; // esi
    int v9; // edx
    double v11; // st7
    float a1a; // [esp+4h] [ebp+4h]

    v5 = a2 - thing->light;
    if ( v5 == 0.0 )
        return 0;
    result = NULL;
    if ( sithSurface_numAvail )
    {
        v7 = sithSurface_aAvail[sithSurface_numAvail--];
        if ( v7 > sithSurface_numSurfaces )
            sithSurface_numSurfaces = v7;
        v8 = &sithSurface_aSurfaces[v7];
        _memset(v8, 0, sizeof(rdSurface));
        result = v8;
        v8->index = ((playerThingIdx + 1) << 16) | (uint16_t)v7;
    }
    if ( result )
    {
        v9 = thing->signature;
        result->parent_thing = thing;
        result->signature = v9;
        result->flags = a4 & 1 | SURFACEFLAGS_400000|SURFACEFLAGS_PUDDLE;
        thing->thingflags |= SITH_TF_LIGHT;
        a1a = v5;
        result->field_44 = a1a / a3;
        v11 = thing->light;
        result->field_3C = thing->light;
        result->field_48 = v11;
        result->field_40 = a2;
    }
    return result;
}

void sithSurface_SendDamageToThing(sithSurface *sender, sithThing *receiver, float damage, int damageType)
{
    float v4; // [esp+0h] [ebp-14h]

    if ( (!sithNet_isMulti || !receiver || (receiver->thingflags & 0x100) == 0) && (sender->surfaceFlags & 2) != 0 )
    {
        v4 = (float)(unsigned int)damageType;
        sithCog_SendMessageFromSurfaceEx(sender, receiver, SITH_MESSAGE_DAMAGED, damage, v4, 0.0, 0.0);
    }
}

rdSurface* sithSurface_GetRdSurface(sithSurface *surface)
{
    int v1; // ecx
    rdSurface *i; // eax

    v1 = 0;
    for ( i = sithSurface_aSurfaces; v1 <= sithSurface_numSurfaces; ++i )
    {
        if ( (i->flags & 0x20000) != 0 && i->sithSurfaceParent == surface )
            break;
        ++v1;
    }
    return (rdSurface *)(v1 > sithSurface_numSurfaces ? 0 : (intptr_t)i);
}

rdSurface* sithSurface_GetByIdx(int idx)
{
    int v1; // ecx
    rdSurface *i; // eax

    v1 = 0;
    if ( sithSurface_numSurfaces < 0 )
        return 0;
    for ( i = sithSurface_aSurfaces; !i->flags || i->index != idx; ++i )
    {
        if ( ++v1 > sithSurface_numSurfaces )
            return 0;
    }
    return &sithSurface_aSurfaces[v1];
}

void sithSurface_Sync(int mpFlags)
{
    if ( (sithCogVm_multiplayerFlags & mpFlags) != 0 )
    {
        for (int i = 0; i <= sithSurface_numSurfaces; i++) // TODO: off by one?
        {
            int flags = sithSurface_aSurfaces[i].flags;
            if ( flags && ((flags & 0xC0000) == 0 || !sithSurface_aSurfaces[i].parent_thing || sithThing_ShouldSync(sithSurface_aSurfaces[i].parent_thing)) )
                sithSector_cogMsg_SendStopAnim(&sithSurface_aSurfaces[i], 0, mpFlags);
        }
    }
}

rdSurface* sithSurface_Alloc()
{
    int v1; // edx
    rdSurface *v2; // esi

    if (!sithSurface_numAvail)
        return NULL;

    v1 = sithSurface_aAvail[sithSurface_numAvail--];
    if ( v1 > sithSurface_numSurfaces )
        sithSurface_numSurfaces = v1;

    v2 = &sithSurface_aSurfaces[v1];
    _memset(v2, 0, sizeof(rdSurface));
    v2->index = ((playerThingIdx + 1) << 16) | (uint16_t)v1;
    return v2;
}

sithSurface* sithSurface_sub_4E63B0(int idx)
{
    sithSurface *result; // eax

    if ( sithWorld_pCurWorld && idx >= 0 && idx < sithWorld_pCurWorld->numSurfaces )
        result = &sithWorld_pCurWorld->surfaces[idx];
    else
        result = 0;
    return result;
}
