#include "sithSurface.h"

#include "General/stdHashTable.h"
#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "World/sithSector.h"
#include "Engine/sithAdjoin.h"
#include "Engine/sithMaterial.h"
#include "Engine/sithTime.h"
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

int sithSurface_Open()
{
    sithSurface_bOpened = 1;
    return 1;
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
    sithSurface *surfaceIter; // [esp+20h] [ebp-Ch] BYREF
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
    surfaceIter = surfaces;
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
            if ( (world->adjoins[numAdjoins].flags & 1) == 0
              || face->material && face->geometryMode && (face->type & 2) == 0 && ((v66->header.texture_type & 8) == 0 || (v66->texture_ptr->alpha_en & 1) == 0) )
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

        surfaceInfo->field_40 = pSithHS->alloc(sizeof(float) * v35);
        if ( !surfaceInfo->field_40 )
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
            surfaceInfo->field_40[v45] = _atof(stdConffile_entry.args[v61+v45].value);
        }
        face->numVertices = v35;
        face->num = v67;
        surfaceIter++;
    }
LABEL_71:

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
        if (world->surfaces[i].parent_sector == 8 || !world->surfaces[i].parent_sector)
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
        v6 = (rdSurface *)sithSurface_numAvail;
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

