#include "sithSurface.h"

#include "General/stdHashTable.h"
#include "World/sithWorld.h"
#include "Engine/sithAdjoin.h"
#include "Engine/sithMaterial.h"
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
