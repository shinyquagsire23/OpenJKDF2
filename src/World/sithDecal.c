#include "sithDecal.h"

#ifdef DECAL_RENDERING

#include "Primitives/rdDecal.h"
#include "World/sithWorld.h"
#include "General/stdHashTable.h"
#include "General/stdConffile.h"
#include "General/stdString.h"
#include "stdPlatform.h"
#include "jk.h"

stdHashTable* sithDecal_hashmap;

int sithDecal_Startup()
{
	sithDecal_hashmap = stdHashTable_New(128);
    if (sithDecal_hashmap)
        return 1;
    stdPrintf(pSithHS->errorPrint, ".\\World\\sithDecal.c", 63, "Failed to allocate memory for decals.\n", 0, 0, 0, 0);
    return 0;
}

void sithDecal_Shutdown()
{
    if (sithDecal_hashmap)
    {
        stdHashTable_Free(sithDecal_hashmap);
		sithDecal_hashmap = 0;
    }
}

int sithDecal_Load(sithWorld *world, int a2)
{
    int decal_amt;

    if (a2)
        return 0;

    stdConffile_ReadArgs();
    if ( _memcmp(stdConffile_entry.args[0].value, "world", 6u) || _memcmp(stdConffile_entry.args[1].value, "decals", 7u) )
        return 0;
	decal_amt = _atoi(stdConffile_entry.args[2].value);
    if ( !decal_amt)
        return 1;

    if ( !sithDecal_New(world, decal_amt) )
    {
        stdPrintf(pSithHS->errorPrint, ".\\World\\sithDecal.c", 163, "Memory error while reading decals, line %d.\n", stdConffile_linenum, 0, 0, 0);
        return 0;
    }
    
    sithWorld_UpdateLoadPercent(90.0);
    
    float loadPercent = 90.0;
    if ( stdConffile_ReadArgs() )
    {
        while ( _memcmp(stdConffile_entry.args[0].value, "end", 4u) )
        {
            if ( !sithDecal_LoadEntry(stdConffile_entry.args[1].value) )
            {
                stdPrintf(
                    pSithHS->errorPrint,
                    ".\\World\\sithDecal.c",
                    159,
                    "Parse error while reading decals, line %d.\n",
                    stdConffile_linenum);
                stdPrintf(
                    pSithHS->errorPrint,
                    ".\\World\\sithDecal.c",
                    159,
                    "OpenJKDF2: Failed decal was `%s`\n",
                    stdConffile_entry.args[1].value);
                return 0;
            }
            float percentDelta = 10.0 / (double)decal_amt;
            loadPercent += percentDelta;
            sithWorld_UpdateLoadPercent(loadPercent);
            if ( !stdConffile_ReadArgs() )
                break;
        }
    }
    sithWorld_UpdateLoadPercent(80.0);
    return 1;
}

void sithDecal_FreeEntry(sithWorld *world)
{
    if (!world->numDecals)
        return;

    for (int idx = 0; idx < world->numDecalsLoaded; idx++)
    {
        stdHashTable_FreeKey(sithDecal_hashmap, world->decals[idx].path);
        rdDecal_FreeEntry(&world->decals[idx]);
    }
    pSithHS->free(world->decals);
    world->decals = 0;
    world->numDecalsLoaded = 0;
    world->numDecals = 0;
}

rdDecal* sithDecal_LoadEntry(char *fpath)
{
    sithWorld *world;
	rdDecal* result;
	rdDecal* decal;
    char decalFpath[128];

    world = sithWorld_pLoading;

	if (!sithWorld_pLoading->decals)
	{
		sithWorld_pLoading->decals = (rdDecal*)pSithHS->alloc(64 * sizeof(rdDecal));
		if (sithWorld_pLoading->decals)
		{
			sithWorld_pLoading->numDecals = 64;
			sithWorld_pLoading->numDecalsLoaded = 0;
			_memset(sithWorld_pLoading->decals, 0, 64 * sizeof(rdDecal));
		}
	}

    result = (rdDecal*)stdHashTable_GetKeyVal(sithDecal_hashmap, fpath);
    if ( !result )
    {
        uint32_t idx = world->numDecalsLoaded;
        if ( idx < world->numDecals )
        {
            decal = &world->decals[idx];
            _sprintf(decalFpath, "%s%c%s", "misc\\dcal", '\\', fpath);
            if ( stdConffile_OpenRead(decalFpath) )
            {
				stdString_SafeStrCopy(decal->path, fpath, 0x20);
				if (stdConffile_ReadArgs() && stdConffile_entry.numArgs >= 10)
				{
					rdVector3 col;
					rdVector3 size;
					char mat[32];

					stdString_SafeStrCopy(mat, stdConffile_entry.args[0].value, 0x20);
					uint32_t flags = _atoi(stdConffile_entry.args[1].value);
					col.x = _atof(stdConffile_entry.args[2].value);
					col.y = _atof(stdConffile_entry.args[3].value);
					col.z = _atof(stdConffile_entry.args[4].value);
					size.x = _atof(stdConffile_entry.args[5].value);
					size.z = _atof(stdConffile_entry.args[6].value);
					size.y = _atof(stdConffile_entry.args[7].value); // y is depth
					float fadeTime = _atof(stdConffile_entry.args[8].value);
					float angleFade = _atof(stdConffile_entry.args[9].value);
					rdDecal_NewEntry(decal, fpath, mat, flags, &col, &size, fadeTime, angleFade);
				
					stdConffile_Close();

					//decal->id = world->numDecalsLoaded;
					//if (sithWorld_pLoading->level_type_maybe & 1)
						//decal->id |= 0x8000;
					stdHashTable_SetKeyVal(sithDecal_hashmap, decal->path, decal);
					++world->numDecalsLoaded;
					return decal;
				}				
				else
				{
					jk_printf("OpenJKDF2: Failed read decal `%s`!\n", fpath);
				}
			}
			else if ( _memcmp(fpath, "default.dcal", 0xCu) )
			{
				return sithDecal_LoadEntry("default.dcal");
			}
			else
			{
				jk_printf("OpenJKDF2: Failed to open decal `%s`!\n", decalFpath);
			}
        }
        else
		{
            jk_printf("OpenJKDF2: Failed allocate decal `%s`! numDecalsLoaded < numDecals -> %x < %x failed\n", fpath, world->numDecalsLoaded, world->numDecals);
        }
    }
    return result;
}

int sithDecal_New(sithWorld *world, int num)
{
	rdDecal* decals; // edi

	decals = (rdDecal*)pSithHS->alloc(sizeof(rdDecal) * num);
    world->decals = decals;
    if ( !decals)
        return 0;
    world->numDecals = num;
    world->numDecalsLoaded = 0;
    _memset(decals, 0, sizeof(rdDecal) * num);
    return 1;
}

#endif
