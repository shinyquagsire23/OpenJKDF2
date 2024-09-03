#include "sithPolyline.h"

#include "Primitives/rdPolyLine.h"
#include "World/sithWorld.h"
#include "General/stdHashTable.h"
#include "General/stdConffile.h"
#include "General/stdString.h"
#include "stdPlatform.h"
#include "jk.h"

#ifdef POLYLINE_EXT

stdHashTable* sithPolyline_hashmap;

int sithPolyline_Startup()
{
	sithPolyline_hashmap = stdHashTable_New(128);
    if (sithPolyline_hashmap)
        return 1;
    stdPrintf(pSithHS->errorPrint, ".\\World\\sithPolyline.c", 63, "Failed to allocate memory for polylines.\n", 0, 0, 0, 0);
    return 0;
}

void sithPolyline_Shutdown()
{
    if (sithPolyline_hashmap)
    {
        stdHashTable_Free(sithPolyline_hashmap);
		sithPolyline_hashmap = 0;
    }
}

int sithPolyline_Load(sithWorld *world, int a2)
{
    int polyline_amt;

    if (a2)
        return 0;

    stdConffile_ReadArgs();
    if ( _memcmp(stdConffile_entry.args[0].value, "world", 6u) || _memcmp(stdConffile_entry.args[1].value, "polylines", 8u) )
        return 0;
	polyline_amt = _atoi(stdConffile_entry.args[2].value);
    if ( !polyline_amt)
        return 1;

	world->polylines = (rdPolyLine*)pSithHS->alloc(sizeof(rdPolyLine) * polyline_amt);
	if (!world->polylines)
	{
		stdPrintf(pSithHS->errorPrint, ".\\World\\sithPolyline.c", 163, "Memory error while reading polyline, line %d.\n", stdConffile_linenum, 0, 0, 0);
		return 0;
	}

	world->numPolylines = polyline_amt;
	world->numPolylinesLoaded = 0;
	_memset(world->polylines, 0, sizeof(rdPolyLine) * polyline_amt);

    sithWorld_UpdateLoadPercent(90.0);
    
    float loadPercent = 90.0;
    if ( stdConffile_ReadArgs() )
    {
        while ( _memcmp(stdConffile_entry.args[0].value, "end", 4u) )
        {
            if ( !sithPolyline_LoadEntry(stdConffile_entry.args[1].value) )
            {
                stdPrintf(
                    pSithHS->errorPrint,
                    ".\\World\\sithPolyline.c",
                    159,
                    "Parse error while reading polylines, line %d.\n",
                    stdConffile_linenum);
                stdPrintf(
                    pSithHS->errorPrint,
                    ".\\World\\sithPolyline.c",
                    159,
                    "OpenJKDF2: Failed poyline was `%s`\n",
                    stdConffile_entry.args[1].value);
                return 0;
            }
            float percentDelta = 5.0 / (double)polyline_amt;
            loadPercent += percentDelta;
            sithWorld_UpdateLoadPercent(loadPercent);
            if ( !stdConffile_ReadArgs() )
                break;
        }
    }
    sithWorld_UpdateLoadPercent(95.0);
    return 1;
}

void sithPolyline_Free(sithWorld *world)
{
    if (!world->numPolylines)
        return;

    for (int idx = 0; idx < world->numPolylinesLoaded; idx++)
    {
        stdHashTable_FreeKey(sithPolyline_hashmap, world->polylines[idx].fname);
        rdPolyLine_FreeEntry(&world->polylines[idx]);
    }
    pSithHS->free(world->polylines);
    world->polylines = 0;
    world->numPolylinesLoaded = 0;
    world->numPolylines = 0;
}

rdPolyLine* sithPolyline_LoadEntry(char *fpath)
{
    sithWorld *world;
	rdPolyLine* result;
	rdPolyLine* polyline;
    char lineFpath[128];

    world = sithWorld_pLoading;
    
	if(!world->polylines)
	{
		world->polylines = (rdPolyLine*)pSithHS->alloc(sizeof(rdPolyLine) * 16);
		if (!world->polylines)
		{
			stdPrintf(pSithHS->errorPrint, ".\\World\\sithPolyline.c", 163, "Memory error while loading polyline %s.\n", fpath);
			return 0;
		}

		world->numPolylines = 16;
		world->numPolylinesLoaded = 0;
		_memset(world->polylines, 0, sizeof(rdPolyLine) * 16);
	}
	
	result = (rdPolyLine*)stdHashTable_GetKeyVal(sithPolyline_hashmap, fpath);
    if ( !result )
    {
        uint32_t idx = world->numPolylinesLoaded;
        if ( idx < world->numPolylines )
        {
            polyline = &world->polylines[idx];
            _sprintf(lineFpath, "%s%c%s", "misc\\pln", '\\', fpath);
            if ( stdConffile_OpenRead(lineFpath) )
            {
                if ( stdConffile_ReadArgs() && stdConffile_entry.numArgs >= 9 )
                {
                    char sidemat[32];
					char tipmat[32];

                    stdString_SafeStrCopy(sidemat, stdConffile_entry.args[0].value, 0x20);
					stdString_SafeStrCopy(tipmat, stdConffile_entry.args[1].value, 0x20);
					float length = _atof(stdConffile_entry.args[2].value);
                    float baserad = _atof(stdConffile_entry.args[3].value);
                    float tiprad = _atof(stdConffile_entry.args[4].value);
                    int geometryMode = _atoi(stdConffile_entry.args[5].value);
                    int lightMode = _atoi(stdConffile_entry.args[6].value);
                    int textureMode = _atoi(stdConffile_entry.args[7].value);
                    float extralight = _atof(stdConffile_entry.args[8].value);
                    stdConffile_Close();
                    if (length > 0.0 && baserad > 0.0 && baserad > 0.0 )
                    {
                        
                        if ( rdPolyLine_NewEntry(polyline, fpath, sidemat, tipmat, length, baserad, tiprad, geometryMode, lightMode, textureMode, extralight) )
                        {
                            stdHashTable_SetKeyVal(sithPolyline_hashmap, polyline->fname, polyline);
                            ++world->numPolylinesLoaded;
                            return polyline;
                        }
                        else {
                            jk_printf("OpenJKDF2: Failed to create polyline `%s`! rdPolyLine_NewEntry failed.\n", lineFpath);
                        }
                    }
                    else { // Added
                        jk_printf("OpenJKDF2: Failed to read polyline `%s`! length %f baserad %f tiprad %f\n", lineFpath, length, baserad, tiprad);
                    }
                }
                else // Added
                {
                    jk_printf("OpenJKDF2: Failed to read polyline `%s`! NumArgs %x < 9?\n", lineFpath, stdConffile_entry.numArgs);
                    stdConffile_Close();
                }
            }
            else if ( _memcmp(fpath, "default.pln", 0xCu) )
            {
                return sithPolyline_LoadEntry("default.pln");
            }
            else { // Added
                jk_printf("OpenJKDF2: Failed to open polyline `%s`!\n", lineFpath);
            }
        }
        else { // Added
            jk_printf("OpenJKDF2: Failed allocate polyline `%s`! numParticlesLoaded < numPolylines -> %x < %x failed\n", fpath, world->numParticlesLoaded, world->numPolylines);
        }
    }
    return result;
}

#endif
