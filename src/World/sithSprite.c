#include "sithSprite.h"

#include "Primitives/rdSprite.h"
#include "World/sithWorld.h"
#include "General/stdHashTable.h"
#include "General/stdConffile.h"
#include "General/stdString.h"
#include "stdPlatform.h"
#include "jk.h"

int sithSprite_Startup()
{
    sithSprite_hashmap = stdHashTable_New(128);
    if (sithSprite_hashmap)
        return 1;
    stdPrintf(pSithHS->errorPrint, ".\\World\\sithSprite.c", 63, "Failed to allocate memory for sprites.\n", 0, 0, 0, 0);
    return 0;
}

void sithSprite_Shutdown()
{
    if ( sithSprite_hashmap )
    {
        stdHashTable_Free(sithSprite_hashmap);
        sithSprite_hashmap = 0;
    }
}

int sithSprite_Load(sithWorld *world, int a2)
{
    int sprites_amt;

    if (a2)
        return 0;

    stdConffile_ReadArgs();
    if ( _memcmp(stdConffile_entry.args[0].value, "world", 6u) || _memcmp(stdConffile_entry.args[1].value, "sprites", 8u) )
        return 0;
    sprites_amt = _atoi(stdConffile_entry.args[2].value);
    if ( !sprites_amt )
        return 1;

    if ( !sithSprite_New(world, sprites_amt) )
    {
        stdPrintf(pSithHS->errorPrint, ".\\World\\sithSprite.c", 163, "Memory error while reading sprites, line %d.\n", stdConffile_linenum, 0, 0, 0);
        return 0;
    }
    
    sithWorld_UpdateLoadPercent(70.0);
    
    float loadPercent = 70.0;
    if ( stdConffile_ReadArgs() )
    {
        while ( _memcmp(stdConffile_entry.args[0].value, "end", 4u) )
        {
            if ( !sithSprite_LoadEntry(stdConffile_entry.args[1].value) )
            {
                stdPrintf(
                    pSithHS->errorPrint,
                    ".\\World\\sithSprite.c",
                    159,
                    "Parse error while reading sprites, line %d.\n",
                    stdConffile_linenum);
                stdPrintf(
                    pSithHS->errorPrint,
                    ".\\World\\sithSprite.c",
                    159,
                    "OpenJKDF2: Failed sprite was `%s`\n",
                    stdConffile_entry.args[1].value);
                return 0;
            }
            float percentDelta = 10.0 / (double)sprites_amt;
            loadPercent += percentDelta;
            sithWorld_UpdateLoadPercent(loadPercent);
            if ( !stdConffile_ReadArgs() )
                break;
        }
    }
    sithWorld_UpdateLoadPercent(80.0);
    return 1;
}

void sithSprite_FreeEntry(sithWorld *world)
{
    if (!world->numSprites)
        return;

    for (int idx = 0; idx < world->numSpritesLoaded; idx++)
    {
        stdHashTable_FreeKey(sithSprite_hashmap, world->sprites[idx].path);
        rdSprite_FreeEntry(&world->sprites[idx]);
    }
    pSithHS->free(world->sprites);
    world->sprites = 0;
    world->numSpritesLoaded = 0;
    world->numSprites = 0;
}

rdSprite* sithSprite_LoadEntry(char *fpath)
{
    sithWorld *world;
    rdSprite *result;
    rdSprite *sprite;
    char spriteFpath[128];

    world = sithWorld_pLoading;
    result = (rdSprite *)stdHashTable_GetKeyVal(sithSprite_hashmap, fpath);
    if ( !result )
    {
        uint32_t idx = world->numSpritesLoaded;
        if ( idx < world->numSprites )
        {
            sprite = &world->sprites[idx];
            _sprintf(spriteFpath, "%s%c%s", "misc\\spr", '\\', fpath);
            if ( stdConffile_OpenRead(spriteFpath) )
            {
                if ( stdConffile_ReadArgs() && stdConffile_entry.numArgs >= 0xBu )
                {
                    rdVector3 off;
                    char mat[32];

                    stdString_SafeStrCopy(mat, stdConffile_entry.args[0].value, 0x20);
                    uint32_t typeid = _atoi(stdConffile_entry.args[1].value);
                    float width = _atof(stdConffile_entry.args[2].value);
                    float height = _atof(stdConffile_entry.args[3].value);
                    int geometryMode = _atoi(stdConffile_entry.args[4].value);
                    int lightMode = _atoi(stdConffile_entry.args[5].value);
                    int textureMode = _atoi(stdConffile_entry.args[6].value);
                    float extralight = _atof(stdConffile_entry.args[7].value);
                    off.x = _atof(stdConffile_entry.args[8].value);
                    off.y = _atof(stdConffile_entry.args[9].value);
                    off.z = _atof(stdConffile_entry.args[10].value);
                    stdConffile_Close();
                    if ( typeid <= 2 && width > 0.0 && height > 0.0 )
                    {
                        
                        if ( rdSprite_NewEntry(sprite, fpath, typeid, mat, width, height, geometryMode, lightMode, textureMode, extralight, &off) )
                        {
#ifdef DYNAMIC_POV
							sprite->id = world->numSpritesLoaded;
							if (sithWorld_pLoading->level_type_maybe & 1)
							{
							#ifdef STATIC_JKL_EXT
								sprite->id |= world->idx_offset;
							#else
								sprite->id |= 0x8000;
							#endif
							}
#endif
                            stdHashTable_SetKeyVal(sithSprite_hashmap, sprite->path, sprite);
                            ++world->numSpritesLoaded;
                            return sprite;
                        }
                        else {
                            jk_printf("OpenJKDF2: Failed to create sprite `%s`! rdSprite_NewEntry failed.\n", spriteFpath);
                        }
                    }
                    else { // Added
                        jk_printf("OpenJKDF2: Failed to read sprite `%s`! typeid %x > 2? width %f height %f\n", spriteFpath, typeid, width, height);
                    }
                }
                else // Added
                {
                    jk_printf("OpenJKDF2: Failed to read sprite `%s`! NumArgs %x < 0xB?\n", spriteFpath, stdConffile_entry.numArgs);
                    stdConffile_Close();
                }
            }
            else if ( _memcmp(fpath, "default.spr", 0xCu) )
            {
                return sithSprite_LoadEntry("default.spr");
            }
            else { // Added
                jk_printf("OpenJKDF2: Failed to open sprite `%s`!\n", spriteFpath);
            }
        }
        else { // Added
            jk_printf("OpenJKDF2: Failed allocate sprite `%s`! numSpritesLoaded < numSprites -> %x < %x failed\n", fpath, world->numSpritesLoaded, world->numSprites);
        }
    }
    return result;
}

int sithSprite_New(sithWorld *world, int num)
{
    rdSprite *sprites; // edi

    sprites = (rdSprite *)pSithHS->alloc(sizeof(rdSprite) * num);
    world->sprites = sprites;
    if ( !sprites )
        return 0;
    world->numSprites = num;
    world->numSpritesLoaded = 0;
    _memset(sprites, 0, sizeof(rdSprite) * num);
    return 1;
}
