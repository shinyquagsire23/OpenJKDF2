#include "sithSprite.h"

#include "Primitives/rdSprite.h"
#include "World/sithWorld.h"
#include "General/stdHashtbl.h"
#include "General/stdConffile.h"
#include "General/stdString.h"
#include "stdPlatform.h"
#include "jk.h"

int sithSprite_Startup()
{
    sithSprite_pHashtable = stdHashtbl_New(128);
    if (sithSprite_pHashtable)
        return 1;
    stdPrintf(pSithHS->errorPrint, ".\\World\\sithSprite.c", 63, "Failed to allocate memory for sprites.\n", 0, 0, 0, 0);
    return 0;
}

void sithSprite_Shutdown()
{
    if ( sithSprite_pHashtable )
    {
        stdHashtbl_Free(sithSprite_pHashtable);
        sithSprite_pHashtable = 0;
    }
}

int sithSprite_ReadStaticSpritesListText(SithWorld *pWorld, int bSkip)
{
    int sprites_amt;

    if (bSkip)
        return 0;

    stdConffile_ReadArgs();
    if ( _memcmp(stdConffile_g_entry.aArgs[0].value, "world", 6u) || _memcmp(stdConffile_g_entry.aArgs[1].value, "sprites", 8u) )
        return 0;
    sprites_amt = _atoi(stdConffile_g_entry.aArgs[2].value);
    if ( !sprites_amt )
        return 1;

    if ( !sithSprite_AllocWorldSprites(pWorld, sprites_amt) )
    {
        stdPrintf(pSithHS->errorPrint, ".\\World\\sithSprite.c", 163, "Memory error while reading sprites, line %d.\n", stdConffile_linenum, 0, 0, 0);
        return 0;
    }
    
    sithWorld_UpdateLoadProgress(70.0);
    
    flex_t loadPercent = 70.0;
    if ( stdConffile_ReadArgs() )
    {
        while ( _memcmp(stdConffile_g_entry.aArgs[0].value, "end", 4u) )
        {
            if ( !sithSprite_Load(stdConffile_g_entry.aArgs[1].value) )
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
                    stdConffile_g_entry.aArgs[1].value);
                return 0;
            }
            flex_t percentDelta = 10.0 / (flex_d_t)sprites_amt;
            loadPercent += percentDelta;
            sithWorld_UpdateLoadProgress(loadPercent);
            if ( !stdConffile_ReadArgs() )
                break;
        }
    }
    sithWorld_UpdateLoadProgress(80.0);
    return 1;
}

void sithSprite_FreeWorldSprites(SithWorld *pWorld)
{
    if (!pWorld->sizeSprites)
        return;

    for (int idx = 0; idx < pWorld->numSprites; idx++)
    {
        stdHashtbl_Remove(sithSprite_pHashtable, pWorld->aSprites[idx].path);
        rdSprite_FreeEntry(&pWorld->aSprites[idx]);
    }
    SITH_FREE(pWorld->aSprites);
    pWorld->aSprites = 0;
    pWorld->numSprites = 0;
    pWorld->sizeSprites = 0;
}

rdSprite* sithSprite_Load(char *pName)
{
    SithWorld *world;
    rdSprite *result;
    rdSprite *sprite;
    char spriteFpath[128];

    world = sithWorld_g_pLastLoadedWorld;
    result = (rdSprite *)stdHashtbl_Find(sithSprite_pHashtable, pName);
    if ( !result )
    {
        uint32_t idx = world->numSprites;
        if ( idx < world->sizeSprites )
        {
            sprite = &world->aSprites[idx];
            _sprintf(spriteFpath, "%s%c%s", "misc\\spr", '\\', pName);
            if ( stdConffile_Open(spriteFpath) )
            {
                if ( stdConffile_ReadArgs() && stdConffile_g_entry.numArgs >= 0xBu )
                {
                    rdVector3 off;
                    char mat[32];

                    stdString_SafeStrCopy(mat, stdConffile_g_entry.aArgs[0].value, 0x20);
                    uint32_t type_id = _atoi(stdConffile_g_entry.aArgs[1].value);
                    flex32_t width = _atof(stdConffile_g_entry.aArgs[2].value);
                    flex32_t height = _atof(stdConffile_g_entry.aArgs[3].value);
                    int geometryMode = _atoi(stdConffile_g_entry.aArgs[4].value);
                    int lightMode = _atoi(stdConffile_g_entry.aArgs[5].value);
                    int textureMode = _atoi(stdConffile_g_entry.aArgs[6].value);
                    flex32_t extralight = _atof(stdConffile_g_entry.aArgs[7].value);
                    off.x = _atof(stdConffile_g_entry.aArgs[8].value);
                    off.y = _atof(stdConffile_g_entry.aArgs[9].value);
                    off.z = _atof(stdConffile_g_entry.aArgs[10].value);
                    stdConffile_Close();
                    if ( type_id <= 2 && width > 0.0 && height > 0.0 )
                    {
                        
                        if ( rdSprite_NewEntry(sprite, pName, type_id, mat, width, height, geometryMode, lightMode, textureMode, extralight, &off) )
                        {
                            stdHashtbl_Add(sithSprite_pHashtable, sprite->path, sprite);
                            ++world->numSprites;
                            return sprite;
                        }
                        else {
                            jk_printf("OpenJKDF2: Failed to create sprite `%s`! rdSprite_NewEntry failed.\n", spriteFpath);
                        }
                    }
                    else { // Added
                        jk_printf("OpenJKDF2: Failed to read sprite `%s`! type_id %x > 2? width %f (%s) height %f (%s)\n", spriteFpath, type_id, (flex32_t)width, stdConffile_g_entry.aArgs[2].value, (flex32_t)height, stdConffile_g_entry.aArgs[3].value);
                    }
                }
                else // Added
                {
                    jk_printf("OpenJKDF2: Failed to read sprite `%s`! NumArgs %x < 0xB?\n", spriteFpath, stdConffile_g_entry.numArgs);
                    stdConffile_Close();
                }
            }
            else if ( _memcmp(pName, "default.spr", 0xCu) )
            {
                return sithSprite_Load("default.spr");
            }
            else { // Added
                jk_printf("OpenJKDF2: Failed to open sprite `%s`!\n", spriteFpath);
            }
        }
        else { // Added
            jk_printf("OpenJKDF2: Failed allocate sprite `%s`! numSpritesLoaded < numSprites -> %x < %x failed\n", pName, world->numSprites, world->sizeSprites);
        }
    }
    return result;
}

int sithSprite_AllocWorldSprites(SithWorld *pWorld, int size)
{
    rdSprite *aSprites; // edi

    aSprites = (rdSprite *)SITH_ALLOC(sizeof(rdSprite) * size);
    pWorld->aSprites = aSprites;
    if ( !aSprites )
        return 0;
    pWorld->sizeSprites = size;
    pWorld->numSprites = 0;
    _memset(aSprites, 0, sizeof(rdSprite) * size);
    return 1;
}
