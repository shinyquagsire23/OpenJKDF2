#include "sithSoundClass.h"

#include "stdPlatform.h"
#include "General/stdHashTable.h"

static const char* sithSoundClass_aKeys[96] = {
    "--reserved--",
    "create",
    "activate",
    "startmove",
    "stopmove",
    "moving",
    "lwalkhard",
    "rwalkhard",
    "lrunhard",
    "rrunhard",
    "lwalkmetal",
    "rwalkmetal",
    "lrunmetal",
    "rrunmetal",
    "lwalkwater",
    "rwalkwater",
    "lrunwater",
    "rrunwater",
    "lwalkpuddle",
    "rwalkpuddle",
    "lrunpuddle",
    "rrunpuddle",
    "lwalkearth",
    "rwalkearth",
    "lrunearth",
    "rrunearth",
    "enterwater",
    "enterwaterslow",
    "exitwater",
    "exitwaterslow",
    "lswimsurface",
    "rswimsurface",
    "treadsurface",
    "lswimunder",
    "rswimunder",
    "treadunder",
    "jump",
    "jumpmetal",
    "jumpwater",
    "jumpearth",
    "landhard",
    "landmetal",
    "landwater",
    "landpuddle",
    "landearth",
    "landhurt",
    "hithard",
    "hitmetal",
    "hitearth",
    "deflected",
    "scrapehard",
    "scrapemetal",
    "scrapeearth",
    "hitdamaged",
    "falling",
    "corpsehit",
    "hurtimpact",
    "hurtenergy",
    "hurtfire",
    "hurtmagic",
    "hurtspecial",
    "drowning",
    "choking",
    "death1",
    "death2",
    "deathunder",
    "drowned",
    "splattered",
    "pant",
    "breath",
    "gasp",
    "fire1",
    "fire2",
    "fire3",
    "fire4",
    "curious",
    "alert",
    "idle",
    "gloat",
    "fear",
    "boast",
    "happy",
    "victory",
    "help",
    "flee",
    "search",
    "calm",
    "surprise",
    "reserved1",
    "reserved2",
    "reserved3",
    "reserved4",
    "reserved5",
    "reserved6",
    "reserved7",
    "reserved8",
};

int sithSoundClass_Startup()
{
    sithSoundClass_hashtable = stdHashTable_New(64);
    sithSoundClass_nameToKeyHashtable = stdHashTable_New(192);
    if ( sithSoundClass_hashtable && sithSoundClass_nameToKeyHashtable )
    {
        for (int i = 1; i < 96; i++)
        {
            stdHashTable_SetKeyVal(sithSoundClass_nameToKeyHashtable, sithSoundClass_aKeys[i], (void *)i);
        }
        return 1;
    }
    else
    {
        stdPrintf(pSithHS->errorPrint, ".\\World\\sithSoundClass.c", 214, "Could not allocate hashtable for soundclasses.\n", 0, 0, 0, 0);
        return 0;
    }
}
