#include "jkHudInv.h"

#include "stdPlatform.h"
#include "Cog/sithCog.h"
#include "World/sithInventory.h"
#include "Main/Main.h"
#include "jk.h"

int jkHudInv_Initialize()
{
    _memset(jkHudInv_idkItems, 0, 14 * sizeof(int)); // sizeof(jkHudInv_idkItems)
    return 1;
}

int jkHudInv_items_init()
{
    int v1; // ecx
    sithItemDescriptor *v2; // eax
    int *v3; // edx
    int v4; // ecx
    sithItemDescriptor *v5; // eax

    _sprintf(std_genBuffer, "misc\\%s", "items.dat");
    if (!jkHudInv_ItemDatLoad(std_genBuffer))
        return 0;

    sithInventory_KeybindInit();
    v1 = 0;
    v2 = sithInventory_aDescriptors;
    jkHudInv_numItems = 0;
    for (int i = 0; i < 200; i++)
    {
        if ( (v2->flags & 8) != 0 )
            ++v1;
        ++v2;
    }

    jkHudInv_numItems = v1;
    if ( v1 > 0 )
    {
        jkHudInv_aItems = (int*)pHS->alloc(sizeof(int) * v1);
        if (!jkHudInv_aItems)
        {
            jkHudInv_numItems = 0;
            return 0;
        }
        v3 = jkHudInv_aItems;
        v4 = 0;
        v5 = sithInventory_aDescriptors;
        for (int i = 0; i < 200; i++)
        {
            if ( (v5->flags & 8) != 0 )
                *v3++ = v4;
            ++v5;
            ++v4;
        }
    }
    return 1;
}

int jkHudInv_ItemDatLoad(char *fpath)
{
    unsigned int binNum; // esi
    unsigned int v3; // ebp
    sithCog *cog_; // eax
    sithCog *cog; // [esp+10h] [ebp-10h]
    float max; // [esp+18h] [ebp-8h]
    float min; // [esp+1Ch] [ebp-4h]
    int flags;

    if (!stdConffile_OpenRead(fpath))
        return 0;

    while ( stdConffile_ReadArgs() )
    {
        flags = 0;
        cog = 0;
        if ( !_strcmp(stdConffile_entry.args[0].value, "end") )
            break;
        if ( stdConffile_entry.numArgs < 4u || (binNum = _atoi(stdConffile_entry.args[1].value), binNum >= 0xC8) )
        {
            stdConffile_Close();
            return 0;
        }
        min = _atof(stdConffile_entry.args[2].value);
        max = _atof(stdConffile_entry.args[3].value);
        _sscanf(stdConffile_entry.args[4].value, "%x", &flags);

        for (v3 = 5; v3 < stdConffile_entry.numArgs; v3++)
        {
            if ( !_strcmp(stdConffile_entry.args[v3].key, "cog") )
            {
                cog_ = sithCog_LoadCogscript(stdConffile_entry.args[v3].value);
                if ( cog_ )
                    cog_->flags |= 0x40u;
                cog = cog_;
            }
        }
        sithInventory_NewEntry(binNum, cog, stdConffile_entry.args[0].value, min, max, flags);
    }
    stdConffile_Close();
    return 1;
}
