#include "jkCredits.h"

#include "General/stdStrTable.h"
#include "General/stdFont.h"

void jkCredits_Initialize(char *fpath)
{
    stdStrTable_Load(&jkCredits_table, fpath);
    jkCredits_fontLarge = stdFont_Load("ui\\sft\\creditlarge.sft", 0, 0);
    jkCredits_fontSmall = stdFont_Load("ui\\sft\\creditsmall.sft", 0, 0);
    jkCredits_bInitted = 1;
}

void jkCredits_Shutdown()
{
    if ( jkCredits_fontLarge )
    {
        stdFont_Free(jkCredits_fontLarge);
        jkCredits_fontLarge = 0;
    }
    if ( jkCredits_fontSmall )
    {
        stdFont_Free(jkCredits_fontSmall);
        jkCredits_fontSmall = 0;
    }
    stdStrTable_Free(&jkCredits_table);
    jkCredits_bInitted = 0;
}