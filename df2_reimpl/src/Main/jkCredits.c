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
