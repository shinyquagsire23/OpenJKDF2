#include "jkCutscene.h"

#include "General/stdStrTable.h"
#include "General/stdFont.h"

void jkCutscene_Initialize(char *fpath)
{
    stdStrTable_Load(&jkCutscene_strings, fpath);
    jkCutscene_subtitlefont = stdFont_Load("ui\\sft\\subtitlefont.sft", 0, 0);
    jkCutscene_rect1.x = 10;
    jkCutscene_rect2.y = 10;
    jkCutscene_rect1.y = 360;
    jkCutscene_rect1.width = 620;
    jkCutscene_rect1.height = 120;
    jkCutscene_rect2.x = 0;
    jkCutscene_rect2.width = 640;
    jkCutscene_rect2.height = 40;
    jkCutscene_bInitted = 1;
}
