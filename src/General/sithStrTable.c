#include "sithStrTable.h"

#include "General/stdStrTable.h"
#include "jk.h"

static int sithStrTable_bInitted;
static stdStrTable sithStrTable_pSithStrings;

int sithStrTable_Startup()
{
    stdStrTable_Load(&sithStrTable_pSithStrings, "misc\\sithStrings.uni");
    sithStrTable_bInitted = 1;
    return 1;
}

void sithStrTable_Shutdown()
{
    stdStrTable_Free(&sithStrTable_pSithStrings);
    sithStrTable_bInitted = 0;

    // Added: clean reset
    _memset(&sithStrTable_pSithStrings, 0, sizeof(sithStrTable_pSithStrings));
}

wchar_t* sithStrTable_GetUniString(const char *key)
{
    return stdStrTable_GetUniString(&sithStrTable_pSithStrings, key);
}

wchar_t* sithStrTable_GetString(char *key)
{
    return stdStrTable_GetStringWithFallback(&sithStrTable_pSithStrings, key);
}
