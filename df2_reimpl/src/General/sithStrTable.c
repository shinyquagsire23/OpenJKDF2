#include "sithStrTable.h"

#include "General/stdStrTable.h"

static int sithStrTable_bInitted;
static stdStrTable pSithStrings;

int sithStrTable_Startup()
{
    stdStrTable_Load(&pSithStrings, "misc\\sithStrings.uni");
    sithStrTable_bInitted = 1;
    return 1;
}

void sithStrTable_Shutdown()
{
    stdStrTable_Free(&pSithStrings);
    sithStrTable_bInitted = 0;
}

wchar_t* sithStrTable_GetUniString(const char *key)
{
    return stdStrTable_GetUniString(&pSithStrings, key);
}

wchar_t* sithStrTable_GetString(char *key)
{
    return stdStrTable_GetString(&pSithStrings, key);
}
