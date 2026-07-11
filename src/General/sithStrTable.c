#include "sithStrTable.h"

#include "General/stdStrTable.h"
#include "Main/jkStrings.h" // openjkdf2_i8n override
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

char16_t* sithStrTable_GetUniString(const char *key)
{
    char16_t* result = NULL;
#ifdef QOL_IMPROVEMENTS
    if (!result) {
        result = stdStrTable_GetValue(&jkStrings_tableExtOver, key);
    }
#endif
    if (!result) {
        result = stdStrTable_GetValue(&sithStrTable_pSithStrings, key);
    }
    return result;
}

char16_t* sithStrTable_GetUniStringWithFallback(char *key)
{
    char16_t* result = NULL;
#ifdef QOL_IMPROVEMENTS
    if (!result) {
        result = stdStrTable_GetValue(&jkStrings_tableExtOver, key);
    }
#endif
    if (!result) {
        result = stdStrTable_GetValueOrKey(&sithStrTable_pSithStrings, key);
    }
    return result;
}
