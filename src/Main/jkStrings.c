#include "jkStrings.h"

#include "General/stdStrTable.h"
#include "Cog/jkCog.h"

static int jkStrings_bInitialized;
static stdStrTable jkstrings_hashmap;

int jkStrings_Startup()
{
    int result; // eax

    result = stdStrTable_Load(&jkstrings_hashmap, "ui\\jkstrings.uni");
    jkStrings_bInitialized = 1;
    return result;
}

void jkStrings_Shutdown()
{
    stdStrTable_Free(&jkstrings_hashmap);
    jkStrings_bInitialized = 0;
}

wchar_t* jkStrings_GetText2(const char *key)
{
    wchar_t *result; // eax

    result = stdStrTable_GetUniString(&jkstrings_hashmap, key);
    if ( !result )
        result = stdStrTable_GetUniString(&jkCog_strings, key);
    return result;
}

wchar_t* jkStrings_GetText(const char *key)
{
    wchar_t *result; // eax

    result = stdStrTable_GetUniString(&jkstrings_hashmap, key);
    if ( !result )
        result = stdStrTable_GetStringWithFallback(&jkCog_strings, (char *)key);
    return result;
}

int jkStrings_unused_sub_40B490()
{
    return 1;
}
