#include "jkStrings.h"

#include "General/stdStrTable.h"
#include "Cog/jkCog.h"
#include "../jk.h"

static int jkStrings_bInitialized = 0;
static stdStrTable jkStrings_table;
#ifdef QOL_IMPROVEMENTS
static stdStrTable jkStrings_tableExt;
stdStrTable jkStrings_tableExtOver;
#endif // QOL_IMPROVEMENTS

int jkStrings_Startup()
{
    // Added: clean reset
    _memset(&jkStrings_table, 0, sizeof(jkStrings_table));

    int result = stdStrTable_Load(&jkStrings_table, "ui\\jkstrings.uni");

    // Added: OpenJKDF2 i8n
#ifdef QOL_IMPROVEMENTS
    _memset(&jkStrings_tableExtOver, 0, sizeof(jkStrings_tableExtOver));
    _memset(&jkStrings_tableExt, 0, sizeof(jkStrings_tableExt));

    stdStrTable_Load(&jkStrings_tableExtOver, "ui\\openjkdf2_i8n.uni");
    stdStrTable_Load(&jkStrings_tableExt, "ui\\openjkdf2.uni");
#endif // QOL_IMPROVEMENTS

    jkStrings_bInitialized = 1;
    return result;
}

void jkStrings_Shutdown()
{
    // Added: OpenJKDF2 i8n
#ifdef QOL_IMPROVEMENTS
    stdStrTable_Free(&jkStrings_tableExtOver);
    stdStrTable_Free(&jkStrings_tableExt);
    _memset(&jkStrings_tableExtOver, 0, sizeof(jkStrings_tableExtOver));
    _memset(&jkStrings_tableExt, 0, sizeof(jkStrings_tableExt));
#endif

    stdStrTable_Free(&jkStrings_table);
    jkStrings_bInitialized = 0;

    // Added: clean reset
    _memset(&jkStrings_table, 0, sizeof(jkStrings_table));
}

wchar_t* jkStrings_GetUniString(const char *key)
{
    wchar_t *result; // eax

    // Added: Allow openjkdf2_i8n.uni to override everything
#ifdef QOL_IMPROVEMENTS
    result = stdStrTable_GetUniString(&jkStrings_tableExtOver, key);
    if ( !result )
#endif
    result = stdStrTable_GetUniString(&jkStrings_table, key);
    if ( !result )
        result = stdStrTable_GetUniString(&jkCog_strings, key);
#ifdef QOL_IMPROVEMENTS
    if ( !result )
        result = stdStrTable_GetUniString(&jkStrings_tableExt, key);
#endif
    return result;
}

wchar_t* jkStrings_GetUniStringWithFallback(const char *key)
{
    wchar_t *result; // eax

    // Added: Allow openjkdf2_i8n.uni to override everything
#ifdef QOL_IMPROVEMENTS
    result = stdStrTable_GetUniString(&jkStrings_tableExtOver, key);
    if ( !result )
#endif
    result = stdStrTable_GetUniString(&jkStrings_table, key);

    // Added: OpenJKDF2 i8n -- stdStrTable_GetStringWithFallback must always be the last lookup
    // because it always succeeds.
#ifdef QOL_IMPROVEMENTS
    if ( !result )
        result = stdStrTable_GetUniString(&jkCog_strings, (char *)key);
    if ( !result )
        result = stdStrTable_GetStringWithFallback(&jkStrings_tableExt, key);
#else
        if ( !result )
        result = stdStrTable_GetStringWithFallback(&jkCog_strings, (char *)key);
#endif
    return result;
}

int jkStrings_unused_sub_40B490()
{
    return 1;
}
