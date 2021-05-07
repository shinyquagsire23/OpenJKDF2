#include "sithAIClass.h"

#include "General/stdHashTable.h"
#include "jk.h"

int sithAIClass_Startup()
{
    sithAIClass_hashmap = stdHashTable_New(64);
    return sithAIClass_hashmap != 0;
}
