#include "DebugConsole.h"

#include "jk.h"

#ifdef LINUX
void DebugConsole_PrintUniStr(wchar_t* s)
{
    printf("STUB: DebugConsole_PrintUniStr\n");
}

void DebugConsole_Print(char* s)
{
    printf("%s", s);
}

void DebugConsole_AdvanceLogBuf()
{
}

void DebugConsole_AlertSound()
{
}
#endif
