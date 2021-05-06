#ifndef _WINIDK_H
#define _WINIDK_H

#include "types.h"

#define WinIdk_SetDplayGuid_ADDR (0x00436D50)
#define WinIdk_GetDplayGuid_ADDR (0x00436D80)
#define WinIdk_PrintConsole_ADDR (0x00436D90)
#define WinIdk_detect_cpu_ADDR (0x00437930)

void WinIdk_SetDplayGuid(int *guid);
uint32_t *__cdecl WinIdk_GetDplayGuid();
int WinIdk_detect_cpu(char *a1);

static int (*WinIdk_PrintConsole)(HWND hWnd, LPARAM lParam, int a3) = (void*)WinIdk_PrintConsole_ADDR;

// this is technically in another file?
//static int (*WinIdk_detect_cpu)(char *a1) = (void*)WinIdk_detect_cpu_ADDR;

#define WinIdk_aDplayGuid ((uint32_t*)0x008607F0)

#endif // _WINIDK_H
