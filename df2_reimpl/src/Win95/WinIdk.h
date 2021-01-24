#ifndef _WINIDK_H
#define _WINIDK_H

#define WinIdk_SetDplayGuid_ADDR (0x00436D50)
#define WinIdk_GetDplayGuid_ADDR (0x00436D80)
#define WinIdk_PrintConsole_ADDR (0x00436D90)
#define WinIdk_detect_cpu_ADDR (0x00437930)

static void (*WinIdk_SetDplayGuid)(int *a1) = (void*)WinIdk_SetDplayGuid_ADDR;
static int* (*WinIdk_GetDplayGuid)() = (void*)WinIdk_GetDplayGuid_ADDR;
static int (*WinIdk_PrintConsole)(HWND hWnd, LPARAM lParam, int a3) = (void*)WinIdk_PrintConsole_ADDR;

// this is technically in another file?
static int (*WinIdk_detect_cpu)(char *a1) = (void*)WinIdk_detect_cpu_ADDR;

#endif // _WINIDK_H
