#ifndef _WUREGISTRY_H
#define _WUREGISTRY_H

#include "types.h"
#include "globals.h"

#define wuRegistry_Startup_ADDR (0x0050EEB0)
#define wuRegistry_Shutdown_ADDR (0x0050F030)
#define wuRegistry_SaveInt_ADDR (0x0050F040)
#define wuRegistry_SaveFloat_ADDR (0x0050F0A0)
#define wuRegistry_GetInt_ADDR (0x0050F100)
#define wuRegistry_GetFloat_ADDR (0x0050F180)
#define wuRegistry_SaveBool_ADDR (0x0050F200)
#define wuRegistry_GetBool_ADDR (0x0050F260)
#define wuRegistry_SaveBytes_ADDR (0x0050F2E0)
#define wuRegistry_GetBytes_ADDR (0x0050F340)
#define wuRegistry_SetString_ADDR (0x0050F3B0)
#define wuRegistry_GetString_ADDR (0x0050F410)

LSTATUS wuRegistry_Startup(HKEY hKey, LPCSTR lpSubKey, BYTE *lpData);
void wuRegistry_Shutdown();
int wuRegistry_SaveInt(LPCSTR lpValueName, int val);
int wuRegistry_SaveFloat(LPCSTR lpValueName, flex_t val);
int wuRegistry_GetInt(LPCSTR lpValueName, int a2);
flex_t wuRegistry_GetFloat(LPCSTR lpValueName, flex_t v5);
int wuRegistry_SaveBool(LPCSTR lpValueName, int bDefault);
int wuRegistry_GetBool(LPCSTR lpValueName, int a2);
int wuRegistry_SaveBytes(LPCSTR lpValueName, BYTE *lpData, DWORD cbData);
int wuRegistry_GetBytes(LPCSTR lpValueName, BYTE *lpDefaultData, DWORD defaultDataSize);
int wuRegistry_SetString(LPCSTR lpValueName, const char *lpData);
int wuRegistry_GetString(LPCSTR lpValueName, char* lpData, int outSize, const char *outDefault);

int wuRegistry_SetWString(LPCSTR lpValueName, const wchar_t *lpData);
int wuRegistry_GetWString(LPCSTR lpValueName, wchar_t* lpData, int outSize, const wchar_t *outDefault);

//static int (*wuRegistry_SaveFloat)(LPCSTR lpValueName, flex_t val) = (void*)wuRegistry_SaveFloat_ADDR;
//static int (*wuRegistry_SaveInt)(LPCSTR lpValueName, int val) = (void*)wuRegistry_SaveInt_ADDR;
//static int (*wuRegistry_SaveBool)(LPCSTR lpValueName, HKEY phkResult) = (void*)wuRegistry_SaveBool_ADDR;
//static flex_t (*wuRegistry_GetFloat)(LPCSTR lpValueName, flex_t v5) = (void*)wuRegistry_GetFloat_ADDR;
//static int (*wuRegistry_GetInt)(LPCSTR lpValueName, int a2) = (void*)wuRegistry_GetInt_ADDR;
//static LSTATUS (*wuRegistry_SetString)(LPCSTR lpValueName, BYTE *lpData) = (void*)wuRegistry_SetString_ADDR;
//static int (*wuRegistry_GetString)(LPCSTR lpValueName, LPBYTE lpData, int outSize, char *out) = (void*)wuRegistry_GetString_ADDR;

//static void (*wuRegistry_Shutdown)() = (void*)wuRegistry_Shutdown_ADDR;

#endif // _WUREGISTRY_H
