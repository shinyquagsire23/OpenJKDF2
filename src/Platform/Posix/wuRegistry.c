#include "Platform/wuRegistry.h"

#include "General/stdJSON.h"

#include "jk.h"

LSTATUS wuRegistry_Startup(HKEY hKey, LPCSTR lpSubKey, BYTE *lpData)
{
    wuRegistry_bStarted = 1;
    return 0;
}

void wuRegistry_Shutdown()
{
    wuRegistry_bStarted = 0;
}

int wuRegistry_SaveInt(LPCSTR lpValueName, int val)
{
    stdJSON_SaveInt(REGISTRY_FNAME, lpValueName, val);
    return 1;
}

int wuRegistry_SaveFloat(LPCSTR lpValueName, flex_t val)
{
    return stdJSON_SaveFloat(REGISTRY_FNAME, lpValueName, val);
}

int wuRegistry_GetInt(LPCSTR lpValueName, int defaultVal)
{
    return stdJSON_GetInt(REGISTRY_FNAME, lpValueName, defaultVal);
}

flex_t wuRegistry_GetFloat(LPCSTR lpValueName, flex_t defaultVal)
{
    return stdJSON_GetFloat(REGISTRY_FNAME, lpValueName, defaultVal);
}

int wuRegistry_SaveBool(LPCSTR lpValueName, int bVal)
{
    return stdJSON_SaveBool(REGISTRY_FNAME, lpValueName, bVal);
}

int wuRegistry_GetBool(LPCSTR lpValueName, int bDefaultVal)
{
    return stdJSON_GetBool(REGISTRY_FNAME, lpValueName, bDefaultVal);
}

int wuRegistry_SaveBytes(LPCSTR lpValueName, BYTE *lpData, DWORD cbData)
{
    return stdJSON_SaveBytes(REGISTRY_FNAME, lpValueName, lpData, cbData);
}

int wuRegistry_GetBytes(LPCSTR lpValueName, BYTE *lpData, DWORD cbData)
{
    return stdJSON_GetBytes(REGISTRY_FNAME, lpValueName, lpData, cbData);
}

int wuRegistry_SaveStr(LPCSTR lpValueName, const char *lpData)
{
    return stdJSON_SetString(REGISTRY_FNAME, lpValueName, lpData);
}

int wuRegistry_GetStr(LPCSTR lpValueName, char* lpData, int outSize, const char *outDefault)
{
    return stdJSON_GetString(REGISTRY_FNAME, lpValueName, lpData, outSize, outDefault);
}

int wuRegistry_SetWString(LPCSTR lpValueName, const char16_t *lpData)
{
    return stdJSON_SetWString(REGISTRY_FNAME, (const char*)lpValueName, lpData);
}

int wuRegistry_GetWString(LPCSTR lpValueName, char16_t* lpData, int outSize, const char16_t *outDefault)
{
    return stdJSON_GetWString(REGISTRY_FNAME, (const char*)lpValueName, lpData, outSize, outDefault);
}