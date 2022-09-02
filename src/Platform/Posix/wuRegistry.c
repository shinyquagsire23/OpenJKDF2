#include "Platform/wuRegistry.h"

#include "General/stdJSON.h"

#include "jk.h"

LSTATUS wuRegistry_Startup(HKEY hKey, LPCSTR lpSubKey, BYTE *lpData)
{
    wuRegistry_bInitted = 1;
    return 0;
}

void wuRegistry_Shutdown()
{
    wuRegistry_bInitted = 0;
}

int wuRegistry_SaveInt(LPCSTR lpValueName, int val)
{
    stdJSON_SaveInt("registry.json", lpValueName, val);
    return 1;
}

int wuRegistry_SaveFloat(LPCSTR lpValueName, float val)
{
    return stdJSON_SaveFloat("registry.json", lpValueName, val);
}

int wuRegistry_GetInt(LPCSTR lpValueName, int defaultVal)
{
    return stdJSON_GetInt("registry.json", lpValueName, defaultVal);
}

float wuRegistry_GetFloat(LPCSTR lpValueName, float defaultVal)
{
    return stdJSON_GetFloat("registry.json", lpValueName, defaultVal);
}

int wuRegistry_SaveBool(LPCSTR lpValueName, int bVal)
{
    return stdJSON_SaveBool("registry.json", lpValueName, bVal);
}

int wuRegistry_GetBool(LPCSTR lpValueName, int bDefaultVal)
{
    return stdJSON_GetBool("registry.json", lpValueName, bDefaultVal);
}

int wuRegistry_SaveBytes(LPCSTR lpValueName, BYTE *lpData, DWORD cbData)
{
    return stdJSON_SaveBytes("registry.json", lpValueName, lpData, cbData);
}

int wuRegistry_GetBytes(LPCSTR lpValueName, BYTE *lpData, DWORD cbData)
{
    return stdJSON_GetBytes("registry.json", lpValueName, lpData, cbData);
}

int wuRegistry_SetString(LPCSTR lpValueName, const char *lpData)
{
    return stdJSON_SetString("registry.json", lpValueName, lpData);
}

int wuRegistry_GetString(LPCSTR lpValueName, char* lpData, int outSize, const char *outDefault)
{
    return stdJSON_GetString("registry.json", lpValueName, lpData, outSize, outDefault);
}

int wuRegistry_SetWString(LPCSTR lpValueName, const wchar_t *lpData)
{
    return stdJSON_SetWString("registry.json", lpValueName, lpData);
}

int wuRegistry_GetWString(LPCSTR lpValueName, wchar_t* lpData, int outSize, const wchar_t *outDefault)
{
    return stdJSON_GetWString("registry.json", lpValueName, lpData, outSize, outDefault);
}