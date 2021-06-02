#include "Win95/wuRegistry.h"

#include "jk.h"

#ifdef LINUX

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
    
    return 1;
}

int wuRegistry_SaveFloat(LPCSTR lpValueName, float val)
{
    
    return 1;
}

int wuRegistry_GetInt(LPCSTR lpValueName, int a2)
{
    return a2;
}

float wuRegistry_GetFloat(LPCSTR lpValueName, float v5)
{
    return v5;
}

int wuRegistry_SaveBool(LPCSTR lpValueName, HKEY phkResult)
{
    return 1;
}

int wuRegistry_GetBool(LPCSTR lpValueName, int a2)
{
    return a2;
}

int wuRegistry_SaveBytes(LPCSTR lpValueName, BYTE *lpData, DWORD cbData)
{
    return 1;
}

int wuRegistry_GetBytes(LPCSTR lpValueName, DWORD Type, DWORD cbData)
{
    return 1;
}

LSTATUS wuRegistry_SetString(LPCSTR lpValueName, BYTE *lpData)
{
    return 1;
}

int wuRegistry_GetString(LPCSTR lpValueName, LPBYTE lpData, int outSize, char *out)
{

    if (out && out != lpData)
    {
        _strncpy((char *)lpData, out, outSize - 1);
        lpData[outSize - 1] = 0;
    }
    return 0;
}
#endif
