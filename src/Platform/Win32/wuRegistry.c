#include "Platform/wuRegistry.h"

#include <windows.h>

#include "jk.h"

LSTATUS wuRegistry_Startup(HKEY hKey, LPCSTR lpSubKey, BYTE *lpData)
{
    LSTATUS result; // eax
    LSTATUS v6; // esi
    BOOL v7; // edi
    HKEY v8; // [esp+4Ch] [ebp-94h] BYREF
    HKEY phkResult; // [esp+50h] [ebp-90h] BYREF
    DWORD cbData; // [esp+54h] [ebp-8Ch] BYREF
    DWORD dwDisposition; // [esp+58h] [ebp-88h] BYREF
    DWORD Type; // [esp+5Ch] [ebp-84h] BYREF
    BYTE Data[128]; // [esp+60h] [ebp-80h] BYREF

    wuRegistry_bInitted = 1;
    wuRegistry_lpSubKey = lpSubKey;
    wuRegistry_hKey = hKey;
    result = RegCreateKeyExA(hKey, lpSubKey, 0, wuRegistry_lpClass, 0, 0xF003Fu, 0, &phkResult, &dwDisposition);
    v6 = result;
    if ( !result )
    {
        RegOpenKeyExA(wuRegistry_hKey, wuRegistry_lpSubKey, 0, 0xF003Fu, &v8);
        cbData = 128;
        v7 = RegQueryValueExA(v8, "Version", 0, &Type, Data, &cbData) == 0;
        result = RegCloseKey(v8);
        if ( v7 )
        {
            result = _strcmpi((const char *)Data, (const char *)lpData);
            if ( result )
            {
                RegDeleteKeyA(wuRegistry_hKey, wuRegistry_lpSubKey);
                result = RegCreateKeyExA(wuRegistry_hKey, wuRegistry_lpSubKey, 0, wuRegistry_byte_855EB4, 0, 0xF003F, 0, &phkResult, &dwDisposition);
                v6 = result;
            }
        }
    }
    if ( !v6 )
    {
        RegOpenKeyExA(wuRegistry_hKey, wuRegistry_lpSubKey, 0, 0xF003Fu, &v8);
        RegSetValueExA(v8, "Version", 0, 1u, lpData, _strlen((const char *)lpData));
        RegCloseKey(v8);
        result = RegCloseKey(phkResult);
    }
    return result;
}

void wuRegistry_Shutdown()
{
    wuRegistry_bInitted = 0;
}

int wuRegistry_SaveInt(LPCSTR lpValueName, int val)
{
    HKEY phkResult; // [esp+0h] [ebp-4h] BYREF

    if ( RegOpenKeyExA(wuRegistry_hKey, wuRegistry_lpSubKey, 0, 0xF003Fu, &phkResult) )
        return 0;
    RegSetValueExA(phkResult, lpValueName, 0, 3u, (const BYTE *)&val, 4u);
    RegCloseKey(phkResult);
    return 1;
}

int wuRegistry_SaveFloat(LPCSTR lpValueName, flex_t val)
{
    HKEY v2; // ecx
    HKEY phkResult; // [esp+0h] [ebp-4h] BYREF

    v2 = 0; // Added: fix undef
    phkResult = v2;
    if ( RegOpenKeyExA(wuRegistry_hKey, wuRegistry_lpSubKey, 0, 0xF003Fu, &phkResult) )
        return 0;
    RegSetValueExA(phkResult, lpValueName, 0, 3u, (const BYTE *)&val, 4u); // FLEXTODO
    RegCloseKey(phkResult);
    return 1;
}

int wuRegistry_GetInt(LPCSTR lpValueName, int a2)
{
    HKEY phkResult; // [esp+0h] [ebp-Ch] BYREF
    DWORD cbData; // [esp+4h] [ebp-8h] BYREF
    BYTE Data[4]; // [esp+8h] [ebp-4h] BYREF

    if ( !RegOpenKeyExA(wuRegistry_hKey, wuRegistry_lpSubKey, 0, 0xF003Fu, &phkResult) )
    {
        cbData = 4;
        if ( !RegQueryValueExA(phkResult, lpValueName, 0, (LPDWORD)&lpValueName, Data, &cbData) )
        {
            RegCloseKey(phkResult);
            return *(int*)Data;
        }
        RegCloseKey(phkResult);
    }
    return a2;
}

flex_t wuRegistry_GetFloat(LPCSTR lpValueName, flex_t v5)
{
    HKEY phkResult; // [esp+0h] [ebp-Ch] BYREF
    DWORD cbData; // [esp+4h] [ebp-8h] BYREF
    BYTE Data[4]; // [esp+8h] [ebp-4h] BYREF

    if ( !RegOpenKeyExA(wuRegistry_hKey, wuRegistry_lpSubKey, 0, 0xF003Fu, &phkResult) )
    {
        cbData = 4;
        if ( !RegQueryValueExA(phkResult, lpValueName, 0, (LPDWORD)&lpValueName, Data, &cbData) )
        {
            RegCloseKey(phkResult);
            return *(flex_t *)Data; // FLEXTODO
        }
        RegCloseKey(phkResult);
    }
    return v5;
}

int wuRegistry_SaveBool(LPCSTR lpValueName, int bDefault)
{
    intptr_t Data = 0; // [esp+0h] [ebp-4h] BYREF
    HKEY hkResult;

    Data = (intptr_t)bDefault;
    if ( RegOpenKeyExA(wuRegistry_hKey, wuRegistry_lpSubKey, 0, 0xF003Fu, &hkResult) )
        return 0;
    RegSetValueExA(hkResult, lpValueName, 0, REG_BINARY, &Data, 4u);
    RegCloseKey(hkResult);
    return 1;
}

int wuRegistry_GetBool(LPCSTR lpValueName, int a2)
{
    HKEY phkResult; // [esp+0h] [ebp-Ch] BYREF
    DWORD cbData; // [esp+4h] [ebp-8h] BYREF
    int Data; // [esp+8h] [ebp-4h] BYREF

    if ( !RegOpenKeyExA(wuRegistry_hKey, wuRegistry_lpSubKey, 0, 0xF003Fu, &phkResult) )
    {
        cbData = 4;
        if ( !RegQueryValueExA(phkResult, lpValueName, 0, (LPDWORD)&lpValueName, &Data, &cbData) )
        {
            RegCloseKey(phkResult);
            return Data;
        }
        RegCloseKey(phkResult);
    }
    return a2;
}

int wuRegistry_SaveBytes(LPCSTR lpValueName, BYTE *lpData, DWORD cbData)
{
    HKEY phkResult; // [esp+0h] [ebp-4h] BYREF

    if ( RegOpenKeyExA(wuRegistry_hKey, wuRegistry_lpSubKey, 0, 0xF003Fu, &phkResult) )
        return 0;
    RegSetValueExA(phkResult, lpValueName, 0, REG_BINARY, lpData, cbData);
    RegCloseKey(phkResult);
    return 1;
}

int wuRegistry_GetBytes(LPCSTR lpValueName, BYTE *lpDefaultData, DWORD defaultDataSize)
{
    HKEY phkResult; // [esp+0h] [ebp-4h] BYREF
    DWORD Type;

    if ( !RegOpenKeyExA(wuRegistry_hKey, wuRegistry_lpSubKey, 0, 0xF003Fu, &phkResult) )
    {
        if ( !RegQueryValueExA(phkResult, lpValueName, 0, &Type, lpDefaultData, &defaultDataSize) )
        {
            RegCloseKey(phkResult);
            return 1;
        }
        RegCloseKey(phkResult);
    }
    return 0;
}

int wuRegistry_SetString(LPCSTR lpValueName, const char *lpData)
{
    HKEY phkResult; // [esp+0h] [ebp-4h] BYREF

    RegOpenKeyExA(wuRegistry_hKey, wuRegistry_lpSubKey, 0, 0xF003Fu, &phkResult);
    RegSetValueExA(phkResult, lpValueName, 0, REG_SZ, lpData, _strlen(lpData));
    return RegCloseKey(phkResult);
}

int wuRegistry_GetString(LPCSTR lpValueName, char* lpData, int outSize, const char *outDefault)
{
    int result; // eax
    HKEY phkResult; // [esp+8h] [ebp-Ch] BYREF
    DWORD cbData; // [esp+Ch] [ebp-8h] BYREF
    DWORD Type; // [esp+10h] [ebp-4h] BYREF

    RegOpenKeyExA(wuRegistry_hKey, wuRegistry_lpSubKey, 0, 0xF003Fu, &phkResult);
    cbData = outSize;
    if (RegQueryValueExA(phkResult, lpValueName, 0, &Type, lpData, &cbData))
    {
        if (outDefault)
        {
            _strncpy(lpData, outDefault, outSize - 1);
            lpData[outSize - 1] = 0;
        }
        RegCloseKey(phkResult);
        result = 0;
    }
    else
    {
        RegCloseKey(phkResult);
        result = 1;
    }
    return result;
}

int wuRegistry_SetWString(LPCSTR lpValueName, const wchar_t *lpData)
{
    HKEY phkResult; // [esp+0h] [ebp-4h] BYREF

    RegOpenKeyExA(wuRegistry_hKey, wuRegistry_lpSubKey, 0, 0xF003Fu, &phkResult);
    RegSetValueExA(phkResult, lpValueName, 0, REG_SZ, lpData, _wcslen(lpData) * sizeof(wchar_t));
    return RegCloseKey(phkResult);
}

int wuRegistry_GetWString(LPCSTR lpValueName, wchar_t* lpData, int outSize, const wchar_t *outDefault)
{
    int result; // eax
    HKEY phkResult; // [esp+8h] [ebp-Ch] BYREF
    DWORD cbData; // [esp+Ch] [ebp-8h] BYREF
    DWORD Type; // [esp+10h] [ebp-4h] BYREF

    RegOpenKeyExA(wuRegistry_hKey, wuRegistry_lpSubKey, 0, 0xF003Fu, &phkResult);
    cbData = outSize * sizeof(wchar_t);
    if (RegQueryValueExA(phkResult, lpValueName, 0, &Type, lpData, &cbData))
    {
        if (outDefault)
        {
            _wcsncpy(lpData, outDefault, outSize - 1);
            lpData[outSize - 1] = 0;
        }
        RegCloseKey(phkResult);
        result = 0;
    }
    else
    {
        RegCloseKey(phkResult);
        result = 1;
    }
    return result;
}
