#include "advapi32.h"

#include "vm.h"

uint32_t AdvApi32::RegCreateKeyExA(uint32_t a, char* subkey, uint32_t c, uint32_t d, uint32_t e, uint32_t f, uint32_t g, uint32_t h, uint32_t i)
{
    printf("STUB: AdvApi32::RegCreateKeyExA(subkey %s, ...)\n", subkey);
        
    return 1; //not success
}

uint32_t AdvApi32::RegOpenKeyExA(uint32_t keyHnd, char* subkey, uint32_t c, uint32_t d, uint32_t* phkResult)
{
    printf("STUB: AdvApi32::RegOpenKeyExA(keyHnd %x, subkey %s, ...)\n", keyHnd, subkey);

    *phkResult = hKeyCnt++;

    return 0;
}

uint32_t AdvApi32::RegQueryValueExA(uint32_t keyHnd, char* valuename, uint32_t c, uint32_t lpType, void* lpData, uint32_t *lpcbData)
{
    printf("STUB: AdvApi32::RegQueryValueExA(keyHnd %x, valuename %s, ...)\n", keyHnd, valuename);

    //TODO write data

    if (!strcmp(valuename, "b3DAccel"))
    {
        *(uint32_t*)lpData = 1;
        return 0;
    }
    else if (!strcmp(valuename, "bHighResGraphicsInstall"))
    {
        *(uint32_t*)lpData = 1;
        return 0;
    }
    else if (!strcmp(valuename, "viewSize"))
    {
        *(uint32_t*)lpData = 9;
        return 0;
    }
    else if (!strcmp(valuename, "displayDeviceGUID"))
    {
        memset(lpData, 0x61, *lpcbData);
        return 0;
    }
    else if (!strcmp(valuename, "3DDeviceGUID"))
    {
        uint8_t id[0x10] = {0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62};
        memcpy(lpData, id, *lpcbData);
        return 0;
    }
    else if (!strcmp(valuename, "displayMode"))
    {
        *(uint32_t*)lpData = 2;
        return 0;
    }
    else if (!strcmp(valuename, "InstallType"))
    {
        *(uint32_t*)lpData = 9;
        return 0;
    }
    else if (!strcmp(valuename, "InstallData"))
    {
        *(uint32_t*)lpData = 1;
        return 0;
    }

    return 1; //TODO error
}

uint32_t AdvApi32::RegCloseKey(uint32_t keyHnd)
{
    printf("STUB: AdvApi32::RegCloseKey(keyhnd %x)\n", keyHnd);

    return 0; //TODO error
}

/*uint32_t ComCtl32::(uint32_t )
{
}*/
