#include "advapi32.h"

#include "vm.h"

uint32_t AdvApi32::RegCreateKeyExA(uint32_t a, char* subkey, uint32_t c, uint32_t d, uint32_t e, uint32_t f, uint32_t g, uint32_t h, uint32_t i)
{
    printf("Stub: Create key %s\n", subkey);
        
    return 1; //not success
}

uint32_t AdvApi32::RegOpenKeyExA(uint32_t keyHnd, char* subkey, uint32_t c, uint32_t d, uint32_t* phkResult)
{
    printf("Stub: open key %x, %s\n", keyHnd, subkey);

    *phkResult = hKeyCnt++;

    return 0;
}

uint32_t AdvApi32::RegQueryValueExA(uint32_t keyHnd, char* valuename, uint32_t c, uint32_t lpType, void* lpData, uint32_t *lpcbData)
{
    printf("Stub: open value %x, %s\n", keyHnd, valuename);

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
        memset(lpData, 0xAA, *lpcbData);
        return 0;
    }
    else if (!strcmp(valuename, "3DDeviceGUID"))
    {
        memset(lpData, 0xAA, *lpcbData);
        return 0;
    }

    return 1; //TODO error
}

uint32_t AdvApi32::RegCloseKey(uint32_t keyHnd)
{
    printf("Stub: close key %x\n", keyHnd);

    return 0; //TODO error
}

/*uint32_t ComCtl32::(uint32_t )
{
}*/
