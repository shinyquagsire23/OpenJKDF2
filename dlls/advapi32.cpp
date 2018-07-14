#include "advapi32.h"

#include "vm.h"

uint32_t AdvApi32::RegCreateKeyExA(uint32_t a, uint32_t subkey_ptr, uint32_t c, uint32_t d, uint32_t e, uint32_t f, uint32_t g, uint32_t h, uint32_t i)
{
    std::string subkey = vm_read_string(subkey_ptr);
    printf("Stub: Create key %s\n", subkey.c_str());
        
    return 1; //not success
}

uint32_t AdvApi32::RegOpenKeyExA(uint32_t keyHnd, uint32_t subkey_ptr, uint32_t c, uint32_t d, uint32_t e)
{
    std::string subKey = vm_read_string(subkey_ptr);
    printf("Stub: open key %x, %s\n", keyHnd, subKey.c_str());

    //TODO write handle

    return 0;
}

uint32_t AdvApi32::RegQueryValueExA(uint32_t keyHnd, uint32_t valuename_ptr, uint32_t c, uint32_t d, uint32_t e, uint32_t f)
{
    std::string valueName = vm_read_string(valuename_ptr);
    printf("Stub: open value %x, %s\n", keyHnd, valueName.c_str());

    //TODO write data

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
