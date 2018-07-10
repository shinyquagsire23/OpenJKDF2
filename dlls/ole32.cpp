#include "ole32.h"

#include "uc_utils.h"
#include "winutils.h"

#include "main.h"

uint32_t Ole32::CoInitialize(uint32_t a)
{
    return 1;
}

uint32_t Ole32::CoCreateInstance(uint8_t* rclsid, void* pUnkOuter, void* dwClsContext, uint8_t* riid, uint32_t* ppv)
{
    std::string rclsidStr = guid_to_string(rclsid);
    std::string riidStr = guid_to_string(riid);
    printf("STUB: CoCreatInstance:\nrclsid %s\nriid   %s\n", rclsidStr.c_str(), riidStr.c_str());
    
    if (rclsidStr == "d1eb6d20-8923-11d0-9d97-00a0c90a43cb")
    {
        if (riidStr == "133efe40-32dc-11d0-9cfb-00a0c90a43cb")
        {
            printf("IDirectPlay3 instance created\n");
            *ppv = CreateInterfaceInstance("IDirectPlay3", 47);
        }
    }
    else if (rclsidStr == "d8f1eee0-f634-11cf-8700-00a0245d918b")
    {
        if (riidStr == "279afa83-4981-11ce-a521-0020af0be560")
        {
            printf("IDirectSound instance created\n");
            *ppv = CreateInterfaceInstance("IDirectSound", 11);
        }
    }
    
    return 1;
}

/*uint32_t Ole32::(uint32_t )
{
}*/
