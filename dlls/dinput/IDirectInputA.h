
#ifndef IDIRECTINPUTA_H
#define IDIRECTINPUTA_H

#include <QObject>
#include <unicorn/unicorn.h>
#include "dlls/winutils.h"

class IDirectInputA : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE IDirectInputA() {}

    /*** Base ***/
    Q_INVOKABLE void QueryInterface(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void AddRef(void* this_ptr){}
    Q_INVOKABLE void Release(void* this_ptr){}
    
    /*** IDirectInput ***/
    Q_INVOKABLE void CreateDevice(void* this_ptr, uint8_t* rguid, uint32_t *lplpDirectInputDevice, void *pUnkOuter)
    {
        std::string guidStr = guid_to_string(rguid);
        printf("STUB: CreateDevice %s\n", guidStr.c_str());
        
        if (guidStr == "6f1d2b61-d5a0-11cf-bfc7-444553540000")
        {
            printf("STUB: Creating Mouse\n");
        }
        else if (guidStr == "6f1d2b60-d5a0-11cf-bfc7-444553540000")
        {
            printf("STUB: Creating Keyboard\n");
        }
        *lplpDirectInputDevice = CreateInterfaceInstance("IDirectInputDeviceA", 200);
    }
    Q_INVOKABLE void EnumDevices(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB: EnumDevices\n");
    }
    Q_INVOKABLE void GetDeviceStatus(void* this_ptr, uint32_t a)
    {
        printf("STUB: GetDeviceStatus\n");
    }
    Q_INVOKABLE void RunControlPanel(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void Initialize(void* this_ptr, uint32_t a, uint32_t b){}

//    Q_INVOKABLE uint32_t ();
};

extern IDirectInputA* idirectinputa;

#endif // IDIRECTINPUTA_H
