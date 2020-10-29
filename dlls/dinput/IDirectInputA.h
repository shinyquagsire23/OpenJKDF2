
#ifndef IDIRECTINPUTA_H
#define IDIRECTINPUTA_H

#include <QObject>
#include "vm.h"
#include "dlls/winutils.h"

typedef struct dinputdevice_ext
{
    uint32_t lpVtbl;
    uint8_t padding[0x200];
    int type;
} dinputdevice_ext;

enum InputDeviceType
{
    InputDeviceType_None,
    InputDeviceType_Keyboard,
    InputDeviceType_Mouse,
};

#define DI_OK 0

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
    Q_INVOKABLE uint32_t CreateDevice(void* this_ptr, uint8_t* rguid, uint32_t *lplpDirectInputDevice, void *pUnkOuter)
    {
        std::string guidStr = guid_to_string(rguid);
        printf("STUB: CreateDevice %s\n", guidStr.c_str());

        *lplpDirectInputDevice = CreateInterfaceInstance("IDirectInputDeviceA", 200);
        
        dinputdevice_ext* obj = (dinputdevice_ext*)vm_ptr_to_real_ptr(*lplpDirectInputDevice);
        if (guidStr == "6f1d2b61-d5a0-11cf-bfc7-444553540000")
        {
            obj->type = InputDeviceType_Keyboard;
        }
        else if (guidStr == "6f1d2b60-d5a0-11cf-bfc7-444553540000")
        {
            obj->type = InputDeviceType_Mouse;
        }
        
        return DI_OK;
    }
    Q_INVOKABLE void EnumDevices(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB: EnumDevices\n");
    }
    
    Q_INVOKABLE void GetDeviceStatus(void* this_ptr, uint32_t a)
    {
        //printf("STUB: GetDeviceStatus\n");
    }
    
    Q_INVOKABLE void RunControlPanel(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void Initialize(void* this_ptr, uint32_t a, uint32_t b){}

//    Q_INVOKABLE uint32_t ();
};

extern IDirectInputA* idirectinputa;

#endif // IDIRECTINPUTA_H
