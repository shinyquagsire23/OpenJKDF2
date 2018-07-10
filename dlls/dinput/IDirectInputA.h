
#ifndef IDIRECTINPUTA_H
#define IDIRECTINPUTA_H

#include <QObject>
#include <unicorn/unicorn.h>

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
    Q_INVOKABLE void CreateDevice(void* this_ptr, uint32_t a, uint32_t b, uint32_t c){}
    Q_INVOKABLE void EnumDevices(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d){}
    Q_INVOKABLE void GetDeviceStatus(void* this_ptr, uint32_t a){}
    Q_INVOKABLE void RunControlPanel(void* this_ptr, uint32_t a, uint32_t b){}
    Q_INVOKABLE void Initialize(void* this_ptr, uint32_t a, uint32_t b){}

//    Q_INVOKABLE uint32_t ();
};

#endif // IDIRECTINPUTA_H
