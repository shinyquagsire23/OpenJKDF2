#ifndef DINPUT_H
#define DINPUT_H

#include <QObject>
#include <unicorn/unicorn.h>
#include "dlls/winutils.h"

class DInput : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE DInput() {}
    
    Q_INVOKABLE void DirectInputCreateA(uint32_t hinst, uint32_t dwVersion, uint32_t* lplpDirectInput, void* pUnkOuter)
    {
        *lplpDirectInput = CreateInterfaceInstance("IDirectInputA", 200);
    }

//    Q_INVOKABLE uint32_t ();
};

#endif // DINPUT_H
