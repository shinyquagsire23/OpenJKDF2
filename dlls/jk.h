#ifndef JK_H
#define JK_H

#include <QObject>
#include "main.h"

#define window_related_2(...) vm_call_func(0x50E750, __VA_ARGS__)

class JK : public QObject
{
Q_OBJECT

private:

public:

    Q_INVOKABLE JK() {}
    
    void hook()
    {
        register_hook("JK", "WinMain", 0x41EBD0);
        //register_hook("JK", "verify_key", 0x40EBB0);
    }
    
    Q_INVOKABLE uint32_t WinMain(uint32_t hInstance, uint32_t hPrevInstance, uint32_t lpCmdLine, int nShowCmd)
    {
        window_related_2(hInstance, hPrevInstance, lpCmdLine, nShowCmd, 0x53c624);

        return 0;
    }
    
    /*Q_INVOKABLE uint32_t verify_key(uint32_t a)
    {
        printf("aaaaaaaaaaaaaa\n");
        return 0;
    }*/

//    Q_INVOKABLE uint32_t ();
};

#endif // JK_H
