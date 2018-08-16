#ifndef JK_H
#define JK_H

#include <QObject>
#include "main.h"
#include "user32.h"
#include "gdi32.h"
#include "comctl32.h"

#define HWND uint32_t
#define WNDPROC uint32_t

//TODO: I need some kind of generator for this stuff

#define VM_VAR(name, type, ptr) vm_ptr<type*> name ## _ptr = {ptr};
#define VM_VAR_DECL(name, type) extern vm_ptr<type*> name ## _ptr;

#define g_hWnd *(*g_hWnd_ptr)

#define g_nShowCmd *(g_nShowCmd_ptr.translated())
#define g_hInstance *(g_hInstance_ptr.translated())

#define g_app_suspended *(g_app_suspended_ptr.translated())
#define g_window_active *(g_window_active_ptr.translated())
#define g_app_active *(g_app_active_ptr.translated())
#define g_should_exit *(g_should_exit_ptr.translated())
#define g_thing_two_some_dialog_count *(g_thing_two_some_dialog_count_ptr.translated())
#define g_handler_count *(g_handler_count_ptr.translated())

#define g_855E8C *(*g_855E8C_ptr)
#define g_855E90 *(*g_855E90_ptr)
#define g_window_not_destroyed *(g_window_not_destroyed_ptr.translated())

#define wm_msg_main_handler (0x50ECB0)

VM_VAR_DECL(g_hWnd, HWND);

VM_VAR_DECL(g_nShowCmd, uint32_t);
VM_VAR_DECL(g_hInstance, uint32_t);

VM_VAR_DECL(g_app_suspended, uint32_t);
VM_VAR_DECL(g_window_active, uint32_t);
VM_VAR_DECL(g_app_active, uint32_t);
VM_VAR_DECL(g_should_exit, uint32_t);
VM_VAR_DECL(g_thing_two_some_dialog_count, uint32_t);
VM_VAR_DECL(g_handler_count, uint32_t);

VM_VAR_DECL(g_855E8C, uint32_t);
VM_VAR_DECL(g_855E90, uint32_t);
VM_VAR_DECL(g_window_not_destroyed, uint32_t);

//#define jk_main(...) vm_call_func(0x50E750, __VA_ARGS__)
#define sub_436D10(...) vm_call_func(0x436D10, __VA_ARGS__)
#define sub_436D30(...) vm_call_func(0x436D30, __VA_ARGS__)
#define sub_401000(...) vm_call_func(0x401000, __VA_ARGS__)
#define other_window_stuff() vm_call_function(0x4037E0, 0)
#define _exit(...) vm_call_func(0x512590, __VA_ARGS__)

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
    
    Q_INVOKABLE uint32_t WinMain(uint32_t hInstance, uint32_t hPrevInstance, uint32_t lpCmdLine, uint32_t nShowCmd)
    {
        jk_main(hInstance, hPrevInstance, lpCmdLine, nShowCmd, (vm_ptr<char*>)0x53c624);

        return 0;
    }
    
    Q_INVOKABLE uint32_t jk_main(uint32_t hInstance, uint32_t hPrevInstance, uint32_t lpCmdLine, uint32_t nShowCmd, vm_ptr<char*> lpWindowName);

    /*Q_INVOKABLE uint32_t verify_key(uint32_t a)
    {
        printf("aaaaaaaaaaaaaa\n");
        return 0;
    }*/

//    Q_INVOKABLE uint32_t ();
};

#endif // JK_H
