#ifndef JK_H
#define JK_H

#include <QObject>
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
        //vm_hook_register("JK.EXE", "WinMain", 0x41EBD0);
        //vm_hook_register("JK.EXE", "jk_main", 0x50E750);

        // Switching between HLE and VM is sloooowwww
        //vm_hook_register("JK", "_atoi", 0x512840);
        //vm_hook_register("JK", "_strtok", 0x512850);

        //vm_hook_register("JK", "verify_key", 0x40EBB0);
        //vm_hook_register("JK", "test", 0x42A4B5);

        // nop out b3DAccel set to 0 for 16bpp render
        /*((uint8_t*)vm_ptr_to_real_ptr(0x414897))[0] = 0x90;
        ((uint8_t*)vm_ptr_to_real_ptr(0x414897))[1] = 0x90;
        ((uint8_t*)vm_ptr_to_real_ptr(0x414897))[2] = 0x90;
        ((uint8_t*)vm_ptr_to_real_ptr(0x414897))[3] = 0x90;
        ((uint8_t*)vm_ptr_to_real_ptr(0x414897))[4] = 0x90;
        ((uint8_t*)vm_ptr_to_real_ptr(0x414897))[5] = 0x90;
        ((uint8_t*)vm_ptr_to_real_ptr(0x414897))[6] = 0x90;
        ((uint8_t*)vm_ptr_to_real_ptr(0x414897))[7] = 0x90;
        ((uint8_t*)vm_ptr_to_real_ptr(0x414897))[8] = 0x90;
        ((uint8_t*)vm_ptr_to_real_ptr(0x414897))[9] = 0x90;*/
        
        //((uint8_t*)vm_ptr_to_real_ptr(0x414852))[0] = 0x00;
        //((uint8_t*)vm_ptr_to_real_ptr(0x414852))[1] = 0x90;
        //((uint8_t*)vm_ptr_to_real_ptr(0x414858))[0] = 0x00;
        //((uint8_t*)vm_ptr_to_real_ptr(0x414858))[1] = 0x90;
    }
    
    Q_INVOKABLE uint32_t WinMain(uint32_t hInstance, uint32_t hPrevInstance, uint32_t lpCmdLine, uint32_t nShowCmd)
    {
        jk_main(hInstance, hPrevInstance, lpCmdLine, nShowCmd, (vm_ptr<char*>)0x53c624);

        return 0;
    }
    
    Q_INVOKABLE uint32_t jk_main(uint32_t hInstance, uint32_t hPrevInstance, uint32_t lpCmdLine, uint32_t nShowCmd, vm_ptr<char*> lpWindowName);

    Q_INVOKABLE uint32_t _atoi(char* a)
    {
        return atoi(a);
    }

    Q_INVOKABLE uint32_t _strtok(char* a, char* b)
    {
        return real_ptr_to_vm_ptr(strtok(a, b));
    }

    Q_INVOKABLE void test()
    {
        for (int i = 0; i < 0x10; i++)
        {
            printf("aaa %x\n", vm_reg_read(UC_X86_REG_EBP));
            //printf("aaa %x+%x %x\n", vm_reg_read(UC_X86_REG_EAX), i*4, *(uint32_t*)(vm_ptr_to_real_ptr(vm_reg_read(UC_X86_REG_EAX)+i*4)));
        }
        vm_stop();
        while(1);
    }

    /*Q_INVOKABLE uint32_t verify_key(uint32_t a)
    {
        printf("aaaaaaaaaaaaaa\n");
        return 0;
    }*/

//    Q_INVOKABLE uint32_t ();
};

#endif // JK_H
