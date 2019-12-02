#include "jk.h"

//VM_VAR(g_thing_three, uint32_t, 0x855DA0);

VM_VAR(g_hWnd, HWND, 0x855DE0);

VM_VAR(g_nShowCmd, uint32_t, 0x855DE8);
VM_VAR(g_hInstance, uint32_t, 0x855DEC);

VM_VAR(g_app_suspended, uint32_t, 0x855E70);
VM_VAR(g_window_active, uint32_t, 0x855E74);
VM_VAR(g_app_active, uint32_t, 0x855E78);
VM_VAR(g_should_exit, uint32_t, 0x855E7C);
VM_VAR(g_thing_two_some_dialog_count, uint32_t, 0x855E80);
VM_VAR(g_handler_count, uint32_t, 0x855E84);

VM_VAR(g_855E8C, uint32_t, 0x855E8C);
VM_VAR(g_855E90, uint32_t, 0x855E90);
VM_VAR(g_window_not_destroyed, uint32_t, 0x855E94);

uint32_t JK::jk_main(uint32_t hInstance, uint32_t hPrevInstance, uint32_t lpCmdLine, uint32_t nShowCmd, vm_ptr<char*> lpWindowName)
{
    int result;
    WNDCLASSEXA wndClass;

    g_handler_count = 0;
    g_thing_two_some_dialog_count = 0;
    g_should_exit = 0;
    g_window_not_destroyed = 0;
    g_hInstance = hInstance;
    g_nShowCmd = nShowCmd;

    wndClass.cbSize = 48;
    wndClass.hInstance = hInstance;
    wndClass.lpszClassName = (vm_ptr<char*>)0x54F684 /*aWkernel*/;
    wndClass.lpszMenuName = 0;
    wndClass.lpfnWndProc = wm_msg_main_handler;
    wndClass.style = 3;
    wndClass.hIcon = user32->LoadIconA(hInstance, 0x54F68C /*APPICON*/);
    if ( !wndClass.hIcon )
        wndClass.hIcon = user32->LoadIconA(0, 32512);
    wndClass.hIconSm = user32->LoadIconA(hInstance, 0x54F694);
    if ( !wndClass.hIconSm )
        wndClass.hIconSm = user32->LoadIconA(0, 32512);
    wndClass.hCursor = user32->LoadCursorA(0, 0x7F00);
    wndClass.cbClsExtra = 0;
    wndClass.cbWndExtra = 0;
    wndClass.hbrBackground = gdi32->GetStockObject(4);

    if (user32->RegisterClassExA(&wndClass))
    {
        if ( user32->FindWindowA(0x54F69C/*"wKernel", ClassName*/, lpWindowName) )
            _exit(-1);

        uint32_t hres = user32->GetSystemMetrics(1);
        uint32_t vres = user32->GetSystemMetrics(0);
        g_hWnd = user32->CreateWindowExA(0x40000u, "wKernel" /*0x54F6A4*/, lpWindowName.translated(), 0x90000000, 0, 0, vres, hres, 0, 0, hInstance, 0);

        if (g_hWnd)
        {
            g_hInstance = (int)hInstance;
            user32->ShowWindow(g_hWnd, 1);
            user32->UpdateWindow(g_hWnd);
        }
    }

    sub_436D10(g_hWnd);
    sub_436D30(g_hInstance);
    comctl32->InitCommonControls();

    g_855E8C = 2 * user32->GetSystemMetrics(32);
    uint32_t metrics_32 = user32->GetSystemMetrics(32);
    g_855E90 = user32->GetSystemMetrics(15) + 2 * metrics_32;
    result = sub_401000(lpCmdLine);

    if (!result) return result;

    struct tagMSG msg;
    g_window_not_destroyed = 1;

    while (1)
    {
        if (user32->PeekMessageA(&msg, 0, 0, 0, 0))
        {
            if (!user32->GetMessageA(&msg, 0, 0, 0))
            {
                result = msg.wParam;
                g_should_exit = 1;
                break;
            }

            uint32_t some_cnt = 0;
            if (g_thing_two_some_dialog_count > 0)
            {
#if 0
                v16 = &thing_three;
                do
                {
                    //TODO if ( user32->IsDialogMessageA(*v16, &msg) )
                    //  break;
                    ++some_cnt;
                    ++v16;
                }
                while ( some_cnt < g_thing_two_some_dialog_count );
#endif
            }

            if (some_cnt == g_thing_two_some_dialog_count)
            {
                user32->TranslateMessage(&msg);
                user32->DispatchMessageA(&msg);
            }

            if (!user32->PeekMessageA(&msg, 0, 0, 0, 0))
            {
                result = 0;
                if ( g_should_exit )
                    return result;
            }
        }

        if (user32->stopping) break;

        other_window_stuff();
    }

    return result;
}
