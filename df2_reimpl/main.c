#include <stdint.h>
#include <stdio.h>
#include <windows.h>

#include "hook.h"
#include "jk.h"
#include "types.h"

#include "cog.h"
#include "jkl.h"

int jk_main(uint32_t hInstance, uint32_t hPrevInstance, char* lpCmdLine, int nShowCmd, char* lpWindowName)
{
    int result;
    WNDCLASSEXA wndClass;
    MSG msg;

    g_handler_count = 0;
    g_thing_two_some_dialog_count = 0;
    g_should_exit = 0;
    g_window_not_destroyed = 0;
    g_hInstance = hInstance;
    g_nShowCmd = nShowCmd;

    wndClass.cbSize = 48;
    wndClass.hInstance = hInstance;
    wndClass.lpszClassName = "wKernel";
    wndClass.lpszMenuName = 0;
    wndClass.lpfnWndProc = wm_msg_main_handler;
    wndClass.style = 3;
    wndClass.hIcon = jk_LoadIconA(hInstance, "APPICON");
    if ( !wndClass.hIcon )
        wndClass.hIcon = jk_LoadIconA(0, 32512);
    wndClass.hIconSm = jk_LoadIconA(hInstance, "APPICON");
    if ( !wndClass.hIconSm )
        wndClass.hIconSm = jk_LoadIconA(0, 32512);
    wndClass.hCursor = jk_LoadCursorA(0, 0x7F00);
    wndClass.cbClsExtra = 0;
    wndClass.cbWndExtra = 0;
    wndClass.hbrBackground = jk_GetStockObject(4);

    if (jk_RegisterClassExA(&wndClass))
    {
        if ( jk_FindWindowA("wKernel", lpWindowName) )
            jk_exit(-1);

        uint32_t hres = jk_GetSystemMetrics(1);
        uint32_t vres = jk_GetSystemMetrics(0);
        g_hWnd = jk_CreateWindowExA(0x40000u, "wKernel", lpWindowName, 0x90000000, 0, 0, vres, hres, 0, 0, hInstance, 0);

        if (g_hWnd)
        {
            g_hInstance = (int)hInstance;
            jk_ShowWindow(g_hWnd, 1);
            jk_UpdateWindow(g_hWnd);
        }
    }

    sub_436D10(g_hWnd);
    sub_436D30(g_hInstance);
    jk_InitCommonControls();

    g_855E8C = 2 * jk_GetSystemMetrics(32);
    uint32_t metrics_32 = jk_GetSystemMetrics(32);
    g_855E90 = jk_GetSystemMetrics(15) + 2 * metrics_32;
    result = sub_401000(lpCmdLine);
    
    //jk_printf("aaa %x\n", &msg);

    if (!result) return result;

    
    g_window_not_destroyed = 1;

    while (1)
    {
        jk_printf("aaa %x\n", &msg);
        if (jk_PeekMessageA(&msg, 0, 0, 0, 0))
        {
            if (!jk_GetMessageA(&msg, 0, 0, 0))
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
                    //TODO if ( jk_IsDialogMessageA(*v16, &msg) )
                    //  break;
                    ++some_cnt;
                    ++v16;
                }
                while ( some_cnt < g_thing_two_some_dialog_count );
#endif
            }

            if (some_cnt == g_thing_two_some_dialog_count)
            {
                jk_TranslateMessage(&msg);
                jk_DispatchMessageA(&msg);
            }

            if (!jk_PeekMessageA(&msg, 0, 0, 0, 0))
            {
                result = 0;
                if ( g_should_exit )
                    return result;
            }
        }

        //if (user32->stopping) break;

        other_window_stuff();
    }

    return result;
}

__declspec(dllexport) int WinMain_(uint32_t hInstance, uint32_t hPrevInstance, char* lpCmdLine, int nShowCmd)
{
    jk_main(hInstance, hPrevInstance, lpCmdLine, nShowCmd, "Jedi Knight");
    return 0;
}

__declspec(dllexport) void hook_init(void)
{
    jk_init();
    
    hook_function(WinMain_ADDR, WinMain_);
    hook_function(cog_register_jk_verbs_ADDR, cog_register_jk_verbs);
    hook_function(cog_jk_init_ADDR, cog_jk_init);
    hook_function(cog_init_ADDR, cog_init);
    hook_function(cog_math_verbs_init_ADDR, cog_math_verbs_init);
    hook_function(cog_thing_verbs_init_ADDR, cog_thing_verbs_init);
    hook_function(cog_ai_verbs_init_ADDR, cog_ai_verbs_init);
    hook_function(cog_surface_verbs_init_ADDR, cog_surface_verbs_init);
    hook_function(cog_noise_verbs_init_ADDR, cog_noise_verbs_init);
    hook_function(cog_sector_verbs_init_ADDR, cog_sector_verbs_init);
    hook_function(cog_player_verbs_init_ADDR, cog_player_verbs_init);
    
    hook_function(jkl_init_parsers_ADDR, jkl_init_parsers);
    hook_function(jkl_set_section_parser_ADDR, jkl_set_section_parser);
    hook_function(jkl_find_section_parser_ADDR, jkl_find_section_parser);
}
