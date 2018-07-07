#include "user32.h"

#include "uc_utils.h"

uint32_t User32::LoadIconA(uint32_t a, uint32_t b)
{
    return 0;
}

uint32_t User32::LoadCursorA(uint32_t a, uint32_t b)
{
    return 0;
}

uint32_t User32::RegisterClassExA(uint32_t a)
{
    return 444;
}

uint32_t User32::FindWindowA(uint32_t a, uint32_t b)
{
    return 0;
}

uint32_t User32::GetSystemMetrics(uint32_t metric)
{        
    switch (metric)
    {
        case 0: //hres
            return 1280;
        case 1: //vres
            return 1024;
        case 15:
        case 32:
            return 0;
        default:
            printf("Unknown metric %x\n", metric);
            return 16;
    }
}

uint32_t User32::CreateWindowExA(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f, uint32_t g, uint32_t h, uint32_t i, uint32_t j, uint32_t k, uint32_t l)
{
    return 333;
}

uint32_t User32::ShowWindow(uint32_t a, uint32_t b)
{
    return 0;
}

uint32_t User32::UpdateWindow(uint32_t a)
{
    return 1;
}

uint32_t User32::GetActiveWindow()
{
    return 333;
}

uint32_t User32::GetLastActivePopup(uint32_t hWnd)
{
    return 123;
}

void User32::MessageBoxA(uint32_t hWnd, uint32_t lpText, uint32_t lpCaption, uint32_t uType)
{
    std::string text = uc_read_string(current_uc, lpText);
    std::string caption = uc_read_string(current_uc, lpCaption);
    
    printf("MessageBoxA: [%s] %s\n", caption.c_str(), text.c_str());
}

void User32::MessageBoxW(uint32_t hWnd, uint32_t lpText, uint32_t lpCaption, uint32_t uType)
{
    std::string text = uc_read_wstring(current_uc, lpText);
    std::string caption = uc_read_wstring(current_uc, lpCaption);
    
    printf("MessageBoxW: [%s] %s\n", caption.c_str(), text.c_str());
}

uint32_t User32::GetDC(uint32_t a)
{
    return 0xefab;
}
  
uint32_t User32::ReleaseDC(uint32_t a, uint32_t b)
{
    return 1;
}
    
uint32_t User32::EnumDisplaySettingsA(uint32_t a, uint32_t b, uint32_t c)
{
    return 1;
}
    
uint32_t User32::ChangeDisplaySettingsA(uint32_t a, uint32_t b)
{
    return 1;
}

uint32_t User32::SetWindowPos(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f, uint32_t g)    
{
    return 1;
}

uint32_t User32::GetDesktopWindow()    
{
    return 0xabcd;
}

/*uint32_t User32::(uint32_t )
{
}*/
