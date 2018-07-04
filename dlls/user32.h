#ifndef USER32_H
#define USER32_H

#include <QObject>
#include <unicorn/unicorn.h>

class User32 : public QObject
{
Q_OBJECT

private:
    uc_engine *uc;

public:

    Q_INVOKABLE User32(uc_engine *uc) : uc(uc) {}
    
    Q_INVOKABLE uint32_t LoadIconA(uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t LoadCursorA(uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t RegisterClassExA(uint32_t a);
    Q_INVOKABLE uint32_t FindWindowA(uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t GetSystemMetrics(uint32_t metric);
    Q_INVOKABLE uint32_t CreateWindowExA(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f, uint32_t g, uint32_t h, uint32_t i, uint32_t j, uint32_t k, uint32_t l);
    Q_INVOKABLE uint32_t ShowWindow(uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t UpdateWindow(uint32_t a);
    Q_INVOKABLE uint32_t GetActiveWindow();
    Q_INVOKABLE uint32_t GetLastActivePopup(uint32_t hWnd);
    Q_INVOKABLE void MessageBoxA(uint32_t hWnd, uint32_t lpText, uint32_t lpCaption, uint32_t uType);
    Q_INVOKABLE void MessageBoxW(uint32_t hWnd, uint32_t lpText, uint32_t lpCaption, uint32_t uType);
    Q_INVOKABLE uint32_t GetDC(uint32_t a);
    Q_INVOKABLE uint32_t ReleaseDC(uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t EnumDisplaySettingsA(uint32_t a, uint32_t b, uint32_t c);
    Q_INVOKABLE uint32_t ChangeDisplaySettingsA(uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t SetWindowPos(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f, uint32_t g);
    Q_INVOKABLE uint32_t GetDesktopWindow();

//    Q_INVOKABLE uint32_t ();
};

#endif // USER32_H
