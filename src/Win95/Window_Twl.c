#include "Window.h"

#ifdef TARGET_TWL


static int dword_855E98 = 0;
static int dword_855DE4 = 0;

int Window_lastXRel = 0;
int Window_lastYRel = 0;
int Window_lastSampleTime = 0;
int Window_lastSampleMs = 0;
int Window_bMouseLeft = 0;
int Window_bMouseRight = 0;
int Window_resized = 0;
int Window_mouseX = 0;
int Window_mouseY = 0;
int Window_mouseWheelX = 0;
int Window_mouseWheelY = 0;
int Window_lastMouseX = 0;
int Window_lastMouseY = 0;
int Window_xPos = 0;
int Window_yPos = 0;
int last_jkGame_isDDraw = 0;
int last_jkQuakeConsole_bOpen = 0;
int Window_menu_mouseX = 0;
int Window_menu_mouseY = 0;

int Window_Main_Linux(int argc, char** argv)
{
}

int Window_DefaultHandler(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam, void* unused)
{
    return 0;
}

#endif