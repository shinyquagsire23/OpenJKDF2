#include "jkGUIMultiplayer.h"

#include "Gui/jkGUI.h"

void jkGuiMultiplayer_Initialize()
{
    jkGui_InitMenu(&jkGuiMultiplayer_menu, jkGui_stdBitmaps[2]);
    jkGui_InitMenu(&jkGuiMultiplayer_menu2, jkGui_stdBitmaps[2]);
    jkGui_InitMenu(&jkGuiMultiplayer_menu3, jkGui_stdBitmaps[2]);
    jkGui_InitMenu(&jkGuiMultiplayer_menu4, jkGui_stdBitmaps[2]);
    jkGuiMultiplayer_bInitted = 1;
}

void jkGuiMultiplayer_Shutdown()
{
    jkGuiMultiplayer_bInitted = 0;
}
