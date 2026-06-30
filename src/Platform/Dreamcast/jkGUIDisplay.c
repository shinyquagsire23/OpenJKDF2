// Stub Display-settings GUI for the Sega Dreamcast (KallistiOS).
//
// jkGUIDisplay.c is platform-specific (each backend ships its own, since the
// available display options differ). The Dreamcast has a fixed video mode, so for
// now this is a stub: the menu does nothing. A real menu can be fleshed out later,
// modeled on src/Platform/TWL/jkGUIDisplay.c.

#include "Gui/jkGUIDisplay.h"

#include "stdPlatform.h"
#include "jk.h"

void jkGuiDisplay_Startup()
{
}

void jkGuiDisplay_Shutdown()
{
}

int jkGuiDisplay_Show()
{
    return 0;
}

void jkGuiDisplay_sub_4149C0()
{
}
