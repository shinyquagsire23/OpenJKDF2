#include "jkGUIMultiTally.h"

#include "General/Darray.h"
#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "General/stdStrTable.h"
#include "General/stdFileUtil.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "stdPlatform.h"
#include "jk.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUI.h"
#include "Gui/jkGUIDialog.h"
#include "Gameplay/sithPlayer.h"
#include "World/jkPlayer.h"
#include "Main/jkStrings.h"
#include "Win95/stdDisplay.h"
#include "General/stdString.h"
#include "Dss/sithMulti.h"

static jkGuiElement jkGuiMultiTally_buttons[92] = {
    { ELEMENT_TEXT, 0, 2, "GUI_MULTIPLAYER_SCORE", 3, { 90, 20, 460, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 2, NULL, 3, { 0, 50, 640, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 2, "GUI_NAME", 3, { 20, 90, 200, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 2, "GUI_SCORE", 3, { 220, 90, 90, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 2, "GUI_KILLS", 3, { 310, 90, 90, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 2, "GUI_DEATHS", 3, { 400, 90, 90, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 2, "GUI_SUICIDES", 3, { 490, 90, 90, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 20, 120, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 20, 140, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 20, 160, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 20, 180, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 20, 200, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 20, 220, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 20, 240, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 20, 260, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 20, 280, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 20, 300, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 20, 320, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 20, 340, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 20, 360, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 20, 380, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 20, 400, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 20, 420, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 220, 120, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 220, 140, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 220, 160, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 220, 180, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 220, 200, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 220, 220, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 220, 240, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 220, 260, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 220, 280, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 220, 300, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 220, 320, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 220, 340, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 220, 360, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 220, 380, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 220, 400, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 220, 420, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 310, 120, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 310, 140, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 310, 160, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 310, 180, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 310, 200, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 310, 220, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 310, 240, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 310, 260, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 310, 280, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 310, 300, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 310, 320, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 310, 340, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 310, 360, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 310, 380, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 310, 400, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 310, 420, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 400, 120, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 400, 140, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 400, 160, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 400, 180, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 400, 200, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 400, 220, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 400, 240, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 400, 260, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 400, 280, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 400, 300, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 400, 320, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 400, 340, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 400, 360, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 400, 380, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 400, 400, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 400, 420, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 490, 120, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 490, 140, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 490, 160, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 490, 180, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 490, 200, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 490, 220, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 490, 240, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 490, 260, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 490, 280, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 490, 300, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 490, 320, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 490, 340, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 490, 360, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 490, 380, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 490, 400, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 490, 420, 90, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 2, NULL, 3, { 550, 20, 90, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 245, 440, 150, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXTBUTTON, -1, 2, "GUI_QUIT", 3, { 0, 440, 150, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXTBUTTON, 1, 2, "GUI_OK", 3, { 490, 440, 150, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_END, 0, 0, NULL, 0, { 0, 0, 0, 0 }, 0, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 }
};

static jkGuiMenu jkGuiMultiTally_menu = {
    jkGuiMultiTally_buttons, -1, 65535, 65535, 15, NULL, NULL, jkGui_stdBitmaps, jkGui_stdFonts, 0, jkGuiMultiTally_sub_4188B0, "thermloop01.wav", "thrmlpu2.wav", NULL, NULL, NULL, 0, NULL, NULL
};

static jkGuiMenu jkGuiMultiTally_menu2 = {
    jkGuiMultiTally_buttons, -1, 65535, 65535, 15, NULL, NULL, jkGui_stdBitmaps, jkGui_stdFonts, 0, jkGuiMultiTally_sub_4188B0, "thermloop01.wav", "thrmlpu2.wav", NULL, NULL, NULL, 0, NULL, NULL
};

static jkGuiElement jkGuiMultiTally_buttons3[18] = {
    { ELEMENT_TEXT, 0, 2, "GUI_TEAM_SCORE", 3, { 0, 20, 640, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 0, 50, 640, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 2, "GUI_TEAM", 3, { 150, 90, 210, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 2, "GUI_SCORE", 3, { 360, 90, 90, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 150, 120, 210, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 150, 150, 210, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 150, 180, 210, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 150, 210, 210, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 150, 240, 210, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 360, 120, 90, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 360, 150, 90, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 360, 180, 90, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 360, 210, 90, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 360, 240, 90, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXT, 0, 0, NULL, 3, { 245, 440, 150, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXTBUTTON, -1, 2, "GUI_QUIT", 3, { 0, 440, 150, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_TEXTBUTTON, 1, 2, "GUI_OK", 3, { 490, 440, 150, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
    { ELEMENT_END, 0, 0, NULL, 0, { 0, 0, 0, 0 }, 0, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 }
};

static jkGuiMenu jkGuiMultiTally_menu3 = {
    jkGuiMultiTally_buttons3, -1, 65535, 65535, 15, NULL, NULL, jkGui_stdBitmaps, jkGui_stdFonts, 0, jkGuiMultiTally_sub_4188B0, "thermloop01.wav", "thrmlpu2.wav", NULL, NULL, NULL, 0, NULL, NULL
};

static wchar_t jkGuiMultiTally_waTmp[64];
static uint32_t jkGuiMultiTally_msStart;
static int jkGuiMultiTally_dword_5568D0;
static int jkGuiMultiTally_idkType;

// MOTS altered?
int jkGuiMultiTally_Show(int a1)
{
    int result; // eax
    unsigned int v2; // ebp
    sithPlayerInfo* pPlayerInfoIter2; // ecx
    int v4; // edx
    unsigned int v5; // eax
    jkGuiElement* pElementIter; // esi
    sithPlayerInfo* pPlayerInfoIter; // edi
    int v8; // ebp
    int v9; // eax
    int v10; // ecx
    int v11; // edx
    int v12; // eax
    jkGuiElement* v14; // eax
    int v15; // edi
    int v16; // eax
    int v17; // esi
    wchar_t *v18; // eax
    unsigned int v19; // ecx
    jkGuiElement* v20; // esi
    sithPlayerInfo* v21; // edi
    int v22; // ebp
    int v23; // ecx
    int v24; // edx
    int v25; // eax
    int v26; // ecx
    jkGuiElement* v27; // eax
    int v28; // edi
    int v29; // eax
    wchar_t *v30; // eax
    wchar_t *v31; // [esp-4h] [ebp-29EA4h]
    wchar_t *v32; // [esp-4h] [ebp-29EA4h]
    int v33; // [esp+10h] [ebp-29E90h]
    wchar_t *v34; // [esp+10h] [ebp-29E90h]
    unsigned int v35; // [esp+14h] [ebp-29E8Ch]
    unsigned int v36; // [esp+14h] [ebp-29E8Ch]
    int v37; // [esp+18h] [ebp-29E88h]
    unsigned int v38; // [esp+18h] [ebp-29E88h]
    wchar_t *v39; // [esp+1Ch] [ebp-29E84h]
    wchar_t wtmp5[1024]; // [esp+20h] [ebp-29E80h] BYREF
    wchar_t wtmp1[1024]; // [esp+820h] [ebp-29680h] BYREF
    wchar_t wtmp2[1024]; // [esp+1020h] [ebp-28E80h] BYREF
    wchar_t wtmp3[1024]; // [esp+1820h] [ebp-28680h] BYREF
    wchar_t wtmp4[1024]; // [esp+2020h] [ebp-27E80h] BYREF
    sithPlayerInfo aPlayerInfoSorted[32]; // [esp+2820h] [ebp-27680h] BYREF

    memset(jkGuiMultiTally_waTmp, 0, 0x40u);
    jkGuiMultiTally_msStart = stdPlatform_GetTimeMsec();
    jkGuiMultiTally_idkType = a1;
    if ( (sithNet_MultiModeFlags & MULTIMODEFLAG_TEAMS) != 0 )
    {
        result = jkGuiMultiTally_ShowTeamScores(a1);
        if ( result == -1 )
            return result;
    }
    jkGui_SetModeMenu(jkGui_stdBitmaps[JKGUI_BM_BK_TALLY]->palette);
    jkGuiMultiTally_buttons[1].wstr = jkGui_sub_412ED0();
    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiMultiTally_menu, &jkGuiMultiTally_buttons[90]);
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiMultiTally_menu, &jkGuiMultiTally_buttons[89]);
    jkGuiRend_SetVisibleAndDraw(&jkGuiMultiTally_buttons[89], &jkGuiMultiTally_menu, a1);

#ifdef QOL_IMPROVEMENTS
    // Added
    uint32_t hack = jkPlayer_playerInfos[0].flags;
    if (stdComm_bIsServer && jkGuiNetHost_bIsDedicated)
        jkPlayer_playerInfos[0].flags = 0;
#endif

    _memcpy(aPlayerInfoSorted, jkPlayer_playerInfos, sizeof(aPlayerInfoSorted));
    _qsort(aPlayerInfoSorted, 0x20u, sizeof(sithPlayerInfo), (int (__cdecl *)(const void *, const void *))jkGuiMultiTally_SortPlayerScore);
    v2 = 0;
    v35 = 0;
    if ( jkPlayer_maxPlayers )
    {
        pPlayerInfoIter2 = &aPlayerInfoSorted[0];
        v4 = jkPlayer_maxPlayers;
        do
        {
            if ( (pPlayerInfoIter2->flags & 2) != 0 && (pPlayerInfoIter2->flags & 4) != 0 )
                ++v2;
            ++pPlayerInfoIter2;
            --v4;
        }
        while ( v4 );
        v35 = v2;
    }
    v33 = v2;
    if ( v2 > 0x10 )
        v33 = 16;
    v5 = v33;
    if ( v33 )
    {
        pElementIter = &jkGuiMultiTally_buttons[23];
        v39 = wtmp5;
        pPlayerInfoIter = &aPlayerInfoSorted[0];
        v8 = 0;
        v37 = v33;
        do
        {
            if ( (pPlayerInfoIter->flags & 2) != 0 && (pPlayerInfoIter->flags & 4) != 0)
            {
                if ( pPlayerInfoIter->net_id == jkPlayer_playerInfos[playerThingIdx].net_id )
                {
                    pElementIter[-16].textType = 1;
                    pElementIter->textType = 1;
                    pElementIter[16].textType = 1;
                    pElementIter[32].textType = 1;
                    pElementIter[48].textType = 1;
                }
                else
                {
                    pElementIter[-16].textType = 0;
                    pElementIter->textType = 0;
                    pElementIter[16].textType = 0;
                    pElementIter[32].textType = 0;
                    pElementIter[48].textType = 0;
                }
                jk_snwprintf(&wtmp2[v8], 0x20u, L"%ls", pPlayerInfoIter);
                v9 = pPlayerInfoIter->score;
                //pElementIter[-16].hoverId = (intptr_t)&wtmp2[v8]; BUG?
                pElementIter[-16].wstr = &wtmp2[v8];
                jk_snwprintf(&wtmp4[v8], 0x20u, L"%d", v9);
                v10 = pPlayerInfoIter->numKills;
                pElementIter->wstr = &wtmp4[v8];
                jk_snwprintf(v39, 0x20u, L"%d", v10);
                v11 = pPlayerInfoIter->numKilled;
                pElementIter[16].wstr = v39;
                jk_snwprintf(&wtmp1[v8], 0x20u, L"%d", v11);
                v12 = pPlayerInfoIter->numSuicides;
                pElementIter[32].wstr = &wtmp1[v8];
                jk_snwprintf(&wtmp3[v8], 0x20u, L"%d", v12);
                pElementIter[48].wstr = &wtmp3[v8];
            }
            else
            {
                pElementIter[-16].hoverId = 0;
                pElementIter->wstr = 0;
                pElementIter[16].wstr = 0;
                pElementIter[32].wstr = 0;
                pElementIter[48].wstr = 0;
            }
            ++pPlayerInfoIter;
            v8 += 32;
            ++pElementIter;
            v39 += 32;
        }
        while ( --v37 != 0 );
        v2 = v35;
        v5 = v33;
    }
    if ( v5 < 0x10 )
    {
        v14 = &jkGuiMultiTally_buttons[v5 + 23];
        do
        {
            v14[-16].wstr = 0;
            v14->wstr = 0;
            v14[16].wstr = 0;
            v14[32].wstr = 0;
            v14[48].wstr = 0;
            v14++;
        }
        while ( v14 < &jkGuiMultiTally_buttons[39] );
    }
    if ( v2 > 0x10 )
        jkGuiMultiTally_buttons[87].wstr = jkStrings_GetUniStringWithFallback("GUI_PAGE1");
    do
    {
        v15 = 1;
        v16 = jkGuiRend_DisplayAndReturnClicked(&jkGuiMultiTally_menu);
        v17 = v16;
        if ( v16 == -1 )
        {
            v31 = jkStrings_GetUniStringWithFallback("GUI_CONFIRM_ABORT");
            v18 = jkStrings_GetUniStringWithFallback("GUI_ABORT_GAME");
            if ( !jkGuiDialog_YesNoDialog(v18, v31) )
                continue;
        }
        else if ( v16 != 1 )
        {
            continue;
        }
        v15 = 0;
    }
    while ( v15 );
    if ( v17 != -1 && v2 > 0x10 )
    {
        v19 = v2 - 16;
        v38 = v2 - 16;
        v20 = &jkGuiMultiTally_buttons[23];
        v34 = wtmp5;
        v21 = &aPlayerInfoSorted[16];
        v22 = 0;
        v36 = v19;
        do
        {
            if ( (v21->flags & 2) != 0 && (v21->flags & 4) != 0 )
            {
                jk_snwprintf(&wtmp2[v22], 0x20u, L"%ls", v21);
                v23 = v21->score;
                //v20[-16].type = (JKGUIELEMENT_T)&wtmp2[v22]; BUG?
                v20[-16].wstr = &wtmp2[v22];
                jk_snwprintf(&wtmp4[v22], 0x20u, L"%d", v23);
                v24 = v21->numKills;
                v20->wstr = &wtmp4[v22];
                jk_snwprintf(v34, 0x20u, L"%d", v24);
                v25 = v21->numKilled;
                v20[16].wstr = v34;
                jk_snwprintf(&wtmp1[v22], 0x20u, L"%d", v25);
                v26 = v21->numSuicides;
                v20[32].wstr = &wtmp1[v22];
                jk_snwprintf(&wtmp3[v22], 0x20u, L"%d", v26);
                v19 = v38;
                v20[48].wstr = &wtmp3[v22];
            }
            else
            {
                v20[-16].wstr = 0;
                v20->wstr = 0;
                v20[16].wstr = 0;
                v20[32].wstr = 0;
                v20[48].wstr = 0;
            }
            ++v21;
            v22 += 32;
            v34 += 32;
            ++v20;
            --v36;
        }
        while ( v36 );
        if ( v19 < 0x10 )
        {
            v27 = &jkGuiMultiTally_buttons[v19 + 23];
            do
            {
                v27[-16].wstr = 0;
                v27->wstr = 0;
                v27[16].wstr = 0;
                v27[32].wstr = 0;
                v27[48].wstr = 0;
                v27++;
            }
            while ( v27 < &jkGuiMultiTally_buttons[39] );
        }
        jkGuiMultiTally_buttons[87].wstr = jkStrings_GetUniStringWithFallback("GUI_PAGE2");
        do
        {
            v28 = 1;
            v29 = jkGuiRend_DisplayAndReturnClicked(&jkGuiMultiTally_menu2);
            v17 = v29;
            if ( v29 == -1 )
            {
                v32 = jkStrings_GetUniStringWithFallback("GUI_CONFIRM_ABORT");
                v30 = jkStrings_GetUniStringWithFallback("GUI_ABORT_GAME");
                if ( jkGuiDialog_YesNoDialog(v30, v32) )
                {
LABEL_50:
                    v28 = 0;
                    continue;
                }
            }
            else if ( v29 == 1 )
            {
                goto LABEL_50;
            }
        }
        while ( v28 );
    }

#ifdef QOL_IMPROVEMENTS
    // Added
    if (stdComm_bIsServer && jkGuiNetHost_bIsDedicated)
        jkPlayer_playerInfos[0].flags = hack;
#endif

    jkGui_SetModeGame();
    return v17;
}

int jkGuiMultiTally_SortPlayerScore(const sithPlayerInfo *pA, const sithPlayerInfo *pB)
{
    int v2; // edx
    int v3; // eax
    int v4; // edi
    int v5; // eax
    int result; // eax

    v2 = 0;
    v3 = pA->flags;
    v4 = 0;
    if ( (v3 & 2) == 0 || (v3 & 4) == 0 )
        v2 = 1;
    v5 = pB->flags;
    if ( (v5 & 2) == 0 || (v5 & 4) == 0 )
        v4 = 1;
    if ( v2 )
        return v4 == 0;
    if ( v4 )
        return -1;
    result = pB->score - pA->score;
    if ( !result )
    {
        result = pB->numKills - pA->numKills;
        if ( !result )
        {
            result = pA->numKilled - pB->numKilled;
            if ( !result )
                result = pA->numSuicides - pB->numSuicides;
        }
    }
    return result;
}

void jkGuiMultiTally_Startup()
{
    jkGui_InitMenu(&jkGuiMultiTally_menu, jkGui_stdBitmaps[JKGUI_BM_BK_TALLY]);
    jkGui_InitMenu(&jkGuiMultiTally_menu2, jkGui_stdBitmaps[JKGUI_BM_BK_TALLY]);
    jkGui_InitMenu(&jkGuiMultiTally_menu3, jkGui_stdBitmaps[JKGUI_BM_BK_TALLY]);
}

void jkGuiMultiTally_Shutdown()
{
    // Added: clean reset
    memset(jkGuiMultiTally_waTmp, 0, sizeof(jkGuiMultiTally_waTmp));

    jkGuiMultiTally_msStart = 0;
    jkGuiMultiTally_dword_5568D0 = 0;
    jkGuiMultiTally_idkType = 0;
}

void jkGuiMultiTally_sub_4188B0(jkGuiMenu *pMenu)
{
    uint32_t v1; // ecx

    if ( jkGuiMultiTally_idkType )
    {
        v1 = stdPlatform_GetTimeMsec() - jkGuiMultiTally_msStart;
        if ( v1 > SCORE_DELAY_MS )
            pMenu->lastClicked = 1;
        if ( v1 / 1000 != jkGuiMultiTally_dword_5568D0 )
        {
            jkGuiMultiTally_dword_5568D0 = v1 / 1000;
            jk_snwprintf(jkGuiMultiTally_waTmp, 0x20u, L"%d", 30 - v1 / 1000);
            if ( pMenu == &jkGuiMultiTally_menu3 )
            {
                jkGuiMultiTally_buttons3[14].wstr = jkGuiMultiTally_waTmp;
                jkGuiRend_UpdateAndDrawClickable(&jkGuiMultiTally_buttons3[14], pMenu, 1);
            }
            else
            {
                jkGuiMultiTally_buttons[88].wstr = jkGuiMultiTally_waTmp;
                jkGuiRend_UpdateAndDrawClickable(&jkGuiMultiTally_buttons[88], pMenu, 1);
            }
        }
    }
}

// MOTS altered
int jkGuiMultiTally_ShowTeamScores(int a1)
{
    int v3; // ecx
    int v7; // esi
    jkGuiElement* pElementIter; // esi
    wchar_t *v9; // ebx
    jkHudTeamScore *v10; // edi
    wchar_t *v11; // eax
    int v12; // esi
    int v13; // eax
    int v14; // edi
    wchar_t *v15; // eax
    wchar_t *v17; // [esp-4h] [ebp-864h]
    jkHudTeamScore aTmpTeamScores[5]; // [esp+10h] [ebp-850h] BYREF
    wchar_t v19[32 * 5]; // [esp+60h] [ebp-800h] BYREF

    jkGuiMultiTally_msStart = stdPlatform_GetTimeMsec();
    jkGuiMultiTally_idkType = a1;
    jkGuiMultiTally_dword_5568D0 = 0;
    jkGui_SetModeMenu(jkGui_stdBitmaps[JKGUI_BM_BK_TALLY]->palette);
    jkGuiRend_SetVisibleAndDraw(&jkGuiMultiTally_buttons3[15], &jkGuiMultiTally_menu3, a1); // MOTS removed?
    jkGuiMultiTally_buttons3[1].wstr = jkGui_sub_412ED0();
    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiMultiTally_menu3, &jkGuiMultiTally_buttons3[16]);
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiMultiTally_menu3, &jkGuiMultiTally_buttons3[15]);

    for (int i = 0; i < 5; i++)
    {
        aTmpTeamScores[i].field_0 = i;
        aTmpTeamScores[i].field_8 = 0;
    }

    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        sithPlayerInfo* pPlayerInfoIter = &jkPlayer_playerInfos[i];
        if ( (pPlayerInfoIter->flags & 4) != 0 )
            aTmpTeamScores[pPlayerInfoIter->teamNum].field_8 = 1;
    }

    for (int i = 0; i < 5; i++)
    {
        aTmpTeamScores[i].score = sithNet_teamScore[i];
    }

    _qsort(aTmpTeamScores, 5u, sizeof(jkHudTeamScore), jkGuiMultiTally_SortTeamScore);
    pElementIter = &jkGuiMultiTally_buttons3[4];
    v9 = v19;
    v10 = aTmpTeamScores;
    do
    {
        if ( v10->field_8 )
        {
            switch ( v10->field_0 )
            {
                case 1:
                    v11 = jkStrings_GetUniStringWithFallback("GUI_RED");
                    break;
                case 2:
                    v11 = jkStrings_GetUniStringWithFallback("GUI_GOLD");
                    break;
                case 3:
                    v11 = jkStrings_GetUniStringWithFallback("GUI_BLUE");
                    break;
                case 4:
                    v11 = jkStrings_GetUniStringWithFallback("GUI_GREEN");
                    break;
                default:
                    v11 = jkStrings_GetUniStringWithFallback("GUI_NONE");
                    break;
            }
            pElementIter->wstr = v11;
            jk_snwprintf(v9, 0x20u, L"%d", v10->score);
            pElementIter[5].wstr = v9;
        }
        else
        {
            pElementIter->wstr = 0;
            pElementIter[5].wstr = 0;
        }
        ++pElementIter;
        ++v10;
        v9 += 32;
    }
    while ( pElementIter < &jkGuiMultiTally_buttons3[9] );
    do
    {
        v12 = 1;
        v13 = jkGuiRend_DisplayAndReturnClicked(&jkGuiMultiTally_menu3);
        v14 = v13;
        if ( v13 == -1 )
        {
            v17 = jkStrings_GetUniStringWithFallback("GUI_CONFIRM_ABORT");
            v15 = jkStrings_GetUniStringWithFallback("GUI_ABORT_GAME");
            if ( !jkGuiDialog_YesNoDialog(v15, v17) )
                continue;
        }
        else if ( v13 != 1 )
        {
            continue;
        }
        v12 = 0;
    }
    while ( v12 );
    jkGui_SetModeGame();
    return v14;
}

int jkGuiMultiTally_SortTeamScore(const void* a, const void* b)
{
    const jkHudTeamScore *pA = (const jkHudTeamScore *)a; 
    const jkHudTeamScore *pB = (const jkHudTeamScore *)b;

    int v2; // eax

    v2 = pA->field_8;
    if ( !v2 && !pB->field_8 )
        return 0;
    if ( !v2 )
        return 1;
    if ( pB->field_8 )
        return pB->score - pA->score;
    return -1;
}