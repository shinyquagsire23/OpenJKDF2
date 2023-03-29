#include "jkGUIBuildMulti.h"

#include "General/Darray.h"
#include "General/stdBitmap.h"
#include "General/stdString.h"
#include "General/stdFont.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "stdPlatform.h"
#include "jk.h"
#include "Gui/jkGUIRend.h"
#include "Gui/jkGUI.h"
#include "Gui/jkGUIDialog.h"
#include "General/stdFileUtil.h"
#include "General/stdFnames.h"
#include "Main/jkStrings.h"
#include "World/jkPlayer.h"
#include "General/util.h"
#include "Gui/jkGUITitle.h"
#include "Engine/rdColormap.h"
#include "Win95/stdDisplay.h"
#include "Engine/rdroid.h"
#include "Gui/jkGUIForce.h"
#include "Platform/stdControl.h"
#include "Main/jkRes.h"
#include "General/stdStrTable.h"
#include "Main/jkEpisode.h"
#include "Platform/std3D.h"
#include "Win95/Window.h"

#include "jk.h"
#include "types.h"
#include "types_enums.h"

// MOTS added
int jkGuiBuildMulti_jediRank = 0;

static jkGuiElement jkGuiBuildMulti_buttons[17] =
{
  { ELEMENT_TEXT, 0, 5, "GUI_EDIT_CHARACTER", 3, { 240, 20, 400, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 1, NULL, 3, { 240, 60, 400, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 0, NULL, 3, { 30, 60, 140, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 2, NULL, 3, { 310, 90, 270, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_PICBUTTON, 105, 0, NULL, 33, { 6, 90, 24, 24 }, 1, 0, NULL, NULL, jkGuiBuildMulti_SaberButtonClicked, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_PICBUTTON, 104, 0, NULL, 34, { 170, 90, 24, 24 }, 1, 0, NULL, NULL, jkGuiBuildMulti_SaberButtonClicked, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_CUSTOM, 0, 0, NULL, 0, { 315, 115, 260, 260 }, 1, 0, NULL, jkGuiBuildMulti_ModelDrawer, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_CUSTOM, 0, 0, NULL, 0, { 80, 115, 50, 260 }, 1, 0, NULL, jkGuiBuildMulti_SaberDrawer, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 0, "GUI_MODEL", 3, { 336, 380, 216, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_PICBUTTON, 100, 0, NULL, 33, { 312, 380, 24, 24 }, 1, 0, NULL, NULL, jkGuiBuildMulti_SaberButtonClicked, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_PICBUTTON, 101, 0, NULL, 34, { 552, 380, 24, 24 }, 1, 0, NULL, NULL, jkGuiBuildMulti_SaberButtonClicked, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_PICBUTTON, 102, 0, NULL, 33, { 70, 380, 24, 24 }, 1, 0, NULL, NULL, jkGuiBuildMulti_SaberButtonClicked, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_PICBUTTON, 103, 0, NULL, 34, { 113, 380, 24, 24 }, 1, 0, NULL, NULL, jkGuiBuildMulti_SaberButtonClicked, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXTBUTTON, -1, 2, "GUI_CANCEL", 3, { 20, 430, 170, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXTBUTTON, 109, 2, "GUI_FORCEPOWERS", 3, { 290, 430, 170, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXTBUTTON, 106, 2, "GUI_SAVE", 3, { 470, 430, 170, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_END, 0, 0, NULL, 0, { 0, 0, 0, 0 }, 0, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 }
};



jkGuiMenu jkGuiBuildMulti_menu =
{
    &jkGuiBuildMulti_buttons, -1, 65535, 65535, 15, NULL, NULL, jkGui_stdBitmaps, jkGui_stdFonts, 0, jkGuiBuildMulti_sub_41A120, "thermloop01.wav", "thrmlpu2.wav", NULL, NULL, NULL, 0, NULL, NULL
};



static int listbox_images[2] = {JKGUI_BM_UP_15, JKGUI_BM_DOWN_15};
static int listbox_images2[2] = {JKGUI_BM_UP_15, JKGUI_BM_DOWN_15};

static jkGuiElement jkGuiBuildMulti_menuEditCharacter_buttons[17] =
{
/*00*/  { ELEMENT_TEXT, 0, 0, NULL, 3, { 0, 390, 640, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*01*/  { ELEMENT_TEXT, 0, 5, "GUI_EDIT_CHARACTER", 3, { 240, 20, 400, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*02*/  { ELEMENT_TEXT, 0, 1, NULL, 3, { 240, 60, 400, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*03*/  { ELEMENT_LISTBOX, 1, 0, NULL, 0, { 280, 100, 320, 251 }, 1, 0, NULL, NULL, NULL, listbox_images, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*04*/  { ELEMENT_TEXT, 0, 2, "GUI_NAME", 3, { 0, 130, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*05*/  { ELEMENT_TEXT, 0, 1, NULL, 1, { 0, 150, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  
  // 310, 330
/*06*/  { ELEMENT_TEXT, 0, 2, "GUI_RANKLABEL", 3, { 0, 190, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*07*/  { ELEMENT_TEXT, 0, 1, NULL, 1, { 0, 210, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*08*/  { ELEMENT_TEXT, 0, 2, "GUI_MODEL", 3, { 0, 250, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*09*/  { ELEMENT_TEXT, 0, 1, NULL, 1, { 0, 270, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  
/*10*/  { ELEMENT_TEXT, 0, 2, "GUI_PERSONALITY", 3, { 0, 190, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*11*/  { ELEMENT_TEXT, 0, 1, NULL, 1, { 0, 210, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },

/*12*/  { ELEMENT_TEXTBUTTON, -1, 2, "GUI_DONE", 3, { 30, 430, 128, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*13*/  { ELEMENT_TEXTBUTTON, 100, 2, "GUI_NEW", 3, { 250, 430, 128, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*14*/  { ELEMENT_TEXTBUTTON, 102, 2, "GUI_REMOVE", 3, { 380, 430, 128, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*15*/  { ELEMENT_TEXTBUTTON, 1, 2, "GUI_EDIT", 3, { 510, 430, 130, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*16*/  { ELEMENT_END, 0, 0, NULL, 0, { 0, 0, 0, 0 }, 0, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 }
};

static jkGuiMenu jkGuiBuildMulti_menuEditCharacter =
{
    &jkGuiBuildMulti_menuEditCharacter_buttons, -1, 65535, 65535, 15, NULL, NULL, jkGui_stdBitmaps, jkGui_stdFonts, 0, NULL, "thermloop01.wav", "thrmlpu2.wav", NULL, NULL, NULL, 0, NULL, NULL
};

// 13 -> 16
// 12 -> 15
// 11 -> 14
// 10 -> 13
// 7 -> 8
// 6 -> 7
// 5 -> 6?
// 4 -> 5?
// 2 -> 2
static jkGuiElement jkGuiBuildMulti_menuNewCharacter_buttons[18] =
{
/*00*/  { ELEMENT_TEXT, 0, 0, NULL, 3, { 230, 410, 410, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*01*/  { ELEMENT_TEXT, 0, 5, "GUI_NEW_CHARACTER", 3, { 240, 20, 400, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*02*/  { ELEMENT_TEXT, 0, 1, NULL, 3, { 240, 60, 400, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*03*/  { ELEMENT_TEXT, 0, 2, "GUI_NEW_CHARACTER_CONFIG", 3, { 240, 130, 400, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },

/*04 dummy*/  { ELEMENT_TEXT, 0, 0, L"", 3, { 0, 0, 0, 0 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*05*/  { ELEMENT_TEXT, 0, 2, "GUI_MAXSTARS", 3, { 0, 30, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*06*/  { ELEMENT_TEXT, 0, 0, NULL, 3, { 0, 50, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },

/*07*/  { ELEMENT_TEXT, 0, 2, "GUI_RANKLABEL", 3, { 320, 240, 240, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*08*/  { ELEMENT_TEXT, 0, 0, NULL, 3, { 344, 270, 192, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*09*/  { ELEMENT_PICBUTTON, 103, 0, NULL, 33, { 320, 270, 24, 24 }, 1, 0, NULL, NULL, jkGuiBuildMulti_menuNewCharacter_rankArrowButtonClickHandler, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*10*/  { ELEMENT_PICBUTTON, 104, 0, NULL, 34, { 536, 270, 24, 24 }, 1, 0, NULL, NULL, jkGuiBuildMulti_menuNewCharacter_rankArrowButtonClickHandler, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },

/*11 dummy*/  { ELEMENT_TEXT, 0, 0, L"", 3, { 0, 0, 0, 0 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*12 dummy*/  { ELEMENT_TEXT, 0, 0, L"", 3, { 0, 0, 0, 0 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },

/*13*/  { ELEMENT_TEXT, 0, 2, "GUI_NAME", 3, { 320, 170, 240, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*14*/  { ELEMENT_TEXTBOX, 0, 0, NULL, 0, { 320, 200, 240, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*15*/  { ELEMENT_TEXTBUTTON, -1, 2, "GUI_CANCEL", 3, { 0, 430, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*16*/  { ELEMENT_TEXTBUTTON, 1, 2, "GUI_OK", 3, { 460, 430, 180, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*17*/  { ELEMENT_END, 0, 0, NULL, 0, { 0, 0, 0, 0 }, 0, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 }
};

static jkGuiMenu jkGuiBuildMulti_menuNewCharacter =
{
    &jkGuiBuildMulti_menuNewCharacter_buttons, -1, 65535, 65535, 15, NULL, NULL, jkGui_stdBitmaps, jkGui_stdFonts, 0, NULL, "thermloop01.wav", "thrmlpu2.wav", NULL, NULL, NULL, 0, NULL, NULL
};

static jkGuiElement jkGuiBuildMulti_menuNewCharacter_buttonsMots[18] =
{
/*00*/  { ELEMENT_TEXT,        0,    0,    NULL,    3,    { 0, 100, 200, 320 },    1,    0,    NULL,    NULL,    NULL,    NULL,    { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } },    0 },
/*01*/  { ELEMENT_TEXT,        0,    5,    "GUI_NEW_CHARACTER",    3,    { 240, 15, 400, 50 },    1,    0,    NULL,    NULL,    NULL,    NULL,    { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } },    0 },
/*02*/  { ELEMENT_TEXT,        0,    1,    NULL,    3,    { 240, 60, 400, 30 },    1,    0,    NULL,    NULL,    NULL,    NULL,    { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } },    0 },
/*03*/  { ELEMENT_TEXT,        0,    2,    "GUI_NEW_CHARACTER_CONFIG",    3,    { 240, 110, 400, 20 },    1,    0,    NULL,    NULL,    NULL,    NULL,    { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } },    0 },
/*04*/  { ELEMENT_TEXT,        0,    2,    "GUI_TYPEOFGAME",    2,    { 300, 220, 240, 30 },    1,    0,    NULL,    NULL,    NULL,    NULL,    { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } },    0 },

/*05*/  { ELEMENT_CHECKBOX,    0,    0,    "GUI_TYPEPERSONALITIES",    0,    { 300, 250, 340, 20 },    1,    0,    NULL,    NULL,    jkGuiBuildMulti_FUN_004209b0,    NULL,    { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } },    0 },
/*06*/  { ELEMENT_CHECKBOX,    0,    0,    "GUI_TYPEJEDIONLY",    0,    { 300, 270, 340, 20 },    1,    0,    NULL,    NULL,    jkGuiBuildMulti_FUN_00420930,    NULL,    { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } },    0 },

// TODO jkGuiBuildMulti_waTmpRankLabel
/*07*/  { ELEMENT_TEXT,        0,    2,   "GUI_RANKLABEL",    2,    { 300, 320, 240, 30 },    1,    0,    NULL,    NULL,    NULL,    NULL,    { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } },    0 },
/*08*/  { ELEMENT_TEXT,        0,    0,    NULL,    2,    { 360, 360, 192, 30 },    1,    0,    NULL,    NULL,    NULL,    NULL,    { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } },    0 },
/*09*/  { ELEMENT_PICBUTTON,   103,  0,    NULL,    33,    { 300, 360, 24, 24 },    1,    0,    NULL,    NULL,    jkGuiBuildMulti_menuNewCharacter_rankArrowButtonClickHandler,    NULL,    { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } },    0 },
/*10*/  { ELEMENT_PICBUTTON,   104,  0,    NULL,    34,    { 326, 360, 24, 24 },    1,    0,    NULL,    NULL,    jkGuiBuildMulti_menuNewCharacter_rankArrowButtonClickHandler,    NULL,    { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } },    0 },

/*11*/  { ELEMENT_TEXT,        0,    2,    "GUI_PERSONALITY",    2,    { 300, 310, 240, 30 },    1,    0,    NULL,    NULL,    NULL,    NULL,    { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } },    0 },
/*12*/  { ELEMENT_LISTBOX,     1,    0,    NULL,    0,    { 300, 345, 240, 66 },    1,    0,    NULL,    NULL,    NULL,    listbox_images2,    { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } },    0 },

/*13*/  { ELEMENT_TEXT,        0,    2,    "GUI_NAME",    2,    { 300, 145, 240, 30 },    1,    0,    NULL,    NULL,    NULL,    NULL,    { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } },    0 },
/*14*/  { ELEMENT_TEXTBOX,     0,    0,    NULL,    0,    { 300, 180, 240, 20 },    1,    0,    NULL,    NULL,    NULL,    NULL,    { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } },    0 },
/*15*/  { ELEMENT_TEXTBUTTON, -1,    2,    "GUI_CANCEL",    3,    { 0, 430, 200, 40 },    1,    0,    NULL,    NULL,    NULL,    NULL,    { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } },    0 },
/*16*/  { ELEMENT_TEXTBUTTON,  1,    2,    "GUI_OK",    3,    { 460, 430, 180, 40 },    1,    0,    NULL,    NULL,    NULL,    NULL,    { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } },    0 },
/*17*/  { ELEMENT_END,         0,    0,    NULL,    0,    { 0, 0, 0, 0 },    0,    0,    NULL,    NULL,    NULL,    NULL,    { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } },    0}
};

static jkGuiMenu jkGuiBuildMulti_menuNewCharacterMots =
{
    &jkGuiBuildMulti_menuNewCharacter_buttonsMots, -1, 65535, 65535, 15, NULL, NULL, jkGui_stdBitmaps, jkGui_stdFonts, 0, NULL, "thermloop01.wav", "thrmlpu2.wav", NULL, NULL, NULL, 0, NULL, NULL
};

static jkGuiElement* jkGuiBuildMulti_pNewCharacterElements = jkGuiBuildMulti_menuNewCharacter_buttons;
static jkGuiMenu* jkGuiBuildMulti_pNewCharacterMenu = &jkGuiBuildMulti_menuNewCharacter;

static jkGuiElement jkGuiBuildMulti_menuLoadCharacter_buttons[24] =
{
/*00*/  { ELEMENT_TEXT, 0, 0, NULL, 3, { 0, 390, 640, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*01*/  { ELEMENT_TEXT, 0, 5, "GUI_LOAD_CHARACTER", 3, { 240, 20, 400, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*02*/  { ELEMENT_TEXT, 0, 1, NULL, 3, { 240, 60, 400, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*03*/  { ELEMENT_LISTBOX, 1, 0, NULL, 0, { 280, 100, 320, 251 }, 1, 0, NULL, NULL, NULL, listbox_images, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*04*/  { ELEMENT_TEXT, 0, 2, "GUI_SLEPISODE", 3, { 0, 30, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*05*/  { ELEMENT_TEXT, 0, 0, NULL, 1, { 0, 50, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*06*/  { ELEMENT_TEXT, 0, 2, "GUI_SLLEVEL", 3, { 0, 90, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*07*/  { ELEMENT_TEXT, 0, 0, NULL, 1, { 0, 110, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*08*/  { ELEMENT_TEXT, 0, 2, "GUI_MAXSTARS", 3, { 0, 150, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*09*/  { ELEMENT_TEXT, 0, 0, NULL, 1, { 0, 170, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*10*/  { ELEMENT_TEXT, 0, 2, "GUI_NAME", 3, { 0, 210, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*11*/  { ELEMENT_TEXT, 0, 1, NULL, 1, { 0, 230, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*12*/  { ELEMENT_TEXT, 0, 2, "GUI_RANKLABEL", 3, { 0, 270, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*13*/  { ELEMENT_TEXT, 0, 1, NULL, 1, { 0, 290, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*14*/  { ELEMENT_TEXT, 0, 2, "GUI_MODEL", 3, { 0, 330, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*15*/  { ELEMENT_TEXT, 0, 1, NULL, 1, { 0, 350, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  
/*16*/  { ELEMENT_TEXT, 0, 2, "GUI_PERSONALITY", 3, { 0, 390, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*17*/  { ELEMENT_TEXT, 0, 1, NULL, 1, { 0, 410, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },

/*18*/  { ELEMENT_TEXTBUTTON, -1, 2, "GUI_CANCEL", 3, { 0, 430, 128, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*19*/  { ELEMENT_TEXTBUTTON, 100, 2, "GUI_NEW", 3, { 128, 430, 128, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*20*/  { ELEMENT_TEXTBUTTON, 102, 2, "GUI_REMOVE", 3, { 256, 430, 128, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*21*/  { ELEMENT_TEXTBUTTON, 101, 2, "GUI_EDIT", 3, { 384, 430, 128, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*22*/  { ELEMENT_TEXTBUTTON, 1, 2, "GUI_OK", 3, { 512, 430, 128, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
/*23*/  { ELEMENT_END, 0, 0, NULL, 0, { 0, 0, 0, 0 }, 0, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 }
};



static jkGuiMenu jkGuiBuildMulti_menuLoadCharacter =
{
    &jkGuiBuildMulti_menuLoadCharacter_buttons, -1, 65535, 65535, 15, NULL, NULL, jkGui_stdBitmaps, jkGui_stdFonts, 0, NULL, "thermloop01.wav", "thrmlpu2.wav", NULL, NULL, NULL, 0, NULL, NULL
};

static int jkGuiBuildMulti_bInitted = 0;
static wchar_t jkGuiBuildMulti_wPlayerShortName[64];
static jkPlayerMpcInfo jkGuiBuildMulti_aMpcInfo[32];
static wchar_t jkGuiBuildMulti_wTmp[128];
static wchar_t jkGuiBuildMulti_wTmp2[32];
static wchar_t jkGuiBuildMulti_wTmp3[32];
static wchar_t jkGuiBuildMulti_aWchar_5594C8[48];
static rdMaterialLoader_t jkGuiBuildMulti_fnMatLoader;
static model3Loader_t jkGuiBuildMulti_fnModelLoader;
static keyframeLoader_t jkGuiBuildMulti_fnKeyframeLoader;

static rdCanvas *jkGuiBuildMulti_pCanvas = NULL;
static rdCamera *jkGuiBuildMulti_pCamera = NULL;
static rdModel3 *jkGuiBuildMulti_model = NULL;
static rdModel3 *jkGuiBuildMulti_pModelGun = NULL;
static rdKeyframe *jkGuiBuildMulti_keyframe = NULL;
static rdThing *jkGuiBuildMulti_pThingCamera = NULL;
static rdThing *jkGuiBuildMulti_thing = NULL;
static rdThing *jkGuiBuildMulti_pThingGun = NULL;
static uint32_t jkGuiBuildMulti_startTimeSecs = 0; // Added: float -> u32
static rdColormap jkGuiBuildMulti_colormap;
static rdLight jkGuiBuildMulti_light;
static rdMatrix34 jkGuiBuildMulti_matrix;
static stdVBuffer* jkGuiBuildMulti_pVBuf1 = NULL;
static stdVBuffer* jkGuiBuildMulti_pVBuf2 = NULL;
static int jkGuiBuildMulti_trackNum = 0;
static wchar_t jkGuiBuildMulti_waTmp[128];
static wchar_t jkGuiBuildMulti_waTmp2[32];
static stdBitmap **jkGuiBuildMulti_apSaberBitmaps = NULL;
static jkSaberInfo *jkGame_aSabers = NULL;
static int jkGuiBuildMulti_bSabersLoaded = 0;
static int jkGuiBuildMulti_bEditShowing = 0;
static int jkGuiBuildMulti_numModels = 0;
static int jkGuiBuildMulti_numSabers = 0;
static int jkGuiBuildMulti_saberIdx = 0;
static int jkGuiBuildMulti_modelIdx = 0;
static jkMultiModelInfo *jkGuiBuildMulti_aModels = NULL;
static int jkGuiBuildMulti_renderOptions = 0x103;
static rdVector3 jkGuiBuildMulti_projectRot;
static rdVector3 jkGuiBuildMulti_projectPos;
static stdVBufferTexFmt jkGuiBuildMulti_texFmt;
static rdMatrix34 jkGuiBuildMulti_orthoProjection;
static rdVector3 jkGuiBuildMulti_lightPos;
static uint32_t jkGuiBuildMulti_lastModelDrawMs;

static wchar_t jkGuiBuildMulti_waTmpRankLabel[128+1];

static rdRect jkGuiBuildMulti_rect_5353C8 = {315, 115, 260, 260};

#ifndef QOL_IMPROVEMENTS
#define BUILDMULTI_SWITCH_DELAY_MS (1000)
#else
#define BUILDMULTI_SWITCH_DELAY_MS (10)
#endif

// Added
int jkGuiBuildMulti_bRendering = 0;

void jkGuiBuildMulti_StartupEditCharacter()
{
    jkGui_InitMenu(&jkGuiBuildMulti_menu, jkGui_stdBitmaps[JKGUI_BM_BK_BUILD_MULTI]);
}

void jkGuiBuildMulti_ShutdownEditCharacter()
{
    // Added: clean reset
    jkGuiBuildMulti_jediRank = 0;
    jkGuiBuildMulti_bRendering = 0;

    ;
}

rdModel3* jkGuiBuildMulti_ModelLoader(const char *pCharFpath, int unused)
{
    rdModel3 *pModel; // esi
    char fpath[128]; // [esp+4h] [ebp-80h] BYREF

    __snprintf(fpath, 128, "%s%c%s", "3do", '\\', pCharFpath); // ADDED: sprintf -> snprintf
    pModel = (rdModel3 *)pHS->alloc(sizeof(rdModel3));
    memset(pModel, 0, sizeof(rdModel3));
    return rdModel3_Load(fpath, pModel) != 0 ? pModel : NULL;
}

rdMaterial* jkGuiBuildMulti_MatLoader(const char *pMatFname, int a, int b)
{
    rdMaterial *pMaterial; // esi
    char mat_fpath[128]; // [esp+8h] [ebp-80h] BYREF

    pMaterial = (rdMaterial *)pHS->alloc(sizeof(rdMaterial));
    memset(pMaterial, 0, sizeof(rdMaterial));
    _sprintf(mat_fpath, "3do%cmat%c%s", '\\', '\\', pMatFname);
    if ( !rdMaterial_LoadEntry(mat_fpath, pMaterial, 0, 0) )
    {
        _sprintf(mat_fpath, "mat%c%s", '\\', pMatFname);
        rdMaterial_LoadEntry(mat_fpath, pMaterial, 0, 0);
    }
    return pMaterial;
}

rdKeyframe* jkGuiBuildMulti_KeyframeLoader(const char *pKeyframeFname)
{
    rdKeyframe *pKeyframe; // esi
    char key_fpath[128]; // [esp+4h] [ebp-80h] BYREF

    pKeyframe = (rdKeyframe *)pHS->alloc(sizeof(rdKeyframe));
    memset(pKeyframe, 0, sizeof(rdKeyframe));
    _sprintf(key_fpath, "3do%ckey%c%s", '\\', '\\', pKeyframeFname);
    rdKeyframe_LoadEntry(key_fpath, pKeyframe);
    return pKeyframe;
}

void jkGuiBuildMulti_CloseRender()
{
    rdMaterial_RegisterLoader(jkGuiBuildMulti_fnMatLoader);
    rdModel3_RegisterLoader(jkGuiBuildMulti_fnModelLoader);
    rdKeyframe_RegisterLoader(jkGuiBuildMulti_fnKeyframeLoader);
    rdThing_Free(jkGuiBuildMulti_pThingGun);
    rdModel3_Free(jkGuiBuildMulti_pModelGun);
    rdLight_FreeEntry(&jkGuiBuildMulti_light);
    rdThing_Free(jkGuiBuildMulti_pThingCamera);
    rdCanvas_Free(jkGuiBuildMulti_pCanvas);
    rdCamera_Free(jkGuiBuildMulti_pCamera);
    stdDisplay_VBufferFree(jkGuiBuildMulti_pVBuf1);
    stdDisplay_VBufferFree(jkGuiBuildMulti_pVBuf2);
    rdColormap_FreeEntry(&jkGuiBuildMulti_colormap);
    rdClose();
}

void jkGuiBuildMulti_ThingInit(char *pModelFpath)
{
    rdPuppet *pPuppet; // [esp-8h] [ebp-18h]

    int tmp = jkGuiBuildMulti_bRendering; // Added
    jkGuiBuildMulti_bRendering = 1; // Added

    jkGuiBuildMulti_model = rdModel3_New(pModelFpath);
    jkGuiBuildMulti_thing = rdThing_New(0);
    rdThing_SetModel3(jkGuiBuildMulti_thing, jkGuiBuildMulti_model);
    jkGuiBuildMulti_thing->puppet = rdPuppet_New(jkGuiBuildMulti_thing);
    jkGuiBuildMulti_keyframe = rdKeyframe_Load("kyrun1.key");
    jkGuiBuildMulti_trackNum = rdPuppet_AddTrack(jkGuiBuildMulti_thing->puppet, jkGuiBuildMulti_keyframe, 0, 0);
    pPuppet = jkGuiBuildMulti_thing->puppet;
    jkGuiBuildMulti_startTimeSecs = stdPlatform_GetTimeMsec(); // Added: float -> u32, sec -> ms
    rdPuppet_PlayTrack(pPuppet, jkGuiBuildMulti_trackNum);
    rdPuppet_SetTrackSpeed(jkGuiBuildMulti_thing->puppet, jkGuiBuildMulti_trackNum, 150.0);
    _memcpy(&jkGuiBuildMulti_matrix, &rdroid_identMatrix34, sizeof(jkGuiBuildMulti_matrix));

    jkGuiBuildMulti_bRendering = tmp; // Added
}

void jkGuiBuildMulti_ThingCleanup()
{
    int tmp = jkGuiBuildMulti_bRendering; // Added
    jkGuiBuildMulti_bRendering = 1; // Added

    // Added
    //std3D_PurgeTextureCache();

    rdPuppet_ResetTrack(jkGuiBuildMulti_thing->puppet, jkGuiBuildMulti_trackNum);
    rdKeyframe_FreeEntry(jkGuiBuildMulti_keyframe);
    rdThing_Free(jkGuiBuildMulti_thing);
    rdModel3_Free(jkGuiBuildMulti_model);

    jkGuiBuildMulti_bRendering = tmp; // Added
}

// MOTS altered
int jkGuiBuildMulti_ShowEditCharacter(int bIdk)
{
    int v1; // esi
    wchar_t *v2; // eax
    wchar_t *v3; // eax
    int v4; // esi
    jkSaberInfo *v5; // ecx
    jkSaberInfo *v6; // ecx
    stdBitmap *v7; // eax
    int v8; // ebp
    jkSaberInfo * v9; // edi
    jkMultiModelInfo *v10; // eax
    int v11; // eax
    int v12; // edi
    jkMultiModelInfo *v13; // ebp
    rdPuppet *v14; // eax
    wchar_t *v15; // eax
    int v16; // esi
    int v17; // eax
    int v18; // edi
    int i; // esi
    wchar_t *v21; // [esp-4h] [ebp-190h]
    int idx; // [esp+10h] [ebp-17Ch] BYREF
    int _v23;
    int64_t v23; // [esp+14h] [ebp-178h]
    char v24[32]; // [esp+1Ch] [ebp-170h] BYREF
    char tmp1[32]; // [esp+2Ch] [ebp-160h] BYREF
    char tmp2[32]; // [esp+4Ch] [ebp-140h] BYREF
    char tmp3[32]; // [esp+6Ch] [ebp-120h] BYREF
    char v28[32]; // [esp+8Ch] [ebp-100h] BYREF
    char v32[32]; // [esp+ACh] [ebp-E0h] BYREF
    char v33[32]; // [esp+CCh] [ebp-C0h] BYREF
    char v34[32]; // [esp+ECh] [ebp-A0h] BYREF
    char FileName[128]; // [esp+10Ch] [ebp-80h] BYREF

    memset(v28, 0, sizeof(v28));
    jkGui_SetModeMenu(jkGui_stdBitmaps[JKGUI_BM_BK_BUILD_MULTI]->palette);
    v1 = jkPlayer_GetJediRank();
    stdString_snprintf(v24, 32, "RANK_%d_L", v1);
    v21 = jkStrings_GetUniStringWithFallback(v24);
    v2 = jkStrings_GetUniStringWithFallback("GUI_RANK");
    jk_snwprintf(jkGuiBuildMulti_waTmp, 0x80u, v2, v1, v21);
    jkGuiBuildMulti_buttons[2].wstr = jkGuiBuildMulti_waTmp;

    if (jkPlayer_personality != 1) {
        jkGuiBuildMulti_buttons[2].bIsVisible = 0;
    }
    else {
        jkGuiBuildMulti_buttons[2].bIsVisible = 1; // Added: Fix an LEC bug where the rank text disappeared forever
    }

    v3 = jkStrings_GetUniStringWithFallback("GUI_S_MULTIPLAYER_CHARACTERS");
    jk_snwprintf(&jkGuiBuildMulti_waTmp[64], 0x40u, v3, jkPlayer_playerShortName);
    jkGuiBuildMulti_buttons[1].wstr = &jkGuiBuildMulti_waTmp[64];
    v4 = jkPlayer_GetMpcInfo(&jkGuiBuildMulti_waTmp[32], v28, v34, v33, v32);
    _v23 = v4;
    jkGuiBuildMulti_buttons[3].wstr = &jkGuiBuildMulti_waTmp[32];
    jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiBuildMulti_menu, &jkGuiBuildMulti_buttons[15]);
    jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiBuildMulti_menu, &jkGuiBuildMulti_buttons[13]);
    jkGuiRend_SetVisibleAndDraw(&jkGuiBuildMulti_buttons[4], &jkGuiBuildMulti_menu, 0);
    jkGuiRend_SetVisibleAndDraw(&jkGuiBuildMulti_buttons[5], &jkGuiBuildMulti_menu, 0);
    jkGuiBuildMulti_numSabers = 0;
    jkGuiBuildMulti_bEditShowing = 1;
    if ( stdConffile_OpenRead("misc\\sabers.dat") )
    {
        stdConffile_ReadLine();
        if ( _sscanf(stdConffile_aLine, "numsabers: %d", &jkGuiBuildMulti_numSabers) == 1 )
        {
            jkGame_aSabers = (jkSaberInfo *)pHS->alloc(sizeof(jkSaberInfo) * jkGuiBuildMulti_numSabers);
            memset(jkGame_aSabers, 0, sizeof(jkSaberInfo) * jkGuiBuildMulti_numSabers);
            for ( jkGuiBuildMulti_apSaberBitmaps = (stdBitmap **)pHS->alloc(sizeof(stdBitmap*) * jkGuiBuildMulti_numSabers);
                  stdConffile_ReadLine();
                  jkGuiBuildMulti_apSaberBitmaps[idx] = v7 )
            {
                _sscanf(stdConffile_aLine, "%d: %s %s %s", &idx, tmp3, tmp2, tmp1);
                _strncpy(jkGame_aSabers[idx].BM, tmp3, 0x1Fu);
                v5 = jkGame_aSabers;
                jkGame_aSabers[idx].BM[31] = 0;
                _strncpy(v5[idx].sideMat, tmp2, 0x1Fu);
                v6 = jkGame_aSabers;
                jkGame_aSabers[idx].sideMat[31] = 0;
                _strncpy(v6[idx].tipMat, tmp1, 0x1Fu);
                jkGame_aSabers[idx].tipMat[31] = 0;
                stdString_snprintf(FileName, 128, "ui\\bm\\%s", tmp3);
                v7 = stdBitmap_Load(FileName, 1, 0);
            }
        }
        stdConffile_Close();
    }
    else {
        return 0; // Added: MoTS demo has no MP assets
    }

    if ( v4 )
    {
        v8 = 0;
        idx = 0;
        if ( jkGuiBuildMulti_numSabers > 0 )
        {
            v9 = jkGame_aSabers;
            while ( strcmp(v33, v9->sideMat) || strcmp(v32, v9->tipMat) )
            {
                ++v8;
                ++v9;
                if ( v8 >= jkGuiBuildMulti_numSabers )
                {
                    v4 = _v23;
                    jkGuiBuildMulti_saberIdx = idx;
                    goto LABEL_16;
                }
            }
            idx = v8;
        }
        v4 = _v23;
        jkGuiBuildMulti_saberIdx = idx;
    }
    else
    {
        jkGuiBuildMulti_saberIdx = 0;
    }
LABEL_16:
    jkGuiBuildMulti_numModels = 0;
    jkGuiBuildMulti_bSabersLoaded = 1;
    if ( stdConffile_OpenRead("misc\\models.dat") )
    {
        stdConffile_ReadLine();
        if ( _sscanf(stdConffile_aLine, "nummodels: %d", &jkGuiBuildMulti_numModels) == 1 )
        {
            jkGuiBuildMulti_aModels = (jkMultiModelInfo *)pHS->alloc(jkGuiBuildMulti_numModels * sizeof(jkMultiModelInfo));
            memset(jkGuiBuildMulti_aModels, 0, jkGuiBuildMulti_numModels * sizeof(jkMultiModelInfo));
            while ( stdConffile_ReadLine() )
            {
                if ( _sscanf(stdConffile_aLine, "%d: %s %s", &idx, tmp1, tmp2) == 3 )
                {
                    _strncpy(jkGuiBuildMulti_aModels[idx].modelFpath, tmp1, 0x1Fu);
                    v10 = jkGuiBuildMulti_aModels;
                    jkGuiBuildMulti_aModels[idx].modelFpath[31] = 0;
                    _strncpy(v10[idx].sndFpath, tmp2, 0x1Fu);
                    jkGuiBuildMulti_aModels[idx].sndFpath[31] = 0;
                }
            }
        }
        stdConffile_Close();
    }
    if ( v4 )
    {
        v11 = 0;
        v12 = 0;
        _v23 = 0;
        if ( jkGuiBuildMulti_numModels > 0 )
        {
            v13 = jkGuiBuildMulti_aModels;
            while ( strcmp(v28, v13->modelFpath) )
            {
                ++v12;
                ++v13;
                if ( v12 >= jkGuiBuildMulti_numModels )
                {
                    jkGuiBuildMulti_modelIdx = _v23;
                    goto LABEL_32;
                }
            }
            v11 = v12;
        }
        jkGuiBuildMulti_modelIdx = v11;
    }
    else
    {
        jkGuiBuildMulti_modelIdx = 0;
    }
LABEL_32:
    jkGuiBuildMulti_DisplayModel();

    jkGuiBuildMulti_ThingInit(jkGuiBuildMulti_aModels[jkGuiBuildMulti_modelIdx].modelFpath); // inlined

    stdFnames_CopyShortName(v24, 16, jkGuiBuildMulti_aModels[jkGuiBuildMulti_modelIdx].modelFpath);
    jkGuiTitle_sub_4189A0(v24);
    v15 = jkStrings_GetUniStringWithFallback(v24);
    jk_snwprintf(jkGuiBuildMulti_waTmp2, 0x20, L"%s", v15); // ADDED: swprintf -> snwprintf
    jkGuiBuildMulti_buttons[8].wstr = jkGuiBuildMulti_waTmp2;
    do
    {
        v16 = 0;
        v17 = jkGuiRend_DisplayAndReturnClicked(&jkGuiBuildMulti_menu);
        v18 = v17;
        switch ( v17 )
        {
            case -1:
                if ( bIdk )
                {
                    jkGuiBuildMulti_Load(FileName, 128, jkPlayer_playerShortName, &jkGuiBuildMulti_waTmp[32], 1);
                    stdFileUtil_DelFile(FileName);
                }
                break;
            case 106:
                jkPlayer_SetMpcInfo(
                    &jkGuiBuildMulti_waTmp[32],
                    jkGuiBuildMulti_aModels[jkGuiBuildMulti_modelIdx].modelFpath,
                    jkGuiBuildMulti_aModels[jkGuiBuildMulti_modelIdx].sndFpath,
                    jkGame_aSabers[jkGuiBuildMulti_saberIdx].sideMat,
                    jkGame_aSabers[jkGuiBuildMulti_saberIdx].tipMat);
                break;
            case 109:
                jkPlayer_FixStars();
                jkGuiBuildMulti_bRendering = 0; // Added
                if (!Main_bMotsCompat || jkPlayer_personality == 1) {
                    jkGuiForce_Show(1, 1, 0, &jkGuiBuildMulti_waTmp[32], 0, 0);
                }
                else {
                    jkGuiForce_Show(0, 1, 0, &jkGuiBuildMulti_waTmp[32], 0, 0);
                }
                
                jkGuiBuildMulti_bRendering = 1; // Added
                v16 = 1;
                break;
        }
    }
    while ( v16 );
    jkGuiBuildMulti_ThingCleanup(); // inlined

    jkGuiBuildMulti_CloseRender(); // inlined

    jkGuiBuildMulti_bSabersLoaded = 0;
    if ( jkGuiBuildMulti_aModels )
        pHS->free(jkGuiBuildMulti_aModels);
    jkGuiBuildMulti_bEditShowing = 0;
    if ( jkGame_aSabers )
        pHS->free(jkGame_aSabers);
    for ( i = 0; i < jkGuiBuildMulti_numSabers; ++i ) {
        stdBitmap_Free(jkGuiBuildMulti_apSaberBitmaps[i]);
        jkGuiBuildMulti_apSaberBitmaps[i] = NULL; // Added
    }
    if ( jkGuiBuildMulti_apSaberBitmaps ) {
        pHS->free(jkGuiBuildMulti_apSaberBitmaps);
        jkGuiBuildMulti_apSaberBitmaps = NULL; // Added
    }
    jkGui_SetModeGame();

    // Added
    //std3D_PurgeTextureCache();

    jkGuiBuildMulti_bRendering = 0; // Added

    return v18;
}

int jkGuiBuildMulti_DisplayModel()
{
    stdVBufferTexFmt v1; // [esp+8h] [ebp-4Ch] BYREF

    int tmp = jkGuiBuildMulti_bRendering; // Added
    jkGuiBuildMulti_bRendering = 1; // Added

    rdOpen(0);
    rdColormap_LoadEntry("misc\\cmp\\UIColormap.cmp", &jkGuiBuildMulti_colormap);
    rdColormap_SetCurrent(&jkGuiBuildMulti_colormap);
    rdSetRenderOptions(jkGuiBuildMulti_renderOptions);
    rdSetGeometryMode(RD_GEOMODE_TEXTURED);
    rdSetLightingMode(RD_LIGHTMODE_GOURAUD);
    rdSetTextureMode(RD_TEXTUREMODE_PERSPECTIVE);
    rdSetZBufferMethod(RD_ZBUFFER_READ_WRITE);
    rdSetSortingMethod(0);
    rdSetOcclusionMethod(0);
    v1.format.bpp = 8;
    v1.width = 260;
    v1.height = 260;
    v1.format.is16bit = 0;
    jkGuiBuildMulti_pVBuf1 = stdDisplay_VBufferNew(&v1, 0, 0, 0);
    stdDisplay_VBufferFill(jkGuiBuildMulti_pVBuf1, 0, 0);
    _memcpy(&jkGuiBuildMulti_texFmt, &stdDisplay_pCurVideoMode->format, sizeof(jkGuiBuildMulti_texFmt));
    jkGuiBuildMulti_texFmt.format.bpp = 16;
    jkGuiBuildMulti_pVBuf2 = stdDisplay_VBufferNew(&jkGuiBuildMulti_texFmt, 0, 0, 0);
    jkGuiBuildMulti_pCanvas = rdCanvas_New(3, jkGuiBuildMulti_pVBuf1, jkGuiBuildMulti_pVBuf2, 0, 0, 259, 259, 6);
    jkGuiBuildMulti_pCamera = rdCamera_New(60.0, 0.0, 0.08, 15.0, 1.0);
    rdCamera_SetCanvas(jkGuiBuildMulti_pCamera, jkGuiBuildMulti_pCanvas);
    jkGuiBuildMulti_pThingCamera = rdThing_New(0);
    rdThing_SetCamera(jkGuiBuildMulti_pThingCamera, jkGuiBuildMulti_pCamera);
    rdCamera_SetCurrent(jkGuiBuildMulti_pCamera);
    jkGuiBuildMulti_projectRot.x = 0.0;
    jkGuiBuildMulti_projectRot.y = 0.2;
    jkGuiBuildMulti_projectRot.z = -0.04;
    jkGuiBuildMulti_projectPos.x = 0.0;
    jkGuiBuildMulti_projectPos.y = 180.0;
    jkGuiBuildMulti_projectPos.z = 0.0;
    rdMatrix_Build34(&jkGuiBuildMulti_orthoProjection, &jkGuiBuildMulti_projectPos, &jkGuiBuildMulti_projectRot);
    rdCamera_Update(&jkGuiBuildMulti_orthoProjection);
    _memcpy(&jkGuiBuildMulti_matrix, &rdroid_identMatrix34, sizeof(jkGuiBuildMulti_matrix));
    rdCamera_ClearLights(jkGuiBuildMulti_pCamera);
    rdLight_NewEntry(&jkGuiBuildMulti_light);
    jkGuiBuildMulti_lightPos.x = 0.2;
    jkGuiBuildMulti_lightPos.y = 0.2;
    jkGuiBuildMulti_lightPos.z = 0.0;
    jkGuiBuildMulti_light.intensity = 4.0;
    rdCamera_AddLight(jkGuiBuildMulti_pCamera, &jkGuiBuildMulti_light, &jkGuiBuildMulti_lightPos);
    rdCamera_SetAmbientLight(jkGuiBuildMulti_pCamera, 0.4);
    jkGuiBuildMulti_fnMatLoader = rdMaterial_RegisterLoader(jkGuiBuildMulti_MatLoader);
    jkGuiBuildMulti_fnModelLoader = rdModel3_RegisterLoader(jkGuiBuildMulti_ModelLoader);
    jkGuiBuildMulti_fnKeyframeLoader = rdKeyframe_RegisterLoader(jkGuiBuildMulti_KeyframeLoader);
    jkGuiBuildMulti_pModelGun = rdModel3_New("bryg.3do");
    jkGuiBuildMulti_pThingGun = rdThing_New(0);
    int ret = rdThing_SetModel3(jkGuiBuildMulti_pThingGun, jkGuiBuildMulti_pModelGun);

    jkGuiBuildMulti_bRendering = tmp; // Added
    return ret;
}

void jkGuiBuildMulti_ModelDrawer(jkGuiElement *pElement, jkGuiMenu *pMenu, stdVBuffer *pVbuf, int redraw)
{
    uint32_t v5; // st7
    double v6; // st7
    rdPuppet *v7; // [esp-8h] [ebp-24h]
    int64_t v8; // [esp+8h] [ebp-14h]
    float v9; // [esp+8h] [ebp-14h]
    rdVector3 rot; // [esp+10h] [ebp-Ch] BYREF
    float a2a; // [esp+24h] [ebp+8h]

    jkGuiBuildMulti_bRendering = 1;

    if ( jkGuiBuildMulti_lastModelDrawMs )
    {
        if ( stdPlatform_GetTimeMsec() - (uint32_t)jkGuiBuildMulti_lastModelDrawMs <= BUILDMULTI_SWITCH_DELAY_MS ) {
            stdDisplay_VBufferCopy(pVbuf, pMenu->texture, 315u, 115, &jkGuiBuildMulti_rect_5353C8, 0);
            return;
        }
        jkGuiBuildMulti_ThingCleanup(); // inlined

        jkGuiBuildMulti_ThingInit(jkGuiBuildMulti_aModels[jkGuiBuildMulti_modelIdx].modelFpath); // inlined
        jkGuiBuildMulti_lastModelDrawMs = 0;
    }

    if ( g_app_suspended )
    {
        stdControl_ShowCursor(1);
        stdDisplay_VBufferFill(jkGuiBuildMulti_pVBuf1, 0, 0);
        stdDisplay_VBufferLock(jkGuiBuildMulti_pVBuf1);
        rdAdvanceFrame();

        // Added: switched around the order of casting for this...
        v5 = stdPlatform_GetTimeMsec();
        v6 = (v5 - jkGuiBuildMulti_startTimeSecs) * 0.001;
        if ( v6 < 0.0 )
        {
            a2a = 0.0;
        }
        else if ( v6 > 1.0 )
        {
            a2a = 1.0;
        }
        else
        {
            a2a = v6;
        }
        rdPuppet_UpdateTracks(jkGuiBuildMulti_thing->puppet, a2a);
        jkGuiBuildMulti_startTimeSecs = v5;
        rdThing_Draw(jkGuiBuildMulti_thing, &jkGuiBuildMulti_matrix);
        rdThing_Draw(jkGuiBuildMulti_pThingGun, jkGuiBuildMulti_thing->hierarchyNodeMatrices + 12);
        rdFinishFrame();
        stdDisplay_VBufferUnlock(jkGuiBuildMulti_pVBuf1);
        rot.x = 0.0;
        rot.z = 0.0;
        rot.y = a2a * 20.0;
        rdMatrix_PostRotate34(&jkGuiBuildMulti_matrix, &rot);
        stdDisplay_VBufferCopy(pVbuf, jkGuiBuildMulti_pVBuf1, 0x13Bu, 115, 0, 0);
        stdControl_ShowCursor(0);
    }
}

void jkGuiBuildMulti_SaberDrawer(jkGuiElement *pElement, jkGuiMenu *pMenu, stdVBuffer *pVbuf, int redraw)
{
    stdBitmap *pSabBm; // eax
    signed int bmWidth; // esi
    signed int bmHeight; // esi
    rdRect rect; // [esp+4h] [ebp-10h] BYREF

    pSabBm = jkGuiBuildMulti_apSaberBitmaps[jkGuiBuildMulti_saberIdx];
    rect.x = 0;
    rect.y = 0;
    bmWidth = (*pSabBm->mipSurfaces)->format.width;
    rect.width = pElement->rect.width;
    if ( rect.width >= bmWidth )
        rect.width = bmWidth;
    bmHeight = (*pSabBm->mipSurfaces)->format.height;
    rect.height = pElement->rect.height;
    if ( rect.height >= bmHeight )
        rect.height = bmHeight;
    stdDisplay_VBufferCopy(pVbuf, *pSabBm->mipSurfaces, pElement->rect.x, pElement->rect.y, &rect, 0);
}

// MOTS altered
int jkGuiBuildMulti_SaberButtonClicked(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw)
{
    int v2; // eax
    wchar_t *v3; // eax
    int v4; // eax
    wchar_t *v5; // eax
    char v7[16]; // [esp+0h] [ebp-10h] BYREF

    switch ( pElement->hoverId )
    {
        case 100:
            v2 = --jkGuiBuildMulti_modelIdx;
            if ( jkGuiBuildMulti_modelIdx < 0 )
            {
                v2 = jkGuiBuildMulti_numModels - 1;
                jkGuiBuildMulti_modelIdx = jkGuiBuildMulti_numModels - 1;
                if ( jkGuiBuildMulti_numModels - 1 < 0 )
                {
                    v2 = 0;
                    jkGuiBuildMulti_modelIdx = 0;
                }
            }
            stdFnames_CopyShortName(v7, 16, jkGuiBuildMulti_aModels[v2].modelFpath);
            jkGuiTitle_sub_4189A0(v7);
            v3 = jkStrings_GetUniStringWithFallback(v7);
            jk_snwprintf(jkGuiBuildMulti_waTmp2, 0x20, L"%s", v3); // ADDED: swprintf -> snwprintf
            jkGuiBuildMulti_buttons[8].wstr = jkGuiBuildMulti_waTmp2;
            jkGuiRend_UpdateAndDrawClickable(&jkGuiBuildMulti_buttons[8], pMenu, 1);
            goto LABEL_9;
        case 101:
            v4 = ++jkGuiBuildMulti_modelIdx;
            if ( jkGuiBuildMulti_modelIdx >= jkGuiBuildMulti_numModels )
            {
                v4 = 0;
                jkGuiBuildMulti_modelIdx = 0;
            }
            stdFnames_CopyShortName(v7, 16, jkGuiBuildMulti_aModels[v4].modelFpath);
            jkGuiTitle_sub_4189A0(v7);
            v5 = jkStrings_GetUniStringWithFallback(v7);
            jk_snwprintf(jkGuiBuildMulti_waTmp2, 0x20, L"%s", v5); // ADDED: swprintf -> snwprintf
            jkGuiBuildMulti_buttons[8].wstr = jkGuiBuildMulti_waTmp2;
            jkGuiRend_UpdateAndDrawClickable(&jkGuiBuildMulti_buttons[8], pMenu, 1);
LABEL_9:
            jkGuiBuildMulti_lastModelDrawMs = stdPlatform_GetTimeMsec();
            return 0;
        case 102:
            if ( --jkGuiBuildMulti_saberIdx < 0 )
                jkGuiBuildMulti_saberIdx = jkGuiBuildMulti_numSabers - 1;
            if ( jkGuiBuildMulti_numSabers < 0 )
                jkGuiBuildMulti_saberIdx = 0;
            jkGuiRend_UpdateAndDrawClickable(&jkGuiBuildMulti_buttons[7], pMenu, 1);
            return 0;
        case 103:
            if ( ++jkGuiBuildMulti_saberIdx >= jkGuiBuildMulti_numSabers )
                jkGuiBuildMulti_saberIdx = 0;
            jkGuiRend_UpdateAndDrawClickable(&jkGuiBuildMulti_buttons[7], pMenu, 1);
            return 0;
        default:
            return 0;
    }
}

void jkGuiBuildMulti_sub_41A120(jkGuiMenu *pMenu)
{
    if ( g_app_suspended )
        jkGuiRend_UpdateAndDrawClickable(&jkGuiBuildMulti_buttons[6], pMenu, 1);
}

int jkGuiBuildMulti_Startup()
{
    if (!Main_bMotsCompat)
    {
        jkGuiBuildMulti_pNewCharacterMenu = &jkGuiBuildMulti_menuNewCharacter;
        jkGuiBuildMulti_pNewCharacterElements = jkGuiBuildMulti_menuNewCharacter_buttons;
    }
    else {
        jkGuiBuildMulti_pNewCharacterMenu = &jkGuiBuildMulti_menuNewCharacterMots;
        jkGuiBuildMulti_pNewCharacterElements = jkGuiBuildMulti_menuNewCharacter_buttonsMots;
    }
    jkGui_InitMenu(jkGuiBuildMulti_pNewCharacterMenu, jkGui_stdBitmaps[JKGUI_BM_BK_BUILD_LOAD]);
    jkGui_InitMenu(&jkGuiBuildMulti_menuEditCharacter, jkGui_stdBitmaps[JKGUI_BM_BK_BUILD_LOAD]);
    jkGui_InitMenu(&jkGuiBuildMulti_menuLoadCharacter, jkGui_stdBitmaps[JKGUI_BM_BK_BUILD_LOAD]);

    jkGuiBuildMulti_bInitted = 1;
    return 1;
}

void jkGuiBuildMulti_Shutdown()
{
    jkGuiBuildMulti_bInitted = 0;

    // Added: clean reset
    memset(jkGuiBuildMulti_wPlayerShortName, 0, sizeof(jkGuiBuildMulti_wPlayerShortName));
    memset(jkGuiBuildMulti_aMpcInfo, 0, sizeof(jkGuiBuildMulti_aMpcInfo));
    memset(jkGuiBuildMulti_wTmp, 0, sizeof(jkGuiBuildMulti_wTmp));
    memset(jkGuiBuildMulti_wTmp2, 0, sizeof(jkGuiBuildMulti_wTmp2));
    memset(jkGuiBuildMulti_wTmp3, 0, sizeof(jkGuiBuildMulti_wTmp3));
    memset(jkGuiBuildMulti_aWchar_5594C8, 0, sizeof(jkGuiBuildMulti_aWchar_5594C8));

    jkGuiBuildMulti_fnMatLoader = NULL;
    jkGuiBuildMulti_fnModelLoader = NULL;
    jkGuiBuildMulti_fnKeyframeLoader = NULL;
    jkGuiBuildMulti_pCanvas = NULL;
    jkGuiBuildMulti_pCamera = NULL;
    jkGuiBuildMulti_model = NULL;
    jkGuiBuildMulti_pModelGun = NULL;
    jkGuiBuildMulti_keyframe = NULL;
    jkGuiBuildMulti_pThingCamera = NULL;
    jkGuiBuildMulti_thing = NULL;
    jkGuiBuildMulti_pThingGun = NULL;
    jkGuiBuildMulti_startTimeSecs = 0;

    memset(&jkGuiBuildMulti_colormap, 0, sizeof(jkGuiBuildMulti_colormap));
    memset(&jkGuiBuildMulti_light, 0, sizeof(jkGuiBuildMulti_light));
    memset(&jkGuiBuildMulti_matrix, 0, sizeof(jkGuiBuildMulti_matrix));

    jkGuiBuildMulti_pVBuf1 = NULL;
    jkGuiBuildMulti_pVBuf2 = NULL;
    jkGuiBuildMulti_trackNum = 0;
    memset(jkGuiBuildMulti_waTmp, 0, sizeof(jkGuiBuildMulti_waTmp));
    memset(jkGuiBuildMulti_waTmp2, 0, sizeof(jkGuiBuildMulti_waTmp2));

    jkGuiBuildMulti_apSaberBitmaps = NULL;
    jkGame_aSabers = NULL;
    jkGuiBuildMulti_bSabersLoaded = 0;
    jkGuiBuildMulti_bEditShowing = 0;
    jkGuiBuildMulti_numModels = 0;
    jkGuiBuildMulti_numSabers = 0;
    jkGuiBuildMulti_saberIdx = 0;
    jkGuiBuildMulti_modelIdx = 0;
    jkGuiBuildMulti_aModels = NULL;
    jkGuiBuildMulti_renderOptions = 0x103;

    memset(&jkGuiBuildMulti_projectRot, 0, sizeof(jkGuiBuildMulti_projectRot));
    memset(&jkGuiBuildMulti_projectPos, 0, sizeof(jkGuiBuildMulti_projectPos));
    memset(&jkGuiBuildMulti_texFmt, 0, sizeof(jkGuiBuildMulti_texFmt));
    memset(&jkGuiBuildMulti_orthoProjection, 0, sizeof(jkGuiBuildMulti_orthoProjection));
    memset(&jkGuiBuildMulti_lightPos, 0, sizeof(jkGuiBuildMulti_lightPos));
    jkGuiBuildMulti_lastModelDrawMs = 0;
}

void jkGuiBuildMulti_Load(char *pPathOut, int pathOutLen, wchar_t *pPlayerName, wchar_t *pCharName, int bCharPath)
{
    char tmp1[128]; // [esp+8h] [ebp-100h] BYREF
    char tmp2[128]; // [esp+88h] [ebp-80h] BYREF

    stdString_WcharToChar(tmp1, pPlayerName, 127);
    tmp1[127] = 0;
    stdFnames_MakePath(pPathOut, pathOutLen, "player", tmp1);
    if ( bCharPath )
    {
        stdString_WcharToChar(tmp2, pCharName, 127);
        tmp2[127] = 0;
        stdString_snprintf(pPathOut, pathOutLen, "player\\%s\\%s.mpc", tmp1, tmp2);
    }
    else
    {
        stdString_snprintf(pPathOut, pathOutLen, "player\\%s", tmp1);
    }
}

int jkGuiBuildMulti_Show()
{
    wchar_t *pwMultiplayerCharsStr; // eax
    int v1; // ebp
    int v2; // edi
    int v3; // esi
    jkGuiStringEntry *pEntry; // eax
    wchar_t *v6; // esi
    wchar_t *v7; // eax
    wchar_t *v8; // eax
    int v9; // [esp+10h] [ebp-3DCh]
    Darray darr; // [esp+14h] [ebp-3D8h] BYREF
    wchar_t wPlayerName[32]; // [esp+2Ch] [ebp-3C0h] BYREF
    char aPlayerName[128]; // [esp+6Ch] [ebp-380h] BYREF
    char aMpcFPath[128]; // [esp+ECh] [ebp-300h] BYREF
    char tmp1[128]; // [esp+16Ch] [ebp-280h] BYREF
    wchar_t wtmp1[256]; // [esp+1ECh] [ebp-200h] BYREF

    // MoTS added: Need to move things around for Personality
    if (!Main_bMotsCompat) {
        jkGuiBuildMulti_menuEditCharacter_buttons[10].bIsVisible = 0;
        jkGuiBuildMulti_menuEditCharacter_buttons[11].bIsVisible = 0;

        jkGuiBuildMulti_menuEditCharacter_buttons[6].rect.y = 190;
        jkGuiBuildMulti_menuEditCharacter_buttons[7].rect.y = 210;
    }
    else {
        jkGuiBuildMulti_menuEditCharacter_buttons[10].bIsVisible = 1;
        jkGuiBuildMulti_menuEditCharacter_buttons[11].bIsVisible = 1;

        jkGuiBuildMulti_menuEditCharacter_buttons[6].rect.y = 310;
        jkGuiBuildMulti_menuEditCharacter_buttons[7].rect.y = 330;
    }

    wPlayerName[0] = 0;
    memset(&wPlayerName[1], 0, 0x3Cu);
    wPlayerName[31] = 0;
    jkGui_SetModeMenu(jkGui_stdBitmaps[JKGUI_BM_BK_BUILD_LOAD]->palette);
    jkGuiRend_DarrayNewStr(&darr, 5, 1);
    jkGuiBuildMulti_menuEditCharacter_buttons[3].clickHandlerFunc = jkGuiBuildMulti_sub_41D830;
    jkGuiBuildMulti_menuEditCharacter_buttons[0].wstr = NULL;
    pwMultiplayerCharsStr = jkStrings_GetUniStringWithFallback("GUI_S_MULTIPLAYER_CHARACTERS");
    jk_snwprintf(jkGuiBuildMulti_wPlayerShortName, 0x40u, pwMultiplayerCharsStr, jkPlayer_playerShortName);
    jkGuiBuildMulti_menuEditCharacter_buttons[2].wstr = jkGuiBuildMulti_wPlayerShortName;
    v1 = 0;
    do
    {
        v2 = jkGuiBuildMulti_Show2(&darr, &jkGuiBuildMulti_menuEditCharacter_buttons[3], 0, 9, v1);
        jkGuiBuildMulti_sub_41D680(&jkGuiBuildMulti_menuEditCharacter, jkGuiBuildMulti_menuEditCharacter_buttons[3].selectedTextEntry);
        v3 = 1;
        if ( v2 )
        {
            jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiBuildMulti_menuEditCharacter, &jkGuiBuildMulti_menuEditCharacter_buttons[15]);
            jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiBuildMulti_menuEditCharacter, &jkGuiBuildMulti_menuEditCharacter_buttons[12]);
            v9 = jkGuiRend_DisplayAndReturnClicked(&jkGuiBuildMulti_menuEditCharacter);
        }
        else
        {
            v9 = 100;
        }
        switch ( v9 )
        {
            case -1:
                goto LABEL_8;
            case 1:
                pEntry = jkGuiRend_GetStringEntry(&darr, jkGuiBuildMulti_menuEditCharacter_buttons[3].selectedTextEntry);
                _wcsncpy(wPlayerName, pEntry->str, 0x1Fu);
                wPlayerName[31] = 0;
                v3 = 1;
                if ( jkPlayer_VerifyWcharName(wPlayerName) )
                {
                    jkPlayer_MPCParse(
                        &jkGuiBuildMulti_aMpcInfo[jkGuiBuildMulti_menuEditCharacter_buttons[3].selectedTextEntry],
                        &jkPlayer_playerInfos[playerThingIdx],
                        jkPlayer_playerShortName,
                        wPlayerName,
                        1);
                    jkGuiBuildMulti_ShowEditCharacter(0);
                    jkPlayer_MPCWrite(&jkPlayer_playerInfos[playerThingIdx], jkPlayer_playerShortName, wPlayerName);
                    v1 = jkGuiBuildMulti_menuEditCharacter_buttons[3].selectedTextEntry;
                }
                else
                {
                    jkGuiBuildMulti_menuEditCharacter_buttons[0].wstr = jkStrings_GetUniStringWithFallback("ERR_BAD_PLAYER_NAME");
                }
                break;
            case 100:
                if ( jkGuiBuildMulti_ShowNewCharacter(-1, 0, 0) < 0 && !v2 ) // MOTS altered TODO
LABEL_8:
                    v3 = 0;
                break;
            case 102:
                // MOTS added a tmp array here?
                v6 = jkGuiRend_GetString(&darr, jkGuiBuildMulti_menuEditCharacter_buttons[3].selectedTextEntry);
                v7 = jkStrings_GetUniStringWithFallback("GUI_CONFIRM_REMOVE_PLAYER");
                jk_snwprintf(wtmp1, 0x100u, v7, v6);
                v8 = jkStrings_GetUniStringWithFallback("GUI_REMOVE");
                if ( jkGuiDialog_YesNoDialog(v8, wtmp1) )
                {
                    stdString_WcharToChar(aPlayerName, jkPlayer_playerShortName, 127);
                    aPlayerName[127] = 0;
                    stdFnames_MakePath(aMpcFPath, 128, "player", aPlayerName);
                    stdString_WcharToChar(tmp1, v6, 127);
                    tmp1[127] = 0;
                    stdString_snprintf(aMpcFPath, 128, "player\\%s\\%s.mpc", aPlayerName, tmp1);
                    stdFileUtil_DelFile(aMpcFPath);
                }
                v3 = 1;
                v1 = 0;
                break;
            default:
                break;
        }
    }
    while ( v3 );
    jkGuiBuildMulti_bRendering = 0; // Added
    jkGuiRend_DarrayFree(&darr);
    jkGui_SetModeGame();
    return v9;
}

int jkGuiBuildMulti_Show2(Darray *pDarray, jkGuiElement *pElement, int minIdk, int maxIdk, int idx)
{
    int v5; // ebp
    stdFileSearch *v7; // edi
    jkPlayerMpcInfo *v8; // esi
    int v9; // eax
    char a2a[32]; // [esp+14h] [ebp-1640h] BYREF
    char a1[32]; // [esp+34h] [ebp-1620h] BYREF
    wchar_t name[32]; // [esp+54h] [ebp-1600h] BYREF
    char path[128]; // [esp+94h] [ebp-15C0h] BYREF
    char fpath[128]; // [esp+114h] [ebp-1540h] BYREF
    stdFileSearchResult v16; // [esp+194h] [ebp-14C0h] BYREF
    sithPlayerInfo playerInfo; // [esp+2A0h] [ebp-13B4h] BYREF

    v5 = 0;
    stdString_WcharToChar(a1, jkPlayer_playerShortName, 31);
    a1[31] = 0;
    jkGuiRend_DarrayFreeEntry(pDarray);
    stdString_snprintf(path, 128, "player\\%s", a1);
    pElement->selectedTextEntry = idx;
    v7 = stdFileUtil_NewFind(path, 3, "mpc");
    if ( v7 )
    {
        v8 = jkGuiBuildMulti_aMpcInfo;
        while ( stdFileUtil_FindNext(v7, &v16) )
        {
            if (v8 >= &jkGuiBuildMulti_aMpcInfo[32]) break;

            stdString_snprintf(fpath, 128, "%s\\%s", path, v16.fpath);
            if ( util_FileExists(fpath) )
            {
                _strncpy(a2a, v16.fpath, 0x1Fu);
                a2a[31] = 0;
                stdFnames_StripExtAndDot(a2a);
                stdString_CharToWchar(name, a2a, 31);
                name[31] = 0;
                jkPlayer_MPCParse(v8, &playerInfo, jkPlayer_playerShortName, name, 1);
                v9 = jkPlayer_GetJediRank();
                if ( v9 >= minIdk && v9 <= maxIdk )
                {
                    jkGuiRend_AddStringEntry(pDarray, a2a, 0);
                    if ( !__strcmpi(a2a, a1) )
                        pElement->selectedTextEntry = v5;
                    ++v5;
                    ++v8;
                }
            }
        }
        stdFileUtil_DisposeFind(v7);
    }
    jkGuiRend_DarrayReallocStr(pDarray, 0, 0);
    jkGuiRend_SetClickableString(pElement, pDarray);
    return v5;
}

// MOTS altered TODO
int jkGuiBuildMulti_ShowNewCharacter(int rank, int bGameFormatIsJK, int bHasNoValidChars)
{
    wchar_t *v4; // eax
    signed int v5; // esi
    wchar_t *v6; // eax
    int v7; // esi
    int v8; // ebp
    wchar_t *v9; // eax
    wchar_t *a2a; // [esp+0h] [ebp-1A8h]
    wchar_t *a2b; // [esp+0h] [ebp-1A8h]
    char v15[32]; // [esp+18h] [ebp-190h] BYREF
    char v16[128]; // [esp+28h] [ebp-180h] BYREF
    char v17[128]; // [esp+A8h] [ebp-100h] BYREF
    char v18[128]; // [esp+128h] [ebp-80h] BYREF

    // MOTS added
    Darray daPersonalities;
    char personalityTmp[128];

    // MOTS added
    if (Main_bMotsCompat && bGameFormatIsJK == 0) {
        jkGuiBuildMulti_jediRank = 8;
    }
    else {
        jkGuiBuildMulti_jediRank = rank;
    }

    // MOTS added
    jkGuiRend_DarrayNewStr(&daPersonalities,8,1);
    for (int i = 0; i < 8; i++)
    {
        if ((bGameFormatIsJK == 0) || (i == 0)) {
            stdString_snprintf(personalityTmp, 128, "GUI_PERSONALITY%d", i + 1); // Added: sprintf -> snprintf
            wchar_t* pwVar1 = jkStrings_GetUniString(personalityTmp);
            if (pwVar1 == NULL) break;
            jkGuiRend_DarrayReallocStr(&daPersonalities, pwVar1, 0);
        }
    }
    jkGuiRend_DarrayReallocStr(&daPersonalities,(wchar_t *)0x0,0);

    // MOTS added
    jkPlayer_personality = 1;
    if (Main_bMotsCompat) {
        jkGuiRend_SetClickableString(&jkGuiBuildMulti_pNewCharacterElements[12],&daPersonalities);
        jkGuiBuildMulti_pNewCharacterElements[12].selectedTextEntry = 0;
    }

    // MOTS: 11 -> 14
    jkGuiBuildMulti_pNewCharacterElements[14].wstr = jkGuiBuildMulti_aWchar_5594C8; // 11
    memset(jkGuiBuildMulti_aWchar_5594C8, 0, 0x20u);
    jkGuiBuildMulti_pNewCharacterElements[14].selectedTextEntry = 16; // 11
    if ( bHasNoValidChars )
    {
        jkGuiDialog_ErrorDialog(jkStrings_GetUniStringWithFallback("GUI_NOVALIDCHARTITLE"), jkStrings_GetUniStringWithFallback("GUI_NOVALIDCHARACTERS"));
    }
    jk_snwprintf(&jkGuiBuildMulti_wTmp[64], 0x40u, jkStrings_GetUniStringWithFallback("GUI_S_MULTIPLAYER_CHARACTERS"), jkPlayer_playerShortName);
    jkGuiBuildMulti_pNewCharacterElements[2].wstr = &jkGuiBuildMulti_wTmp[64]; // 2

    if (Main_bMotsCompat) {
        if ( rank < 0 )
        {
            jk_snwprintf(jkGuiBuildMulti_waTmpRankLabel, 0x80u, jkStrings_GetUniStringWithFallback("GUI_RANKLABEL"), rank);
            jkGuiBuildMulti_pNewCharacterElements[7].wstr = jkGuiBuildMulti_waTmpRankLabel;
        }
        else
        {
            jk_snwprintf(jkGuiBuildMulti_waTmpRankLabel, 0x80u, jkStrings_GetUniStringWithFallback("GUI_RANKLABELMAX"), rank);
            jkGuiBuildMulti_pNewCharacterElements[7].wstr = jkGuiBuildMulti_waTmpRankLabel;
        }
    }
    else {
        if ( rank < 0 )
        {
            jkGuiRend_SetVisibleAndDraw(&jkGuiBuildMulti_pNewCharacterElements[5], jkGuiBuildMulti_pNewCharacterMenu, 0); // 4
            jkGuiBuildMulti_pNewCharacterElements[6].wstr = NULL; // 5
        }
        else
        {
            jkGuiRend_SetVisibleAndDraw(&jkGuiBuildMulti_pNewCharacterElements[5], jkGuiBuildMulti_pNewCharacterMenu, 1); // 4
            stdString_snprintf(v15, 32, "RANK_%d_L", rank);
            a2a = jkStrings_GetUniStringWithFallback(v15);
            v4 = jkStrings_GetUniStringWithFallback("GUI_RANK");
            jk_snwprintf(&jkGuiBuildMulti_wTmp[32], 0x80u, v4, rank, a2a);
            jkGuiBuildMulti_pNewCharacterElements[6].wstr = &jkGuiBuildMulti_wTmp[32]; // 5
        }
    }
    
    v5 = rank < 0 ? 0 : rank;
    jkPlayer_SetRank(v5);
    stdString_snprintf(v15, 32, "RANK_%d_L", v5);
    a2b = jkStrings_GetUniStringWithFallback(v15);
    v6 = jkStrings_GetUniStringWithFallback("GUI_RANK");
    jk_snwprintf(jkGuiBuildMulti_wTmp, 0x80u, v6, v5, a2b);
    jkGuiBuildMulti_pNewCharacterElements[8].wstr = jkGuiBuildMulti_wTmp; // 7
    jkGuiBuildMulti_pNewCharacterElements[0].wstr = NULL; // 0

    if (Main_bMotsCompat) {
        jkGuiBuildMulti_pNewCharacterElements[5].bIsVisible = 1;
        jkGuiBuildMulti_pNewCharacterElements[6].bIsVisible = 1;
        if (bGameFormatIsJK == 0) {
            jkGuiBuildMulti_pNewCharacterElements[6].selectedTextEntry = 0;
            jkGuiBuildMulti_pNewCharacterElements[5].selectedTextEntry = 1;
            jkGuiBuildMulti_pNewCharacterElements[7].bIsVisible = 0;
            jkGuiBuildMulti_pNewCharacterElements[8].bIsVisible = 0;
            jkGuiBuildMulti_pNewCharacterElements[9].bIsVisible = 0;
            jkGuiBuildMulti_pNewCharacterElements[10].bIsVisible = 0;
            jkGuiBuildMulti_pNewCharacterElements[11].bIsVisible = 1;
            jkGuiBuildMulti_pNewCharacterElements[12].bIsVisible = 1;
            if (bHasNoValidChars != 0) {
                jkGuiBuildMulti_pNewCharacterElements[6].bIsVisible = 0;
            }
        }
        else {
            jkGuiBuildMulti_pNewCharacterElements[6].selectedTextEntry = 1;
            jkGuiBuildMulti_pNewCharacterElements[5].selectedTextEntry = 0;
            jkGuiBuildMulti_pNewCharacterElements[7].bIsVisible = 1;
            jkGuiBuildMulti_pNewCharacterElements[8].bIsVisible = 1;
            jkGuiBuildMulti_pNewCharacterElements[9].bIsVisible = 1;
            jkGuiBuildMulti_pNewCharacterElements[10].bIsVisible = 1;
            jkGuiBuildMulti_pNewCharacterElements[11].bIsVisible = 0;
            jkGuiBuildMulti_pNewCharacterElements[12].bIsVisible = 0;
            if (bHasNoValidChars != 0) {
                jkGuiBuildMulti_pNewCharacterElements[5].bIsVisible = 0;
            }
        }
    }

    do
    {
        v7 = 0;
        jkGuiRend_MenuSetReturnKeyShortcutElement(jkGuiBuildMulti_pNewCharacterMenu, &jkGuiBuildMulti_pNewCharacterElements[16]); // 13
        jkGuiRend_MenuSetEscapeKeyShortcutElement(jkGuiBuildMulti_pNewCharacterMenu, &jkGuiBuildMulti_pNewCharacterElements[15]); // 12
        v8 = jkGuiRend_DisplayAndReturnClicked(jkGuiBuildMulti_pNewCharacterMenu);
        if ( v8 != 1 )
            goto LABEL_16;
        if ( jkGuiBuildMulti_aWchar_5594C8[0] )
        {
            if ( jkPlayer_VerifyWcharName(jkGuiBuildMulti_aWchar_5594C8) )
            {
                stdString_WcharToChar(v16, jkPlayer_playerShortName, 127);
                v16[127] = 0;
                stdFnames_MakePath(v18, 128, "player", v16);
                stdString_WcharToChar(v17, jkGuiBuildMulti_aWchar_5594C8, 127);
                v17[127] = 0;
                stdString_snprintf(v18, 128, "player\\%s\\%s.mpc", v16, v17);
                if ( !util_FileExists(v18) )
                    goto LABEL_16;
                v7 = 1;
                v9 = jkStrings_GetUniStringWithFallback("ERR_PLAYER_ALREADY_EXISTS");
            }
            else
            {
                v7 = 1;
                memset(jkGuiBuildMulti_aWchar_5594C8, 0, 0x20u);
                v9 = jkStrings_GetUniStringWithFallback("ERR_BAD_PLAYER_NAME");
            }
        }
        else
        {
            v7 = 1;
            v9 = jkStrings_GetUniStringWithFallback("ERR_NO_PLAYER_NAME");
        }
        jkGuiBuildMulti_pNewCharacterElements[0].wstr = v9; // 8
LABEL_16:
        if ( v8 == -1 ) {
            jkGuiRend_DarrayFree(&daPersonalities); // MOTS added
            return -1;
        }
    }
    while ( v7 );
    sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS, (double)jkPlayer_GetJediRank() * 3.0);
    sithPlayer_SetBinAmt(SITHBIN_NEW_STARS, 0.0);
    if (Main_bMotsCompat) {
        if (jkGuiBuildMulti_pNewCharacterElements[5].selectedTextEntry == 0) {
            jkPlayer_personality = 1;
        }
        else {
            jkPlayer_SetRank(7);
            jkPlayer_personality = jkGuiBuildMulti_pNewCharacterElements[12].selectedTextEntry + 1;
        }
        jkPlayer_SetAmmoMaximums(jkPlayer_personality);
    }
    jkPlayer_ResetPowers();
    if (Main_bMotsCompat) {
        jkPlayer_SyncForcePowers(jkPlayer_GetJediRank(), 1);
    }
    jkPlayer_SetPlayerName(jkGuiBuildMulti_aWchar_5594C8);
    jkPlayer_mpcInfoSet = 0;
    jkGuiBuildMulti_ShowEditCharacter(1);
    jkPlayer_MPCWrite(&jkPlayer_playerInfos[playerThingIdx], jkPlayer_playerShortName, jkGuiBuildMulti_aWchar_5594C8);
    jkGuiRend_DarrayFree(&daPersonalities); // MOTS added
    return v8;
}


int jkGuiBuildMulti_FUN_00420930(jkGuiElement *pElement,jkGuiMenu *pMenu,int mouseX,int mouseY, BOOL redraw)
{
    jkGuiBuildMulti_pNewCharacterElements[6].selectedTextEntry = 1;
    jkGuiBuildMulti_pNewCharacterElements[5].selectedTextEntry = 0;
    if (pMenu != (jkGuiMenu *)0x0) {
        jkGuiRend_UpdateAndDrawClickable(pElement,pMenu,1);
    }
    jkGuiBuildMulti_pNewCharacterElements[7].bIsVisible = 1;
    jkGuiBuildMulti_pNewCharacterElements[8].bIsVisible = 1;
    jkGuiBuildMulti_pNewCharacterElements[9].bIsVisible = 1;
    jkGuiBuildMulti_pNewCharacterElements[10].bIsVisible = 1;
    jkGuiBuildMulti_pNewCharacterElements[11].bIsVisible = 0;
    jkGuiBuildMulti_pNewCharacterElements[12].bIsVisible = 0;

    // Added: Prevent infloop
    if (!pMenu->focusedElement->bIsVisible) {
        pMenu->focusedElement = &jkGuiBuildMulti_pNewCharacterElements[14];
    }

    if (pMenu != (jkGuiMenu *)0x0) {
        jkGuiRend_Paint(pMenu);
        jkGuiRend_Paint(pMenu);
    }
    return 0;
}

int jkGuiBuildMulti_FUN_004209b0(jkGuiElement *pElement,jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw)
{
    jkGuiBuildMulti_pNewCharacterElements[6].selectedTextEntry = 0;
    jkGuiBuildMulti_pNewCharacterElements[5].selectedTextEntry = 1;
    if (pMenu != (jkGuiMenu *)0x0) {
        jkGuiRend_UpdateAndDrawClickable(pElement,pMenu,1);
    }
    jkGuiBuildMulti_pNewCharacterElements[7].bIsVisible = 0;
    jkGuiBuildMulti_pNewCharacterElements[8].bIsVisible = 0;
    jkGuiBuildMulti_pNewCharacterElements[9].bIsVisible = 0;
    jkGuiBuildMulti_pNewCharacterElements[10].bIsVisible = 0;
    jkGuiBuildMulti_pNewCharacterElements[11].bIsVisible = 1;
    jkGuiBuildMulti_pNewCharacterElements[12].bIsVisible = 1;

    // Added: Prevent infloop
    if (!pMenu->focusedElement->bIsVisible) {
        pMenu->focusedElement = &jkGuiBuildMulti_pNewCharacterElements[14];
    }

    if (pMenu != (jkGuiMenu *)0x0) {
        jkGuiRend_Paint(pMenu);
        jkGuiRend_Paint(pMenu);
    }
    return 0;
}

int jkGuiBuildMulti_menuNewCharacter_rankArrowButtonClickHandler(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL a5)
{
    signed int v2; // esi
    wchar_t *v3; // eax
    signed int v4; // esi
    signed int v6; // [esp-8h] [ebp-1Ch]
    wchar_t *v7; // [esp-4h] [ebp-18h]
    char tmp[32+1]; // [esp+4h] [ebp-10h] BYREF

    if ( pElement->hoverId == 103 )
    {
        v4 = jkPlayer_GetJediRank() - 1;
        if ( v4 < 0 )
            v4 = 8;
        jkPlayer_SetRank(v4);
        stdString_snprintf(tmp, 32, "RANK_%d_L", v4);
        v7 = jkStrings_GetUniStringWithFallback(tmp);
        v6 = v4;
        v3 = jkStrings_GetUniStringWithFallback("GUI_RANK");
        goto LABEL_9;
    }
    if ( pElement->hoverId == 104 )
    {
        v2 = jkPlayer_GetJediRank() + 1;
        if ( v2 > 8 )
            v2 = 0;
        jkPlayer_SetRank(v2);
        stdString_snprintf(tmp, 32, "RANK_%d_L", v2);
        v7 = jkStrings_GetUniStringWithFallback(tmp);
        v6 = v2;
        v3 = jkStrings_GetUniStringWithFallback("GUI_RANK");
LABEL_9:
        jk_snwprintf(jkGuiBuildMulti_wTmp, 0x80u, v3, v6, v7);
        jkGuiBuildMulti_pNewCharacterElements[8].wstr = jkGuiBuildMulti_wTmp;
        jkGuiRend_UpdateAndDrawClickable(&jkGuiBuildMulti_pNewCharacterElements[8], pMenu, 1);
    }
    return 0;
}

int jkGuiBuildMulti_ShowLoad(jkPlayerMpcInfo *pPlayerMpcInfo, char *pStrEpisode, char *pJklFname, int minIdk, int rank, int bGameFormatIsJK)
{
    wchar_t *v5; // eax
    int v6; // eax
    unsigned int v7; // edi
    jkEpisode *v8; // ebp
    int v9; // esi
    wchar_t *v10; // eax
    int v11; // ebx
    int v12; // edi
    int v13; // ebp
    int v14; // esi
    jkGuiStringEntry *v16; // eax
    wchar_t *v17; // esi
    wchar_t *v18; // eax
    wchar_t *v19; // eax
    jkGuiStringEntry *v20; // eax
    wchar_t *v21; // [esp-4h] [ebp-420h]
    int v22; // [esp+10h] [ebp-40Ch]
    Darray darr; // [esp+14h] [ebp-408h] BYREF
    wchar_t name[32]; // [esp+2Ch] [ebp-3F0h] BYREF
    char tmp5[32]; // [esp+6Ch] [ebp-3B0h] BYREF
    stdStrTable strtable; // [esp+8Ch] [ebp-390h] BYREF
    char tmp1[128]; // [esp+9Ch] [ebp-380h] BYREF
    char tmp2[128]; // [esp+11Ch] [ebp-300h] BYREF
    char tmp3[128]; // [esp+19Ch] [ebp-280h] BYREF
    wchar_t wtmp1[256]; // [esp+21Ch] [ebp-200h] BYREF

    if (!Main_bMotsCompat) {
        jkGuiBuildMulti_menuLoadCharacter_buttons[16].bIsVisible = 0;
        jkGuiBuildMulti_menuLoadCharacter_buttons[17].bIsVisible = 0;

        jkGuiBuildMulti_menuLoadCharacter_buttons[10].rect.y = 210;
        jkGuiBuildMulti_menuLoadCharacter_buttons[11].rect.y = 230;

        jkGuiBuildMulti_menuLoadCharacter_buttons[12].rect.y = 270;
        jkGuiBuildMulti_menuLoadCharacter_buttons[13].rect.y = 290;

        jkGuiBuildMulti_menuLoadCharacter_buttons[14].rect.y = 330;
        jkGuiBuildMulti_menuLoadCharacter_buttons[15].rect.y = 350;
    }
    else {
        jkGuiBuildMulti_menuLoadCharacter_buttons[16].bIsVisible = 1;
        jkGuiBuildMulti_menuLoadCharacter_buttons[17].bIsVisible = 1;

        jkGuiBuildMulti_menuLoadCharacter_buttons[10].rect.y = 330;
        jkGuiBuildMulti_menuLoadCharacter_buttons[11].rect.y = 350;

        jkGuiBuildMulti_menuLoadCharacter_buttons[12].rect.y = 270;
        jkGuiBuildMulti_menuLoadCharacter_buttons[13].rect.y = 290;

        jkGuiBuildMulti_menuLoadCharacter_buttons[14].rect.y = 210;
        jkGuiBuildMulti_menuLoadCharacter_buttons[15].rect.y = 230;
    }

    name[0] = 0;
    memset(&name[1], 0, 0x3Cu);
    name[31] = 0;
    tmp5[0] = 0;
    memset(&tmp5[1], 0, 0x1Cu);
    tmp5[29] = 0;
    tmp5[30] = 0;
    tmp5[31] = 0;
    jkGui_SetModeMenu(jkGui_stdBitmaps[JKGUI_BM_BK_BUILD_LOAD]->palette);
    jkGuiRend_DarrayNewStr(&darr, 5, 1);
    jkGuiBuildMulti_menuLoadCharacter_buttons[3].clickHandlerFunc = jkGuiBuildMulti_sub_41D830;
    jkGuiBuildMulti_menuLoadCharacter_buttons[0].unistr = 0;
    v5 = jkStrings_GetUniStringWithFallback("GUI_S_MULTIPLAYER_CHARACTERS");
    jk_snwprintf(&jkGuiBuildMulti_wTmp[64], 0x40u, v5, jkPlayer_playerShortName);
    jkGuiBuildMulti_menuLoadCharacter_buttons[2].wstr = &jkGuiBuildMulti_wTmp[64];
    jkEpisode_LoadVerify();
    v6 = -1;
    v7 = 0;
    if ( jkEpisode_var2 )
    {
        v8 = jkEpisode_aEpisodes;
        while ( strcmp(pStrEpisode, v8->name) )
        {
            ++v7;
            ++v8;
            if ( v7 >= jkEpisode_var2 )
            {
                v6 = -1;
                goto LABEL_7;
            }
        }
        v6 = v7;
    }
LABEL_7:
    if ( v6 == -1 )
        jkGuiBuildMulti_menuLoadCharacter_buttons[5].wstr = 0;
    else
        jkGuiBuildMulti_menuLoadCharacter_buttons[5].wstr = jkEpisode_aEpisodes[v6].unistr;
    jkRes_LoadGob(pStrEpisode);
    stdStrTable_Load(&strtable, "misc\\cogStrings.uni");
    v9 = rank;
    jkGuiBuildMulti_menuLoadCharacter_buttons[7].wstr = jkGuiTitle_quicksave_related_func1(&strtable, pJklFname);
    stdString_snprintf(tmp5, 32, "RANK_%d_L", rank);
    v21 = jkStrings_GetUniStringWithFallback(tmp5);
    v10 = jkStrings_GetUniStringWithFallback("GUI_RANK");
    jk_snwprintf(&jkGuiBuildMulti_wTmp[32], 0x80u, v10, rank, v21);
    jkGuiBuildMulti_menuLoadCharacter_buttons[9].unistr = (char *)&jkGuiBuildMulti_wTmp[32];
    v11 = 0;
    while ( 1 )
    {
        v12 = jkGuiBuildMulti_Show2(&darr, &jkGuiBuildMulti_menuLoadCharacter_buttons[3], minIdk, v9, v11);
        jkGuiBuildMulti_sub_41D680(&jkGuiBuildMulti_menuLoadCharacter, jkGuiBuildMulti_menuLoadCharacter_buttons[3].selectedTextEntry);
        v13 = 0;
        v14 = 1;
        if ( v12 )
        {
            jkGuiRend_MenuSetReturnKeyShortcutElement(&jkGuiBuildMulti_menuLoadCharacter, &jkGuiBuildMulti_menuLoadCharacter_buttons[22]);
            jkGuiRend_MenuSetEscapeKeyShortcutElement(&jkGuiBuildMulti_menuLoadCharacter, &jkGuiBuildMulti_menuLoadCharacter_buttons[18]);
            v22 = jkGuiRend_DisplayAndReturnClicked(&jkGuiBuildMulti_menuLoadCharacter);
        }
        else
        {
            v13 = 1;
            v22 = 100;
        }
        switch ( v22 )
        {
            case -1:
                goto LABEL_18;
            case 1:
                v20 = jkGuiRend_GetStringEntry(&darr, jkGuiBuildMulti_menuLoadCharacter_buttons[3].selectedTextEntry);
                _wcsncpy(name, v20->str, 0x1Fu);
                v14 = 0;
                if ( jkPlayer_VerifyWcharName(name) )
                {
                    jkPlayer_MPCParse(pPlayerMpcInfo, &jkPlayer_playerInfos[playerThingIdx], jkPlayer_playerShortName, name, 1);
                }
                else
                {
                    v14 = 1;
                    jkGuiBuildMulti_menuLoadCharacter_buttons[0].wstr = jkStrings_GetUniStringWithFallback("ERR_BAD_PLAYER_NAME");
                }
                break;
            case 100:
                if ( jkGuiBuildMulti_ShowNewCharacter(rank, bGameFormatIsJK, v13) < 0 && !v12 ) // MOTS altered TODO
LABEL_18:
                    v14 = 0;
                break;
            case 101:
                v16 = jkGuiRend_GetStringEntry(&darr, jkGuiBuildMulti_menuLoadCharacter_buttons[3].selectedTextEntry);
                _wcsncpy(name, v16->str, 0x1Fu);
                v14 = 1;
                if ( jkPlayer_VerifyWcharName(name) )
                {
                    jkPlayer_MPCParse(
                        &jkGuiBuildMulti_aMpcInfo[jkGuiBuildMulti_menuLoadCharacter_buttons[3].selectedTextEntry],
                        &jkPlayer_playerInfos[playerThingIdx],
                        jkPlayer_playerShortName,
                        name,
                        1);
                    jkGuiBuildMulti_ShowEditCharacter(0);
                    jkPlayer_MPCWrite(&jkPlayer_playerInfos[playerThingIdx], jkPlayer_playerShortName, name);
                    v11 = jkGuiBuildMulti_menuLoadCharacter_buttons[3].selectedTextEntry;
                }
                else
                {
                    jkGuiBuildMulti_menuLoadCharacter_buttons[0].wstr = jkStrings_GetUniStringWithFallback("ERR_BAD_PLAYER_NAME");
                }
                break;
            case 102:
                v17 = jkGuiRend_GetString(&darr, jkGuiBuildMulti_menuLoadCharacter_buttons[3].selectedTextEntry);
                v18 = jkStrings_GetUniStringWithFallback("GUI_CONFIRM_REMOVE_PLAYER");
                jk_snwprintf(wtmp1, 0x100u, v18, v17);
                v19 = jkStrings_GetUniStringWithFallback("GUI_REMOVE");
                if ( jkGuiDialog_YesNoDialog(v19, wtmp1) )
                {
                    stdString_WcharToChar(tmp1, jkPlayer_playerShortName, 127);
                    tmp1[127] = 0;
                    stdFnames_MakePath(tmp2, 128, "player", tmp1);
                    stdString_WcharToChar(tmp3, v17, 127);
                    tmp3[127] = 0;
                    stdString_snprintf(tmp2, 128, "player\\%s\\%s.mpc", tmp1, tmp3);
                    stdFileUtil_DelFile(tmp2);
                }
                v14 = 1;
                v11 = 0;
                break;
            default:
                break;
        }
        if ( !v14 )
            break;
        v9 = rank;
    }
    jkGuiRend_DarrayFree(&darr);
    stdStrTable_Free(&strtable); // Added: memleak
    jkGui_SetModeGame();
    return v22;
}


void jkGuiBuildMulti_sub_41D680(jkGuiMenu *pMenu, int idx)
{
    wchar_t *v2; // eax
    wchar_t *v3; // eax
    wchar_t *v4; // eax
    wchar_t *v5; // eax
    int v6; // [esp-8h] [ebp-1Ch]
    int v7; // [esp-8h] [ebp-1Ch]
    int v8; // [esp-4h] [ebp-18h]
    wchar_t *v9; // [esp-4h] [ebp-18h]
    int v10; // [esp-4h] [ebp-18h]
    wchar_t *v11; // [esp-4h] [ebp-18h]
    char tmp1[32]; // [esp+4h] [ebp-10h] BYREF

    if ( pMenu == &jkGuiBuildMulti_menuEditCharacter )
    {
        v8 = jkGuiBuildMulti_aMpcInfo[idx].jediRank;
        jkGuiBuildMulti_menuEditCharacter_buttons[5].wstr = jkGuiBuildMulti_aMpcInfo[idx].name;
        stdString_snprintf(tmp1, 32, "RANK_%d_L", v8);
        v9 = jkStrings_GetUniStringWithFallback(tmp1);
        v6 = jkGuiBuildMulti_aMpcInfo[idx].jediRank;
        v2 = jkStrings_GetUniStringWithFallback("GUI_RANK");
        jk_snwprintf(jkGuiBuildMulti_wTmp, 0x80u, v2, v6, v9);
        jkGuiBuildMulti_menuEditCharacter_buttons[7].wstr = jkGuiBuildMulti_wTmp;
        stdFnames_CopyShortName(tmp1, 16, jkGuiBuildMulti_aMpcInfo[idx].model);
        jkGuiTitle_sub_4189A0(tmp1);
        v3 = jkStrings_GetUniStringWithFallback(tmp1);
        jk_snwprintf(jkGuiBuildMulti_wTmp2, 0x20, L"%s", v3); // ADDED: swprintf -> snwprintf
        jkGuiBuildMulti_menuEditCharacter_buttons[9].wstr = jkGuiBuildMulti_wTmp2;

        if (Main_bMotsCompat) {
            stdString_snprintf(tmp1, 32, "GUI_PERSONALITY%d", jkGuiBuildMulti_aMpcInfo[idx].personality); // Added: sprintf -> snprintf
            v3 = jkStrings_GetUniStringWithFallback(tmp1);

            jk_snwprintf(jkGuiBuildMulti_wTmp3, 0x20, L"%s", v3); // ADDED: swprintf -> snwprintf
            jkGuiBuildMulti_menuEditCharacter_buttons[11].wstr = jkGuiBuildMulti_wTmp3;
        }
    }
    else if ( pMenu == &jkGuiBuildMulti_menuLoadCharacter )
    {
        v10 = jkGuiBuildMulti_aMpcInfo[idx].jediRank;
        jkGuiBuildMulti_menuLoadCharacter_buttons[11].wstr = jkGuiBuildMulti_aMpcInfo[idx].name;
        stdString_snprintf(tmp1, 32, "RANK_%d_L", v10);
        v11 = jkStrings_GetUniStringWithFallback(tmp1);
        v7 = jkGuiBuildMulti_aMpcInfo[idx].jediRank;
        v4 = jkStrings_GetUniStringWithFallback("GUI_RANK");
        jk_snwprintf(jkGuiBuildMulti_wTmp, 0x80u, v4, v7, v11);
        jkGuiBuildMulti_menuLoadCharacter_buttons[13].wstr = jkGuiBuildMulti_wTmp;
        stdFnames_CopyShortName(tmp1, 16, jkGuiBuildMulti_aMpcInfo[idx].model);
        jkGuiTitle_sub_4189A0(tmp1);
        v5 = jkStrings_GetUniStringWithFallback(tmp1);
        jk_snwprintf(jkGuiBuildMulti_wTmp2, 0x20, L"%s", v5); // ADDED: swprintf -> snwprintf
        jkGuiBuildMulti_menuLoadCharacter_buttons[15].wstr = jkGuiBuildMulti_wTmp2;

        if (Main_bMotsCompat) {
            stdString_snprintf(tmp1, 32, "GUI_PERSONALITY%d", jkGuiBuildMulti_aMpcInfo[idx].personality); // Added: sprintf -> snprintf
            v3 = jkStrings_GetUniStringWithFallback(tmp1);

            jk_snwprintf(jkGuiBuildMulti_wTmp3, 0x20, L"%s", v3); // ADDED: swprintf -> snwprintf
            jkGuiBuildMulti_menuLoadCharacter_buttons[17].wstr = jkGuiBuildMulti_wTmp3;
        }
    }
}

int jkGuiBuildMulti_sub_41D830(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, BOOL redraw)
{
    if ( mouseX != -1 || mouseY != -1 )
        jkGuiRend_ClickSound(pElement, pMenu, mouseX, mouseY, redraw);
    jkGuiBuildMulti_sub_41D680(pMenu, pElement->selectedTextEntry);
    if ( pMenu == &jkGuiBuildMulti_menuEditCharacter )
    {
        jkGuiRend_UpdateAndDrawClickable(&jkGuiBuildMulti_menuEditCharacter_buttons[5], pMenu, 1);
        jkGuiRend_UpdateAndDrawClickable(&jkGuiBuildMulti_menuEditCharacter_buttons[7], pMenu, 1);
        jkGuiRend_UpdateAndDrawClickable(&jkGuiBuildMulti_menuEditCharacter_buttons[9], pMenu, 1);
        if (Main_bMotsCompat) {
            jkGuiRend_UpdateAndDrawClickable(&jkGuiBuildMulti_menuEditCharacter_buttons[11], pMenu, 1);
        }
        return redraw != 0;
    }
    else
    {
        if ( pMenu == &jkGuiBuildMulti_menuLoadCharacter )
        {
            jkGuiRend_UpdateAndDrawClickable(&jkGuiBuildMulti_menuLoadCharacter_buttons[11], pMenu, 1);
            jkGuiRend_UpdateAndDrawClickable(&jkGuiBuildMulti_menuLoadCharacter_buttons[13], pMenu, 1);
            jkGuiRend_UpdateAndDrawClickable(&jkGuiBuildMulti_menuLoadCharacter_buttons[15], pMenu, 1);
        }
        return redraw != 0;
    }
    return 0;
}
