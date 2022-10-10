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



static int unk_52B170[2] = {0x0d, 0x0e};

static jkGuiElement jkGuiBuildMulti_menuEditCharacter_buttons[15] =
{
  { ELEMENT_TEXT, 0, 0, NULL, 3, { 0, 390, 640, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 5, "GUI_EDIT_CHARACTER", 3, { 240, 20, 400, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 1, NULL, 3, { 240, 60, 400, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_LISTBOX, 1, 0, NULL, 0, { 280, 100, 320, 251 }, 1, 0, NULL, NULL, NULL, unk_52B170, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 2, "GUI_NAME", 3, { 0, 130, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 1, NULL, 1, { 0, 150, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 2, "GUI_RANKLABEL", 3, { 0, 190, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 1, NULL, 1, { 0, 210, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 2, "GUI_MODEL", 3, { 0, 250, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 1, NULL, 1, { 0, 270, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXTBUTTON, -1, 2, "GUI_DONE", 3, { 30, 430, 128, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXTBUTTON, 100, 2, "GUI_NEW", 3, { 250, 430, 128, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXTBUTTON, 102, 2, "GUI_REMOVE", 3, { 380, 430, 128, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXTBUTTON, 1, 2, "GUI_EDIT", 3, { 510, 430, 130, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_END, 0, 0, NULL, 0, { 0, 0, 0, 0 }, 0, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 }
};

static jkGuiMenu jkGuiBuildMulti_menuEditCharacter =
{
  &jkGuiBuildMulti_menuEditCharacter_buttons, -1, 65535, 65535, 15, NULL, NULL, jkGui_stdBitmaps, jkGui_stdFonts, 0, NULL, "thermloop01.wav", "thrmlpu2.wav", NULL, NULL, NULL, 0, NULL, NULL
};

static jkGuiElement jkGuiBuildMulti_menuNewCharacter_buttons[15] =
{
  { ELEMENT_TEXT, 0, 0, NULL, 3, { 230, 410, 410, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 5, "GUI_NEW_CHARACTER", 3, { 240, 20, 400, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 1, NULL, 3, { 240, 60, 400, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 2, "GUI_NEW_CHARACTER_CONFIG", 3, { 240, 130, 400, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 2, "GUI_MAXSTARS", 3, { 0, 30, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 0, NULL, 3, { 0, 50, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 2, "GUI_RANKLABEL", 3, { 320, 240, 240, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 0, NULL, 3, { 344, 270, 192, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_PICBUTTON, 103, 0, NULL, 33, { 320, 270, 24, 24 }, 1, 0, NULL, NULL, jkGuiBuildMulti_sub_41D000, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_PICBUTTON, 104, 0, NULL, 34, { 536, 270, 24, 24 }, 1, 0, NULL, NULL, jkGuiBuildMulti_sub_41D000, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 2, "GUI_NAME", 3, { 320, 170, 240, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXTBOX, 0, 0, NULL, 0, { 320, 200, 240, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXTBUTTON, -1, 2, "GUI_CANCEL", 3, { 0, 430, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXTBUTTON, 1, 2, "GUI_OK", 3, { 460, 430, 180, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_END, 0, 0, NULL, 0, { 0, 0, 0, 0 }, 0, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 }
};




static jkGuiMenu jkGuiBuildMulti_menuNewCharacter =
{
  &jkGuiBuildMulti_menuNewCharacter_buttons, -1, 65535, 65535, 15, NULL, NULL, jkGui_stdBitmaps, jkGui_stdFonts, 0, NULL, "thermloop01.wav", "thrmlpu2.wav", NULL, NULL, NULL, 0, NULL, NULL
};

static jkGuiElement jkGuiBuildMulti_menuLoadCharacter_buttons[22] =
{
  { ELEMENT_TEXT, 0, 0, NULL, 3, { 0, 390, 640, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 5, "GUI_LOAD_CHARACTER", 3, { 240, 20, 400, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 1, NULL, 3, { 240, 60, 400, 30 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_LISTBOX, 1, 0, NULL, 0, { 280, 100, 320, 251 }, 1, 0, NULL, NULL, NULL, unk_52B170, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 2, "GUI_SLEPISODE", 3, { 0, 30, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 0, NULL, 1, { 0, 50, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 2, "GUI_SLLEVEL", 3, { 0, 90, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 0, NULL, 1, { 0, 110, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 2, "GUI_MAXSTARS", 3, { 0, 150, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 0, NULL, 1, { 0, 170, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 2, "GUI_NAME", 3, { 0, 210, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 1, NULL, 1, { 0, 230, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 2, "GUI_RANKLABEL", 3, { 0, 270, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 1, NULL, 1, { 0, 290, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 2, "GUI_MODEL", 3, { 0, 330, 200, 20 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXT, 0, 1, NULL, 1, { 0, 350, 200, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXTBUTTON, -1, 2, "GUI_CANCEL", 3, { 0, 430, 128, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXTBUTTON, 100, 2, "GUI_NEW", 3, { 128, 430, 128, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXTBUTTON, 102, 2, "GUI_REMOVE", 3, { 256, 430, 128, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXTBUTTON, 101, 2, "GUI_EDIT", 3, { 384, 430, 128, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_TEXTBUTTON, 1, 2, "GUI_OK", 3, { 512, 430, 128, 40 }, 1, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 },
  { ELEMENT_END, 0, 0, NULL, 0, { 0, 0, 0, 0 }, 0, 0, NULL, NULL, NULL, NULL, { 0, 0, 0, 0, 0, { 0, 0, 0, 0 } }, 0 }
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
static wchar_t jkGuiBuildMulti_aWchar_5594C8[48];
static rdMaterialLoader_t jkGuiBuildMulti_fnMatLoader;
static model3Loader_t jkGuiBuildMulti_fnModelLoader;
static keyframeLoader_t jkGuiBuildMulti_fnKeyframeLoader;

static rdCanvas *jkGuiBuildMulti_pCanvas;
static rdCamera *jkGuiBuildMulti_pCamera;
static rdModel3 *jkGuiBuildMulti_model;
static rdModel3 *jkGuiBuildMulti_pModelGun;
static rdKeyframe *jkGuiBuildMulti_keyframe;
static rdThing *jkGuiBuildMulti_pThingCamera;
static rdThing *jkGuiBuildMulti_thing;
static rdThing *jkGuiBuildMulti_pThingGun;
static uint32_t jkGuiBuildMulti_startTimeSecs; // Added: float -> u32
static rdColormap jkGuiBuildMulti_colormap;
static rdLight jkGuiBuildMulti_light;
static rdMatrix34 jkGuiBuildMulti_matrix;
static stdVBuffer* jkGuiBuildMulti_pVBuf1;
static stdVBuffer* jkGuiBuildMulti_pVBuf2;
static int jkGuiBuildMulti_trackNum;
static wchar_t jkGuiBuildMulti_waTmp[128];
static wchar_t jkGuiBuildMulti_waTmp2[32];
static stdBitmap **jkGuiBuildMulti_apSaberBitmaps;
static jkSaberInfo *jkGame_aSabers;
static int jkGuiBuildMulti_bSabersLoaded;
static int jkGuiBuildMulti_bEditShowing;
static int jkGuiBuildMulti_numModels;
static int jkGuiBuildMulti_numSabers;
static int jkGuiBuildMulti_saberIdx;
static int jkGuiBuildMulti_modelIdx;
static jkMultiModelInfo *jkGuiBuildMulti_aModels;
static int jkGuiBuildMulti_renderOptions = 0x103;
static rdVector3 jkGuiBuildMulti_projectRot;
static rdVector3 jkGuiBuildMulti_projectPos;
static stdVBufferTexFmt jkGuiBuildMulti_texFmt;
static rdMatrix34 jkGuiBuildMulti_orthoProjection;
static rdVector3 jkGuiBuildMulti_lightPos;
static uint32_t jkGuiBuildMulti_lastModelDrawMs;

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
    jkGui_InitMenu(&jkGuiBuildMulti_menu, jkGui_stdBitmaps[11]);
}

void jkGuiBuildMulti_ShutdownEditCharacter()
{
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
}

void jkGuiBuildMulti_ThingCleanup()
{
    // Added
    std3D_PurgeTextureCache();

    rdPuppet_ResetTrack(jkGuiBuildMulti_thing->puppet, jkGuiBuildMulti_trackNum);
    rdKeyframe_FreeEntry(jkGuiBuildMulti_keyframe);
    rdThing_Free(jkGuiBuildMulti_thing);
    rdModel3_Free(jkGuiBuildMulti_model);
}

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
    int16_t v30; // [esp+A9h] [ebp-E3h]
    char v31; // [esp+ABh] [ebp-E1h]
    char v32[32]; // [esp+ACh] [ebp-E0h] BYREF
    char v33[32]; // [esp+CCh] [ebp-C0h] BYREF
    char v34[32]; // [esp+ECh] [ebp-A0h] BYREF
    char FileName[128]; // [esp+10Ch] [ebp-80h] BYREF

    memset(v28, 0, sizeof(v28));
    v30 = 0;
    v31 = 0;
    jkGui_SetModeMenu(jkGui_stdBitmaps[11]->palette);
    v1 = jkPlayer_GetJediRank();
    stdString_snprintf(v24, 32, "RANK_%d_L", v1);
    v21 = jkStrings_GetText(v24);
    v2 = jkStrings_GetText("GUI_RANK");
    jk_snwprintf(jkGuiBuildMulti_waTmp, 0x80u, v2, v1, v21);
    jkGuiBuildMulti_buttons[2].wstr = jkGuiBuildMulti_waTmp;
    v3 = jkStrings_GetText("GUI_S_MULTIPLAYER_CHARACTERS");
    jk_snwprintf(&jkGuiBuildMulti_waTmp[64], 0x40u, v3, jkPlayer_playerShortName);
    jkGuiBuildMulti_buttons[1].wstr = &jkGuiBuildMulti_waTmp[64];
    v4 = jkPlayer_GetMpcInfo(&jkGuiBuildMulti_waTmp[32], v28, v34, v33, v32);
    _v23 = v4;
    jkGuiBuildMulti_buttons[3].wstr = &jkGuiBuildMulti_waTmp[32];
    jkGuiRend_MenuSetLastElement(&jkGuiBuildMulti_menu, &jkGuiBuildMulti_buttons[15]);
    jkGuiRend_SetDisplayingStruct(&jkGuiBuildMulti_menu, &jkGuiBuildMulti_buttons[13]);
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
    v15 = jkStrings_GetText(v24);
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
                jkGuiForce_Show(1, 1, 0, &jkGuiBuildMulti_waTmp[32], 0, 0);
                jkGuiBuildMulti_bRendering = 1; // Added
                v16 = 1;
                break;
        }
    }
    while ( v16 );
    jkGuiBuildMulti_ThingCleanup(); // inlined

    jkGuiBuildMulti_CloseRender(); // inlined
    jkGuiBuildMulti_bRendering = 0; // Added

    jkGuiBuildMulti_bSabersLoaded = 0;
    if ( jkGuiBuildMulti_aModels )
        pHS->free(jkGuiBuildMulti_aModels);
    jkGuiBuildMulti_bEditShowing = 0;
    if ( jkGame_aSabers )
        pHS->free(jkGame_aSabers);
    for ( i = 0; i < jkGuiBuildMulti_numSabers; ++i )
        stdBitmap_Free(jkGuiBuildMulti_apSaberBitmaps[i]);
    if ( jkGuiBuildMulti_apSaberBitmaps )
        pHS->free(jkGuiBuildMulti_apSaberBitmaps);
    jkGui_SetModeGame();
    return v18;
}

int jkGuiBuildMulti_DisplayModel()
{
    stdVBufferTexFmt v1; // [esp+8h] [ebp-4Ch] BYREF

    rdOpen(0);
    rdColormap_LoadEntry("misc\\cmp\\UIColormap.cmp", &jkGuiBuildMulti_colormap);
    rdColormap_SetCurrent(&jkGuiBuildMulti_colormap);
    rdSetRenderOptions(jkGuiBuildMulti_renderOptions);
    rdSetGeometryMode(4);
    rdSetLightingMode(3);
    rdSetTextureMode(1);
    rdSetZBufferMethod(2);
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
    return rdThing_SetModel3(jkGuiBuildMulti_pThingGun, jkGuiBuildMulti_pModelGun);
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
int jkGuiBuildMulti_SaberButtonClicked(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, int a5)
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
            v3 = jkStrings_GetText(v7);
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
            v5 = jkStrings_GetText(v7);
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

    jkGui_InitMenu(&jkGuiBuildMulti_menuNewCharacter, jkGui_stdBitmaps[12]);
    jkGui_InitMenu(&jkGuiBuildMulti_menuEditCharacter, jkGui_stdBitmaps[12]);
    jkGui_InitMenu(&jkGuiBuildMulti_menuLoadCharacter, jkGui_stdBitmaps[12]);

    jkGuiBuildMulti_bInitted = 1;
    return 1;
}

void jkGuiBuildMulti_Shutdown()
{
    jkGuiBuildMulti_bInitted = 0;
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

    wPlayerName[0] = 0;
    memset(&wPlayerName[1], 0, 0x3Cu);
    wPlayerName[31] = 0;
    jkGui_SetModeMenu(jkGui_stdBitmaps[12]->palette);
    jkGuiRend_DarrayNewStr(&darr, 5, 1);
    jkGuiBuildMulti_menuEditCharacter_buttons[3].func = jkGuiBuildMulti_sub_41D830;
    jkGuiBuildMulti_menuEditCharacter_buttons[0].wstr = NULL;
    pwMultiplayerCharsStr = jkStrings_GetText("GUI_S_MULTIPLAYER_CHARACTERS");
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
            jkGuiRend_MenuSetLastElement(&jkGuiBuildMulti_menuEditCharacter, &jkGuiBuildMulti_menuEditCharacter_buttons[13]);
            jkGuiRend_SetDisplayingStruct(&jkGuiBuildMulti_menuEditCharacter, &jkGuiBuildMulti_menuEditCharacter_buttons[10]);
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
                    jkGuiBuildMulti_menuEditCharacter_buttons[0].wstr = jkStrings_GetText("ERR_BAD_PLAYER_NAME");
                }
                break;
            case 100:
                if ( jkGuiBuildMulti_ShowNewCharacter(-1, 0) < 0 && !v2 )
LABEL_8:
                    v3 = 0;
                break;
            case 102:
                v6 = jkGuiRend_GetString(&darr, jkGuiBuildMulti_menuEditCharacter_buttons[3].selectedTextEntry);
                v7 = jkStrings_GetText("GUI_CONFIRM_REMOVE_PLAYER");
                jk_snwprintf(wtmp1, 0x100u, v7, v6);
                v8 = jkStrings_GetText("GUI_REMOVE");
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

int jkGuiBuildMulti_ShowNewCharacter(int rank, int bHasValidChars)
{
    wchar_t *v2; // eax
    wchar_t *v3; // eax
    wchar_t *v4; // eax
    signed int v5; // esi
    wchar_t *v6; // eax
    int v7; // esi
    int v8; // ebp
    wchar_t *v9; // eax
    wchar_t *a2; // [esp+0h] [ebp-1A8h]
    wchar_t *a2a; // [esp+0h] [ebp-1A8h]
    wchar_t *a2b; // [esp+0h] [ebp-1A8h]
    float a2d; // [esp+0h] [ebp-1A8h]
    char v15[32]; // [esp+18h] [ebp-190h] BYREF
    char v16[128]; // [esp+28h] [ebp-180h] BYREF
    char v17[128]; // [esp+A8h] [ebp-100h] BYREF
    char v18[128]; // [esp+128h] [ebp-80h] BYREF

    jkGuiBuildMulti_menuNewCharacter_buttons[11].wstr = jkGuiBuildMulti_aWchar_5594C8;
    memset(jkGuiBuildMulti_aWchar_5594C8, 0, 0x20u);
    jkGuiBuildMulti_menuNewCharacter_buttons[11].selectedTextEntry = 16;
    if ( bHasValidChars )
    {
        a2 = jkStrings_GetText("GUI_NOVALIDCHARACTERS");
        v2 = jkStrings_GetText("GUI_NOVALIDCHARTITLE");
        jkGuiDialog_ErrorDialog(v2, a2);
    }
    v3 = jkStrings_GetText("GUI_S_MULTIPLAYER_CHARACTERS");
    jk_snwprintf(&jkGuiBuildMulti_wTmp[64], 0x40u, v3, jkPlayer_playerShortName);
    jkGuiBuildMulti_menuNewCharacter_buttons[2].wstr = &jkGuiBuildMulti_wTmp[64];
    if ( rank < 0 )
    {
        jkGuiRend_SetVisibleAndDraw(&jkGuiBuildMulti_menuNewCharacter_buttons[4], &jkGuiBuildMulti_menuNewCharacter, 0);
        jkGuiBuildMulti_menuNewCharacter_buttons[5].wstr = NULL;
    }
    else
    {
        jkGuiRend_SetVisibleAndDraw(&jkGuiBuildMulti_menuNewCharacter_buttons[4], &jkGuiBuildMulti_menuNewCharacter, 1);
        stdString_snprintf(v15, 32, "RANK_%d_L", rank);
        a2a = jkStrings_GetText(v15);
        v4 = jkStrings_GetText("GUI_RANK");
        jk_snwprintf(&jkGuiBuildMulti_wTmp[32], 0x80u, v4, rank, a2a);
        jkGuiBuildMulti_menuNewCharacter_buttons[5].wstr = &jkGuiBuildMulti_wTmp[32];
    }
    v5 = rank < 0 ? 0 : rank;
    jkPlayer_SetRank(v5);
    stdString_snprintf(v15, 32, "RANK_%d_L", v5);
    a2b = jkStrings_GetText(v15);
    v6 = jkStrings_GetText("GUI_RANK");
    jk_snwprintf(jkGuiBuildMulti_wTmp, 0x80u, v6, v5, a2b);
    jkGuiBuildMulti_menuNewCharacter_buttons[7].wstr = jkGuiBuildMulti_wTmp;
    jkGuiBuildMulti_menuNewCharacter_buttons[0].wstr = NULL;
    do
    {
        v7 = 0;
        jkGuiRend_MenuSetLastElement(&jkGuiBuildMulti_menuNewCharacter, &jkGuiBuildMulti_menuNewCharacter_buttons[13]);
        jkGuiRend_SetDisplayingStruct(&jkGuiBuildMulti_menuNewCharacter, &jkGuiBuildMulti_menuNewCharacter_buttons[12]);
        v8 = jkGuiRend_DisplayAndReturnClicked(&jkGuiBuildMulti_menuNewCharacter);
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
                v9 = jkStrings_GetText("ERR_PLAYER_ALREADY_EXISTS");
            }
            else
            {
                v7 = 1;
                memset(jkGuiBuildMulti_aWchar_5594C8, 0, 0x20u);
                v9 = jkStrings_GetText("ERR_BAD_PLAYER_NAME");
            }
        }
        else
        {
            v7 = 1;
            v9 = jkStrings_GetText("ERR_NO_PLAYER_NAME");
        }
        jkGuiBuildMulti_menuNewCharacter_buttons[0].wstr = v9;
LABEL_16:
        if ( v8 == -1 )
            return -1;
    }
    while ( v7 );
    a2d = (double)jkPlayer_GetJediRank() * 3.0;
    sithPlayer_SetBinAmt(17, a2d);
    sithPlayer_SetBinAmt(16, 0.0);
    jkPlayer_ResetPowers();
    jkPlayer_SetPlayerName(jkGuiBuildMulti_aWchar_5594C8);
    jkPlayer_mpcInfoSet = 0;
    jkGuiBuildMulti_ShowEditCharacter(1);
    jkPlayer_MPCWrite(&jkPlayer_playerInfos[playerThingIdx], jkPlayer_playerShortName, jkGuiBuildMulti_aWchar_5594C8);
    return v8;
}

int jkGuiBuildMulti_sub_41D000(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, int a5)
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
        v7 = jkStrings_GetText(tmp);
        v6 = v4;
        v3 = jkStrings_GetText("GUI_RANK");
        goto LABEL_9;
    }
    if ( pElement->hoverId == 104 )
    {
        v2 = jkPlayer_GetJediRank() + 1;
        if ( v2 > 8 )
            v2 = 0;
        jkPlayer_SetRank(v2);
        stdString_snprintf(tmp, 32, "RANK_%d_L", v2);
        v7 = jkStrings_GetText(tmp);
        v6 = v2;
        v3 = jkStrings_GetText("GUI_RANK");
LABEL_9:
        jk_snwprintf(jkGuiBuildMulti_wTmp, 0x80u, v3, v6, v7);
        jkGuiBuildMulti_menuNewCharacter_buttons[7].wstr = jkGuiBuildMulti_wTmp;
        jkGuiRend_UpdateAndDrawClickable(&jkGuiBuildMulti_menuNewCharacter_buttons[7], pMenu, 1);
    }
    return 0;
}

int jkGuiBuildMulti_ShowLoad(jkPlayerMpcInfo *pPlayerMpcInfo, char *pStrEpisode, char *pJklFname, int minIdk, int a5)
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
    __int16 v26; // [esp+6Ah] [ebp-3B2h]
    char tmp5[32]; // [esp+6Ch] [ebp-3B0h] BYREF
    stdStrTable strtable; // [esp+8Ch] [ebp-390h] BYREF
    char tmp1[128]; // [esp+9Ch] [ebp-380h] BYREF
    char tmp2[128]; // [esp+11Ch] [ebp-300h] BYREF
    char tmp3[128]; // [esp+19Ch] [ebp-280h] BYREF
    wchar_t wtmp1[256]; // [esp+21Ch] [ebp-200h] BYREF

    name[0] = 0;
    memset(&name[1], 0, 0x3Cu);
    name[31] = 0;
    tmp5[0] = 0;
    memset(&tmp5[1], 0, 0x1Cu);
    tmp5[29] = 0;
    tmp5[30] = 0;
    tmp5[31] = 0;
    jkGui_SetModeMenu(jkGui_stdBitmaps[12]->palette);
    jkGuiRend_DarrayNewStr(&darr, 5, 1);
    jkGuiBuildMulti_menuLoadCharacter_buttons[3].func = jkGuiBuildMulti_sub_41D830;
    jkGuiBuildMulti_menuLoadCharacter_buttons[0].unistr = 0;
    v5 = jkStrings_GetText("GUI_S_MULTIPLAYER_CHARACTERS");
    jk_snwprintf(&jkGuiBuildMulti_wTmp[64], 0x40u, v5, jkPlayer_playerShortName);
    jkGuiBuildMulti_menuLoadCharacter_buttons[2].wstr = (char *)&jkGuiBuildMulti_wTmp[64];
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
    v9 = a5;
    jkGuiBuildMulti_menuLoadCharacter_buttons[7].unistr = (char *)jkGuiTitle_quicksave_related_func1(&strtable, pJklFname);
    stdString_snprintf(tmp5, 32, "RANK_%d_L", a5);
    v21 = jkStrings_GetText(tmp5);
    v10 = jkStrings_GetText("GUI_RANK");
    jk_snwprintf(&jkGuiBuildMulti_wTmp[32], 0x80u, v10, a5, v21);
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
            jkGuiRend_MenuSetLastElement(&jkGuiBuildMulti_menuLoadCharacter, &jkGuiBuildMulti_menuLoadCharacter_buttons[20]);
            jkGuiRend_SetDisplayingStruct(&jkGuiBuildMulti_menuLoadCharacter, &jkGuiBuildMulti_menuLoadCharacter_buttons[16]);
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
                v26 = 0;
                if ( jkPlayer_VerifyWcharName(name) )
                {
                    jkPlayer_MPCParse(pPlayerMpcInfo, &jkPlayer_playerInfos[playerThingIdx], jkPlayer_playerShortName, name, 1);
                }
                else
                {
                    v14 = 1;
                    jkGuiBuildMulti_menuLoadCharacter_buttons[0].wstr = jkStrings_GetText("ERR_BAD_PLAYER_NAME");
                }
                break;
            case 100:
                if ( jkGuiBuildMulti_ShowNewCharacter(a5, v13) < 0 && !v12 )
LABEL_18:
                    v14 = 0;
                break;
            case 101:
                v16 = jkGuiRend_GetStringEntry(&darr, jkGuiBuildMulti_menuLoadCharacter_buttons[3].selectedTextEntry);
                _wcsncpy(name, v16->str, 0x1Fu);
                v26 = 0;
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
                    jkPlayer_MPCWrite(&jkPlayer_playerInfos[playerThingIdx], jkPlayer_playerShortName, &name);
                    v11 = jkGuiBuildMulti_menuLoadCharacter_buttons[3].selectedTextEntry;
                }
                else
                {
                    jkGuiBuildMulti_menuLoadCharacter_buttons[0].wstr = jkStrings_GetText("ERR_BAD_PLAYER_NAME");
                }
                break;
            case 102:
                v17 = jkGuiRend_GetString(&darr, jkGuiBuildMulti_menuLoadCharacter_buttons[3].selectedTextEntry);
                v18 = jkStrings_GetText("GUI_CONFIRM_REMOVE_PLAYER");
                jk_snwprintf(wtmp1, 0x100u, v18, v17);
                v19 = jkStrings_GetText("GUI_REMOVE");
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
        v9 = a5;
    }
    jkGuiRend_DarrayFree(&darr);
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
        v9 = jkStrings_GetText(tmp1);
        v6 = jkGuiBuildMulti_aMpcInfo[idx].jediRank;
        v2 = jkStrings_GetText("GUI_RANK");
        jk_snwprintf(jkGuiBuildMulti_wTmp, 0x80u, v2, v6, v9);
        jkGuiBuildMulti_menuEditCharacter_buttons[7].wstr = jkGuiBuildMulti_wTmp;
        stdFnames_CopyShortName(tmp1, 16, jkGuiBuildMulti_aMpcInfo[idx].model);
        jkGuiTitle_sub_4189A0(tmp1);
        v3 = jkStrings_GetText(tmp1);
        jk_snwprintf(jkGuiBuildMulti_wTmp2, 0x20, L"%s", v3); // ADDED: swprintf -> snwprintf
        jkGuiBuildMulti_menuEditCharacter_buttons[9].wstr = jkGuiBuildMulti_wTmp2;
    }
    else if ( pMenu == &jkGuiBuildMulti_menuLoadCharacter )
    {
        v10 = jkGuiBuildMulti_aMpcInfo[idx].jediRank;
        jkGuiBuildMulti_menuLoadCharacter_buttons[11].wstr = jkGuiBuildMulti_aMpcInfo[idx].name;
        stdString_snprintf(tmp1, 32, "RANK_%d_L", v10);
        v11 = jkStrings_GetText(tmp1);
        v7 = jkGuiBuildMulti_aMpcInfo[idx].jediRank;
        v4 = jkStrings_GetText("GUI_RANK");
        jk_snwprintf(jkGuiBuildMulti_wTmp, 0x80u, v4, v7, v11);
        jkGuiBuildMulti_menuLoadCharacter_buttons[13].wstr = jkGuiBuildMulti_wTmp;
        stdFnames_CopyShortName(tmp1, 16, jkGuiBuildMulti_aMpcInfo[idx].model);
        jkGuiTitle_sub_4189A0(tmp1);
        v5 = jkStrings_GetText(tmp1);
        jk_snwprintf(jkGuiBuildMulti_wTmp2, 0x20, L"%s", v5); // ADDED: swprintf -> snwprintf
        jkGuiBuildMulti_menuLoadCharacter_buttons[15].wstr = jkGuiBuildMulti_wTmp2;
    }
}

int jkGuiBuildMulti_sub_41D830(jkGuiElement *pElement, jkGuiMenu *pMenu, int mouseX, int mouseY, int a5)
{
    if ( mouseX != -1 || mouseY != -1 )
        jkGuiRend_ClickSound(pElement, pMenu, mouseX, mouseY, a5);
    jkGuiBuildMulti_sub_41D680(pMenu, pElement->selectedTextEntry);
    if ( pMenu == &jkGuiBuildMulti_menuEditCharacter )
    {
        jkGuiRend_UpdateAndDrawClickable(&jkGuiBuildMulti_menuEditCharacter_buttons[5], pMenu, 1);
        jkGuiRend_UpdateAndDrawClickable(&jkGuiBuildMulti_menuEditCharacter_buttons[7], pMenu, 1);
        jkGuiRend_UpdateAndDrawClickable(&jkGuiBuildMulti_menuEditCharacter_buttons[9], pMenu, 1);
        return a5 != 0;
    }
    else
    {
        if ( pMenu == &jkGuiBuildMulti_menuLoadCharacter )
        {
            jkGuiRend_UpdateAndDrawClickable(&jkGuiBuildMulti_menuLoadCharacter_buttons[11], pMenu, 1);
            jkGuiRend_UpdateAndDrawClickable(&jkGuiBuildMulti_menuLoadCharacter_buttons[13], pMenu, 1);
            jkGuiRend_UpdateAndDrawClickable(&jkGuiBuildMulti_menuLoadCharacter_buttons[15], pMenu, 1);
        }
        return a5 != 0;
    }
    return 0;
}