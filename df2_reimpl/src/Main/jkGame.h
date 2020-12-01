#ifndef _JKGAME_H
#define _JKGAME_H

#include "jk.h"

#define jkGame_SetDefaultSettings_ADDR (0x00401480)
#define jkGame_ForceRefresh_ADDR (0x00401EC0)
#define jkGame_Update_ADDR (0x00401EE0)
#define jkGame_cam_idk_maybe_ADDR (0x00402230)
#define jkGame_Screensize2_ADDR (0x00402540)
#define jkGame_Screensize_ADDR (0x00402570)
#define jkGame_Gamma_ADDR (0x004025A0)
#define jkGame_Screenshot_ADDR (0x004025E0)
#define jkGame_ddraw_idk_palettes_ADDR (0x004027C0)
#define jkGame_nullsub_36_ADDR (0x00402810)
#define jkGame_Initialize_ADDR (0x00402820)
#define jkGame_Shutdown_ADDR (0x00402840)
#define jkGame_ParseSection_ADDR (0x00402850)

typedef struct sithThing sithThing;

#define pHS (*(common_functions**)0x860440)

#define g_sithMode (*(int*)0x8EE660)
#define g_submodeFlags (*(int*)0x8EE664)
#define g_debugmodeFlags (*(int*)0x8EE66C)
//#define g_playersetDifficulty (*(int*)0x8EE670)
#define g_mapModeFlags (*(int*)0x8EE674)

static void (*jkGame_SetDefaultSettings)() = (void*)jkGame_SetDefaultSettings_ADDR;

#endif // _JKGAME_H
