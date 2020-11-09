#ifndef _JKGAME_H
#define _JKGAME_H

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
#define jkGame_GetCurrentGuiState_ADDR (0x00402C00)
#define jkGame_SetVideoMode_ADDR (0x00402D00)
#define jkGame_SetVideoModeGdi_ADDR (0x00402E40)

#define g_sithMode (*(int*)0x8EE660)
#define g_submodeFlags (*(int*)0x8EE664)
#define g_debugmodeFlags (*(int*)0x8EE66C)
#define g_playersetDifficulty (*(int*)0x8EE670)

static int (*jkGame_GetCurrentGuiState)() = (void*)jkGame_GetCurrentGuiState_ADDR;

#endif // _JKGAME_H
