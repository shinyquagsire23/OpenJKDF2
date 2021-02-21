#ifndef _MAINMAIN_H
#define _MAINMAIN_H

#define Main_Startup_ADDR (0x00401000)
#define Main_Shutdown_ADDR (0x00401370)
#define Main_ParseCmdLine_ADDR (0x004014B0)
#define Main_FPrintf_ADDR (0x00401870)

#define Main_bDevMode (*(int*)0x00860780)
#define Main_bDisplayConfig (*(int*)0x00860784)
#define Main_bWindowGUI (*(int*)0x00860788)
#define Main_dword_86078C (*(int*)0x86078C)
#define Main_bFrameRate (*(int*)0x00860790)
#define Main_bDispStats (*(int*)0x00860794)
#define Main_bNoHUD (*(int*)0x00860798)
#define Main_logLevel (*(int*)0x0086079C)
#define Main_verboseLevel (*(int*)0x008607A0)
#define Main_path ((char*)0x008606E4)
#define debug_log_fp (*(FILE**)0x00552880)

#define pHS (*(common_functions**)0x860440)

int Main_Startup(const char *cmdline);
static void (*Main_ParseCmdLine)(char *cmdline) = (void*)Main_ParseCmdLine_ADDR;
static int (*Main_FPrintf)(const char* fmt, ...) = (void*)Main_FPrintf_ADDR;

#endif // _MAINMAIN_H
