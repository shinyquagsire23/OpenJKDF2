#ifndef _MAINMAIN_H
#define _MAINMAIN_H

#include "types.h"
#include "globals.h"

#define Main_Startup_ADDR (0x00401000)
#define Main_Shutdown_ADDR (0x00401370)
#define Main_ParseCmdLine_ADDR (0x004014B0)
#define Main_FPrintf_ADDR (0x00401870)

#ifdef QOL_IMPROVEMENTS
extern int Main_bDedicatedServer;
extern int Main_bHeadless;
extern int Main_bVerboseNetworking;
#endif

int Main_Startup(const char *cmdline);
void Main_Shutdown();
void Main_ParseCmdLine(char *cmdline);
static int (*Main_FPrintf)(const char* fmt, ...) = (void*)Main_FPrintf_ADDR;

void Main_CheckRequiredAssets(int doInstall);

#endif // _MAINMAIN_H
