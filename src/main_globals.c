#include "types.h"

int openjkdf2_bSkipWorkingDirData = 0;
int openjkdf2_bIsFirstLaunch = 1;
int openjkdf2_bIsRunningFromExistingInstall = 0; // 1 is OpenJKDF2 acting as a JK.EXE replacement, 0 is running as a launcher.
int openjkdf2_bOrigWasRunningFromExistingInstall = 0;
int openjkdf2_bOrigWasDF2 = 0;
int openjkdf2_bIsKVM = 1;
int openjkdf2_restartMode = OPENJKDF2_RESTART_NONE;
char openjkdf2_aOrigCwd[1024];
char openjkdf2_aRestartPath[256];
char* openjkdf2_pExecutablePath = "";