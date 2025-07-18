#include "types.h"

int32_t openjkdf2_bSkipWorkingDirData = 0;
int32_t openjkdf2_bIsFirstLaunch = 1;
int32_t openjkdf2_bIsRunningFromExistingInstall = 0; // 1 is OpenJKDF2 acting as a JK.EXE replacement, 0 is running as a launcher.
int32_t openjkdf2_bOrigWasRunningFromExistingInstall = 0;
int32_t openjkdf2_bOrigWasDF2 = 0;
int32_t openjkdf2_bIsKVM = 1;
int32_t openjkdf2_bIsLowMemoryPlatform = 0; // 32MiB
int32_t openjkdf2_bIsExtraLowMemoryPlatform = 0; // 16MiB
int32_t openjkdf2_mem_alt_mspace_valid = 0;
int32_t openjkdf2_restartMode = OPENJKDF2_RESTART_NONE;
char openjkdf2_aOrigCwd[1024];
char openjkdf2_aRestartPath[256];
char* openjkdf2_pExecutablePath = "";