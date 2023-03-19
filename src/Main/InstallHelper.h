#ifndef _MAIN_INSTALLHELPER_H

#include "types.h"

#if defined(PLATFORM_POSIX)
#include <locale.h>
#endif

#if defined(SDL2_RENDER)
#include "SDL2_helper.h"
#ifndef _WIN32
#include <unistd.h>
#endif // _WIN32
#include <sys/types.h>
#include <stdbool.h>
#if defined(LINUX) || defined(MACOS)
#include <pwd.h>
#endif // defined(LINUX) || defined(MACOS)
#include "nfd.h"
#endif // defined(SDL2_RENDER)

#ifdef LINUX
#include "external/fcaseopen/fcaseopen.h"
#endif

#if defined(SDL2_RENDER) && !defined(ARCH_WASM)

int InstallHelper_copy(const char* in_path, const char* out_path);
int InstallHelper_CopyFile(const char* pFolder, const char* pName);
int InstallHelper_CopyFileDisk(const char* pFolder, const char* pName);
int InstallHelper_GetLocalDataDir(char* pOut, size_t pOut_sz, int bChdir);
int InstallHelper_UseLocalData();
int InstallHelper_AttemptInstallFromExisting(nfdu8char_t* path);
int InstallHelper_AttemptInstallFromDisk(nfdu8char_t* path);
int InstallHelper_AttemptInstall();
void InstallHelper_CheckRequiredAssets(int doInstall);
void InstallHelper_SetCwd();
#else
void InstallHelper_SetCwd();
#endif // defined(SDL2_RENDER) && !defined(ARCH_WASM)

#endif // _MAIN_INSTALLHELPER_H