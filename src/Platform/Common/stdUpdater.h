#ifndef _PLATFORM_COMMON_STD_UPDATER_H
#define _PLATFORM_COMMON_STD_UPDATER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"

void stdUpdater_StartupCvars();
int stdUpdater_CheckForUpdates();
void stdUpdater_GetUpdateText(wchar_t* pOut, size_t outSz);
void stdUpdater_DoUpdate();

#ifdef __cplusplus
}
#endif

#endif // _PLATFORM_COMMON_STD_UPDATER_H