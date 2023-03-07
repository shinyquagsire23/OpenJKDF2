#ifndef _PLATFORM_COMMON_STD_UPDATER_H
#define _PLATFORM_COMMON_STD_UPDATER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"

int stdUpdater_CheckForUpdates();
void stdUpdater_GetUpdateText(char* pOut, size_t outSz);

#ifdef __cplusplus
}
#endif

#endif // _PLATFORM_COMMON_STD_UPDATER_H