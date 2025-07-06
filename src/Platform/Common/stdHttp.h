#ifndef _PLATFORM_COMMON_STD_HTTP_H
#define _PLATFORM_COMMON_STD_HTTP_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

void stdHttp_Startup();
void stdHttp_Shutdown();
void* stdHttp_Fetch(const char* pUrl);
int stdHttp_DownloadToPath(const char* pUrl, const char* pFpath);

#ifdef __cplusplus
}
#endif

#endif // _PLATFORM_COMMON_STD_HTTP_H