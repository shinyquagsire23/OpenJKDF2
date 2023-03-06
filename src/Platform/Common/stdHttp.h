#ifndef _PLATFORM_COMMON_STD_HTTP_H
#define _PLATFORM_COMMON_STD_HTTP_H

#include "types.h"

void stdHttp_Startup();
void stdHttp_Shutdown();
void* stdHttp_Fetch(const char* pUrl);

#endif // _PLATFORM_COMMON_STD_HTTP_H