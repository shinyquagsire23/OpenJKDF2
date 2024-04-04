#ifndef _PLATFORM_COMMON_EMBEDDED_RESOURCE_H
#define _PLATFORM_COMMON_EMBEDDED_RESOURCE_H

#ifdef __cplusplus
extern "C" {
#endif


#include "types.h"

char* stdEmbeddedRes_LoadOnlyInternal(const char* filepath, size_t* pOutSz);
char* stdEmbeddedRes_Load(const char* filepath, size_t* pOutSz);

#ifdef __cplusplus
}
#endif


#endif // _PLATFORM_COMMON_EMBEDDED_RESOURCE_H