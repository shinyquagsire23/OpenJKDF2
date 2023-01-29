#ifndef _PLATFORM_GL_JKGM_H
#define _PLATFORM_GL_JKGM_H

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"

typedef void (*stdJSONCallback_t)(const char* pKey, const char* pVal, void *pCtx);

int stdJSON_SaveInt(const char* pFpath, const char* pKey, int val);
int stdJSON_SaveFloat(const char* pFpath, const char* pKey, float val);
int stdJSON_GetInt(const char* pFpath, const char* pKey, int valDefault);
float stdJSON_GetFloat(const char* pFpath, const char* pKey, float valDefault);
int stdJSON_SaveBool(const char* pFpath, const char* pKey, int bVal);
int stdJSON_GetBool(const char* pFpath, const char* pKey, int bValDefault);
int stdJSON_SaveBytes(const char* pFpath, const char* pKey, uint8_t *lpData, uint32_t lenMax);
int stdJSON_GetBytes(const char* pFpath, const char* pKey, uint8_t* pValDefault, uint32_t lenDefault);
int stdJSON_SetString(const char* pFpath, const char* pKey, const char *pVal);
int stdJSON_GetString(const char* pFpath, const char* pKey, char* pOut, int outSize, const char *pValDefault);
int stdJSON_SetWString(const char* pFpath, const char* pKey, const char16_t *pVal);
int stdJSON_GetWString(const char* pFpath, const char* pKey, char16_t* pOut, int outSize, const char16_t *pValDefault);

int stdJSON_IterateKeys(const char* pFpath, stdJSONCallback_t pCallbackFn, void* pCtx);
int stdJSON_EraseKey(const char* pFpath, const char* pKey);
int stdJSON_EraseAll(const char* pFpath);

#ifdef __cplusplus
}
#endif

#endif // _PLATFORM_GL_JKGM_H