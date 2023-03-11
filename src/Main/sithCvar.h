#ifndef _OPENJKDF2_SITH_CVAR_H
#define _OPENJKDF2_SITH_CVAR_H

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"

int sithCvar_Startup();
void sithCvar_Shutdown();
tSithCvar* sithCvar_Find(const char* pName);
int sithCvar_LoadLocals(const char* pFpath);
int sithCvar_LoadGlobals();
int sithCvar_SaveLocals(const char* pFpath);
int sithCvar_SaveGlobals();
int sithCvar_ResetLocals();
int sithCvar_ResetGlobals();

int sithCvar_Register(const char* pName, int32_t type, intptr_t defaultVal, void* pLinkPtr, uint32_t flags);
int sithCvar_RegisterStr(const char* pName, const char* pVal, void* pLinkPtr, uint32_t flags);
int sithCvar_RegisterBool(const char* pName, int32_t val, void* pLinkPtr, uint32_t flags);
int sithCvar_RegisterInt(const char* pName, int32_t val, void* pLinkPtr, uint32_t flags);
int sithCvar_RegisterFlex(const char* pName, float val, void* pLinkPtr, uint32_t flags);

int sithCvar_SetRaw(const char* pName, intptr_t val);
int sithCvar_SetStr(const char* pName, const char* pVal);
int sithCvar_SetBool(const char* pName, int32_t val);
int sithCvar_SetInt(const char* pName, int32_t val);
int sithCvar_SetFlex(const char* pName, float val);

int sithCvar_Link(const char* pName, void* pLinkPtr);
int sithCvar_UpdateLink(const char* pName);
int sithCvar_UpdateLinkInternal(tSithCvar* pCvar);
int sithCvar_UpdateValInternal(tSithCvar* pCvar);

const char* sithCvar_GetStr(const char* pName);
int32_t sithCvar_GetBool(const char* pName);
int32_t sithCvar_GetInt(const char* pName);
float sithCvar_GetFlex(const char* pName);

void sithCvar_Enumerate(sithCvarEnumerationFn_t fnCallback);
void sithCvar_ToString(const char* pName, char* pOut, int outSize);
int sithCvar_SetFromString(const char* pName, const char* pStrVal);

#ifdef __cplusplus
}
#endif

#endif // _OPENJKDF2_SITH_CVAR_H