#include "sithCvar.h"

#include "General/stdString.h"
#include "General/stdStrTable.h"
#include "General/stdJSON.h"
#include "Main/jkHud.h"
#include "World/jkPlayer.h"
#include "Platform/Common/stdUpdater.h"
#include "stdPlatform.h"
#include "jk.h"

#include <assert.h>

static int sithCvar_numRegistered = 0;
static stdHashTable* sithCvar_pHashTable = NULL;
static tSithCvar sithCvar_aCvars[SITHCVAR_MAX_CVARS];
static int sithCvar_bInitted = 0;

int sithCvar_Startup()
{
    if (sithCvar_bInitted) return 1;

    sithCvar_numRegistered = 0;
    sithCvar_pHashTable = stdHashTable_New(SITHCVAR_MAX_CVARS * 2);
    memset(sithCvar_aCvars, 0, sizeof(sithCvar_aCvars));

    sithCvar_bInitted = 1;

    jkPlayer_StartupVars();
    stdUpdater_StartupCvars();

    sithCvar_LoadGlobals();

    return 1;
}

void sithCvar_Shutdown()
{
    if (!sithCvar_bInitted) return;

    sithCvar_SaveGlobals();

    for (int i = 0; i < sithCvar_numRegistered; i++)
    {
        tSithCvar* pCvar = &sithCvar_aCvars[i];

        if(pCvar->type == CVARTYPE_STR && pCvar->pStrVal) {
            pHS->free(pCvar->pStrVal);
        }
        if (pCvar->pNameLower) {
            pHS->free(pCvar->pNameLower);
        }
    }

    memset(sithCvar_aCvars, 0, sizeof(sithCvar_aCvars));
    if ( sithCvar_pHashTable )
    {
        stdHashTable_Free(sithCvar_pHashTable);
        sithCvar_pHashTable = 0;
    }
    sithCvar_numRegistered = 0;

    sithCvar_bInitted = 0;
}

int sithCvar_SaveVar(tSithCvar* pCvar, const char* pFpath)
{
    if (!pCvar) return 0;
    sithCvar_UpdateValInternal(pCvar);

    // Don't save defaults, so that stuff like the updater URL can change easily.
    if (pCvar->flags & CVARFLAG_UPDATABLE_DEFAULT)
    {
        if (pCvar->type == CVARTYPE_STR && pCvar->pStrVal && pCvar->defaultVal && !strcmp(pCvar->pStrVal, pCvar->pDefaultStrVal)) {
            return 1;
        }
        else if (pCvar->type != CVARTYPE_STR && pCvar->val == pCvar->defaultVal) {
            return 1;
        }
    }

    switch (pCvar->type) {
        case CVARTYPE_BOOL:
            stdJSON_SaveBool(pFpath, pCvar->pName, pCvar->boolVal);
            break;
        case CVARTYPE_INT:
            stdJSON_SaveInt(pFpath, pCvar->pName, pCvar->intVal);
            break;
        case CVARTYPE_FLEX:
            stdJSON_SaveFloat(pFpath, pCvar->pName, pCvar->flexVal);
            break;
        case CVARTYPE_STR:
            stdJSON_SetString(pFpath, pCvar->pName, pCvar->pStrVal);
            break;
        default:
            return 0;
    }

    return 1;
}

int sithCvar_LoadVar(tSithCvar* pCvar, const char* pFpath)
{
    char tmp[SITHCVAR_MAX_STRLEN];
    if (!pCvar) return 0;

    switch (pCvar->type) {
        case CVARTYPE_BOOL:
            pCvar->boolVal = stdJSON_GetBool(pFpath, pCvar->pName, pCvar->val);
            break;
        case CVARTYPE_INT:
            pCvar->intVal = stdJSON_GetInt(pFpath, pCvar->pName, pCvar->intVal);
            break;
        case CVARTYPE_FLEX:
            pCvar->flexVal = stdJSON_GetFloat(pFpath, pCvar->pName, pCvar->flexVal);
            break;
        case CVARTYPE_STR:
            memset(tmp, 0, SITHCVAR_MAX_STRLEN);
            stdJSON_GetString(pFpath, pCvar->pName, tmp, SITHCVAR_MAX_STRLEN, pCvar->pStrVal);
            memset((char*)pCvar->pStrVal, 0, SITHCVAR_MAX_STRLEN);
            stdString_SafeStrCopy(pCvar->pStrVal, tmp, SITHCVAR_MAX_STRLEN);
            break;
        default:
            return 0;
    }

    sithCvar_UpdateLinkInternal(pCvar);
    return 1;
}

int sithCvar_LoadLocals(const char* pFpath)
{
    for (int i = 0; i < sithCvar_numRegistered; i++)
    {
        tSithCvar* pCvar = &sithCvar_aCvars[i];

        if ((pCvar->flags & CVARFLAG_GLOBAL) == 0) {
            sithCvar_LoadVar(pCvar, pFpath);
        }
    }
    return 1;
}

int sithCvar_LoadGlobals()
{
    for (int i = 0; i < sithCvar_numRegistered; i++)
    {
        tSithCvar* pCvar = &sithCvar_aCvars[i];

        if (pCvar->flags & CVARFLAG_GLOBAL) {
            sithCvar_LoadVar(pCvar, SITHCVAR_FNAME);
        }
    }
    return 1;
}

int sithCvar_SaveLocals(const char* pFpath)
{
    stdJSON_EraseAll(pFpath);
    for (int i = 0; i < sithCvar_numRegistered; i++)
    {
        tSithCvar* pCvar = &sithCvar_aCvars[i];

        if ((pCvar->flags & CVARFLAG_GLOBAL) == 0) {
            sithCvar_SaveVar(pCvar, pFpath);
        }
    }
    return 1;
}

int sithCvar_SaveGlobals()
{
    stdJSON_EraseAll(SITHCVAR_FNAME);
    for (int i = 0; i < sithCvar_numRegistered; i++)
    {
        tSithCvar* pCvar = &sithCvar_aCvars[i];

        if (pCvar->flags & CVARFLAG_GLOBAL) {
            sithCvar_SaveVar(pCvar, SITHCVAR_FNAME);
        }
    }
    return 1;
}

int sithCvar_ResetLocals()
{
    for (int i = 0; i < sithCvar_numRegistered; i++)
    {
        tSithCvar* pCvar = &sithCvar_aCvars[i];

        if ((pCvar->flags & CVARFLAG_GLOBAL) == 0) {
            pCvar->val = pCvar->defaultVal;
        }
    }
    return 1;
}

int sithCvar_ResetGlobals()
{
    for (int i = 0; i < sithCvar_numRegistered; i++)
    {
        tSithCvar* pCvar = &sithCvar_aCvars[i];

        if (pCvar->flags & CVARFLAG_GLOBAL) {
            pCvar->val = pCvar->defaultVal;
        }
    }
    return 1;
}

tSithCvar* sithCvar_Find(const char* pName)
{
    char tmp[256];
    if (!pName) return NULL;

    memset(tmp, 0, sizeof(tmp));
    stdString_SafeStrCopy(tmp, pName, SITHCVAR_MAX_STRLEN);
    _strtolower(tmp);

    tSithCvar* pCvar = (tSithCvar*)stdHashTable_GetKeyVal(sithCvar_pHashTable, tmp);
    return pCvar;
}

int sithCvar_Register(const char* pName, int32_t type, intptr_t defaultVal, void* pLinkPtr, uint32_t flags)
{
    if (sithCvar_numRegistered >= SITHCVAR_MAX_CVARS) return 0;

    char* tmp = pHS->alloc(SITHCVAR_MAX_STRLEN);
    if (!tmp) return 0;

    tSithCvar* pCvar = &sithCvar_aCvars[sithCvar_numRegistered++];
    pCvar->pName = pName;
    pCvar->pNameLower = tmp;
    pCvar->type = type;

    pCvar->val = 0;

    switch (pCvar->type) {
        case CVARTYPE_BOOL:
            pCvar->boolVal = (int32_t)defaultVal;
            break;
        case CVARTYPE_INT:
            pCvar->intVal = (int32_t)defaultVal;
            break;
        case CVARTYPE_FLEX:
            pCvar->flexVal = *(float*)&defaultVal;
            break;
        case CVARTYPE_STR:
        {
            char* pVal = pHS->alloc(SITHCVAR_MAX_STRLEN);
            stdString_SafeStrCopy(pVal, (const char*)defaultVal, SITHCVAR_MAX_STRLEN);
            pCvar->pStrVal = pVal;
            break;
        }
    }

    pCvar->defaultVal = pCvar->val;
    pCvar->pLinkPtr = pLinkPtr;
    pCvar->flags = flags;

    memset(pCvar->pNameLower, 0, SITHCVAR_MAX_STRLEN);
    stdString_SafeStrCopy(pCvar->pNameLower, pName, SITHCVAR_MAX_STRLEN);
    _strtolower(pCvar->pNameLower);
    stdHashTable_SetKeyVal(sithCvar_pHashTable, pCvar->pNameLower, pCvar);
    
    sithCvar_UpdateLinkInternal(pCvar);

    return 1;
}

int sithCvar_RegisterStr(const char* pName, const char* pVal, void* pLinkPtr, uint32_t flags)
{
    return sithCvar_Register(pName, CVARTYPE_STR, (intptr_t)pVal, pLinkPtr, flags);
}

int sithCvar_RegisterBool(const char* pName, int32_t val, void* pLinkPtr, uint32_t flags)
{
    return sithCvar_Register(pName, CVARTYPE_BOOL, (intptr_t)val, pLinkPtr, flags);
}

int sithCvar_RegisterInt(const char* pName, int32_t val, void* pLinkPtr, uint32_t flags)
{
    return sithCvar_Register(pName, CVARTYPE_INT, (intptr_t)val, pLinkPtr, flags);
}

int sithCvar_RegisterFlex(const char* pName, float val, void* pLinkPtr, uint32_t flags)
{
    intptr_t valRaw = 0;
    *(float*)&valRaw = val;

    return sithCvar_Register(pName, CVARTYPE_FLEX, valRaw, pLinkPtr, flags);
}

int sithCvar_SetRaw(const char* pName, intptr_t val)
{
    if (!pName) return 0;

    tSithCvar* pCvar = sithCvar_Find(pName);
    if (!pCvar) return 0;

    if (pCvar->flags & CVARFLAG_READONLY) {
        return 0;
    }

    pCvar->val = val;

    return sithCvar_UpdateLinkInternal(pCvar);
}

int sithCvar_SetStr(const char* pName, const char* pVal)
{
    if (!pName) return 0;

    tSithCvar* pCvar = sithCvar_Find(pName);
    if (!pCvar) return 0;

    if(pCvar->type != CVARTYPE_STR) {
        return 0;
    }

    if (pCvar->flags & CVARFLAG_READONLY) {
        return 0;
    }

    if (!pCvar->pStrVal) {
        return 0;
    }

    stdString_SafeStrCopy(pCvar->pStrVal, pVal, SITHCVAR_MAX_STRLEN);

    return sithCvar_UpdateLinkInternal(pCvar);
}

int sithCvar_SetBool(const char* pName, int32_t val)
{
    if (!pName) return 0;

    tSithCvar* pCvar = sithCvar_Find(pName);
    if (!pCvar) return 0;

    if(pCvar->type != CVARTYPE_BOOL) {
        return 0;
    }

    if (pCvar->flags & CVARFLAG_READONLY) {
        return 0;
    }

    pCvar->boolVal = val;

    return sithCvar_UpdateLinkInternal(pCvar);
}

int sithCvar_SetInt(const char* pName, int32_t val)
{
    if (!pName) return 0;

    tSithCvar* pCvar = sithCvar_Find(pName);
    if (!pCvar) return 0;

    if(pCvar->type != CVARTYPE_INT) {
        return 0;
    }

    if (pCvar->flags & CVARFLAG_READONLY) {
        return 0;
    }

    pCvar->intVal = val;

    return sithCvar_UpdateLinkInternal(pCvar);
}

int sithCvar_SetFlex(const char* pName, float val)
{
    if (!pName) return 0;

    tSithCvar* pCvar = sithCvar_Find(pName);
    if (!pCvar) return 0;

    if(pCvar->type != CVARTYPE_FLEX) {
        return 0;
    }

    if (pCvar->flags & CVARFLAG_READONLY) {
        return 0;
    }

    pCvar->flexVal = val;

    return sithCvar_UpdateLinkInternal(pCvar);
}

int sithCvar_Link(const char* pName, void* pLinkPtr)
{
    if (!pName) return 0;

    tSithCvar* pCvar = sithCvar_Find(pName);
    if (!pCvar) return 0;

    pCvar->pLinkPtr = pLinkPtr;
    if (!pCvar->pLinkPtr) return 1;

    return sithCvar_UpdateLinkInternal(pCvar);
}

int sithCvar_UpdateLink(const char* pName)
{
    if (!pName) return 0;

    tSithCvar* pCvar = sithCvar_Find(pName);
    return sithCvar_UpdateLinkInternal(pCvar);
}

int sithCvar_UpdateLinkInternal(tSithCvar* pCvar)
{
    if (!pCvar) return 0;
    if (!pCvar->pLinkPtr) return 0;

    switch (pCvar->type) {
        case CVARTYPE_BOOL:
            *(int32_t*)pCvar->pLinkPtr = pCvar->boolVal;
            break;
        case CVARTYPE_INT:
            *(int32_t*)pCvar->pLinkPtr = pCvar->intVal;
            break;
        case CVARTYPE_FLEX:
            *(float*)pCvar->pLinkPtr = pCvar->flexVal;
            break;
        case CVARTYPE_STR:
            memset((char*)pCvar->pLinkPtr, 0, SITHCVAR_MAX_STRLEN);
            stdString_SafeStrCopy((char*)pCvar->pLinkPtr, pCvar->pStrVal, SITHCVAR_MAX_STRLEN);
            break;
    }

    if (pCvar->flags & CVARFLAG_RESETHUD) {
        jkHud_Close();
        jkHud_Open();
    }
    return 1;
}

int sithCvar_UpdateValInternal(tSithCvar* pCvar)
{
    if (!pCvar) return 0;
    if (!pCvar->pLinkPtr) return 0;

    switch (pCvar->type) {
        case CVARTYPE_BOOL:
            pCvar->boolVal = *(int32_t*)pCvar->pLinkPtr;
            break;
        case CVARTYPE_INT:
            pCvar->intVal = *(int32_t*)pCvar->pLinkPtr;
            break;
        case CVARTYPE_FLEX:
            pCvar->flexVal = *(float*)pCvar->pLinkPtr;
            break;
        case CVARTYPE_STR:
            stdString_SafeStrCopy(pCvar->pStrVal, (char*)pCvar->pLinkPtr, SITHCVAR_MAX_STRLEN);
            break;
    }
    return 1;
}

const char* sithCvar_GetStr(const char* pName)
{
    if (!pName) return NULL;

    tSithCvar* pCvar = sithCvar_Find(pName);
    if (!pCvar) return "";

    if(pCvar->type != CVARTYPE_STR) {
        return "INVALID";
    }

    sithCvar_UpdateValInternal(pCvar);

    return pCvar->pStrVal;
}

int32_t sithCvar_GetBool(const char* pName)
{
    if (!pName) return 0;

    tSithCvar* pCvar = sithCvar_Find(pName);
    if (!pCvar) return 0;

    if(pCvar->type != CVARTYPE_BOOL) {
        return 0;
    }

    sithCvar_UpdateValInternal(pCvar);

    return pCvar->boolVal;
}

int32_t sithCvar_GetInt(const char* pName)
{
    if (!pName) return -1;

    tSithCvar* pCvar = sithCvar_Find(pName);
    if (!pCvar) return -1;

    if(pCvar->type != CVARTYPE_INT) {
        return -1;
    }

    sithCvar_UpdateValInternal(pCvar);

    return pCvar->intVal;
}

float sithCvar_GetFlex(const char* pName)
{
    if (!pName) return -1;

    tSithCvar* pCvar = sithCvar_Find(pName);
    if (!pCvar) return -1;

    if(pCvar->type != CVARTYPE_FLEX) {
        return -1;
    }

    sithCvar_UpdateValInternal(pCvar);

    return pCvar->flexVal;
}

void sithCvar_Enumerate(sithCvarEnumerationFn_t fnCallback)
{
    if (!fnCallback) return;

    for (int i = 0; i < sithCvar_numRegistered; i++)
    {
        fnCallback(&sithCvar_aCvars[i]);
    }
}

void sithCvar_ToString(const char* pName, char* pOut, int outSize)
{
    if (!pOut || !outSize) return;
    memset(pOut, 0, outSize);

    tSithCvar* pCvar = sithCvar_Find(pName);
    if (!pCvar) {
        return;
    }

    switch (pCvar->type) {
        case CVARTYPE_BOOL:
            stdString_SafeStrCopy(pOut, pCvar->boolVal ? "1" : "0", outSize);
            break;
        case CVARTYPE_INT:
            stdString_snprintf(pOut, outSize, "%d", pCvar->intVal);
            break;
        case CVARTYPE_FLEX:
            stdString_snprintf(pOut, outSize, "%f", pCvar->flexVal);
            break;
        case CVARTYPE_STR:
            stdString_SafeStrCopy(pOut, pCvar->pStrVal, SITHCVAR_MAX_STRLEN);
            break;
    }
}

int sithCvar_SetFromString(const char* pName, const char* pStrVal)
{
    if (!pName || !pStrVal) return 0;

    tSithCvar* pCvar = sithCvar_Find(pName);
    if (!pCvar) {
        return 0;
    }

    if (pCvar->flags & CVARFLAG_READONLY) {
        return 0;
    }

    float readValFlex = 0.0;
    int readValInt = 0;

    switch (pCvar->type) {
        case CVARTYPE_BOOL:
            if (!__strcmpi(pStrVal, "true") || !__strcmpi(pStrVal, "t") || !__strcmpi(pStrVal, "yes") || !__strcmpi(pStrVal, "y") || !__strcmpi(pStrVal, "on")) {
                pCvar->boolVal = 1;
            }
            else if (!__strcmpi(pStrVal, "false") || !__strcmpi(pStrVal, "f") || !__strcmpi(pStrVal, "no") || !__strcmpi(pStrVal, "n") || !__strcmpi(pStrVal, "off")) {
                pCvar->boolVal = 0;
            }
            else if (_sscanf(pStrVal, "%d", &readValInt) == 1) {
                pCvar->boolVal = !!readValInt;
            }
            else {
                return 0;
            }
            return sithCvar_UpdateLinkInternal(pCvar);
        case CVARTYPE_INT:
            if (_sscanf(pStrVal, "%d", &readValInt) == 1) {
                pCvar->intVal = readValInt;
            }
            else {
                return 0;
            }
            return sithCvar_UpdateLinkInternal(pCvar);
        case CVARTYPE_FLEX:
            if (_sscanf(pStrVal, "%f", &readValFlex) == 1) {
                pCvar->flexVal = readValFlex;
            }
            else {
                return 0;
            }
            return sithCvar_UpdateLinkInternal(pCvar);
        case CVARTYPE_STR:
            stdString_SafeStrCopy(pCvar->pStrVal, pStrVal, SITHCVAR_MAX_STRLEN);
            return sithCvar_UpdateLinkInternal(pCvar);
    }
}