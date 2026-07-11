#include "stdString.h"

#include "jk.h"
#include "stdPlatform.h"

char* stdString_FastCopy(const char *pSource)
{
    char *result; // eax
    char *v2; // edx
    unsigned int v3; // ecx
    char v4; // al
    char *v5; // edi
    const char *v6; // esi

    { TWL_EXTRAM_SUGGEST(std_g_pHS); // Added: strings are read-only after creation
    result = (char *)STD_ALLOC(_strlen(pSource) + 1);
    TWL_EXTRAM_RESTORE(std_g_pHS); }
    v2 = result;
    if ( result )
    {
        // Added: word-safe copy (destination may be word-addressable-only)
        stdPlatform_Memcpy32(v2, pSource, _strlen(pSource) + 1);
    }
    return result;
}

// Added: wchar
char16_t* stdString_FastWCopy(const char16_t *str)
{
    if (!str) return NULL;

    char16_t* result;
    { TWL_EXTRAM_SUGGEST(std_g_pHS); // Added: wchar stores are 16-bit -> word-safe
    result = (char16_t*)STD_ALLOC((_wcslen(str) + 1)* sizeof(char16_t));
    TWL_EXTRAM_RESTORE(std_g_pHS); }
    stdString_SafeWStrCopy(result, str, _wcslen(str)+1);
    return result;
}

int stdString_snprintf(char *pStr, int size, const char *format, ...)
{
    int result; // eax
    va_list va; // [esp+18h] [ebp+10h]

    va_start(va, format);
    result = __vsnprintf(pStr, size - 1, format, va);
    va_end(va);
    pStr[size - 1] = 0;
    return result;
}

char* stdString_CopyBetweenDelimiter(char *pSource, char *pFirstToken, int maxTokenLenght, char *pSeparators)
{
    char *out_; // edi
    const char *v5; // ebx
    const char *str_find; // eax
    char *retval; // ebp
    size_t idk_len; // esi

    out_ = pFirstToken;
    if ( pFirstToken )
        *pFirstToken = 0;
    v5 = &pSource[_strspn(pSource, pSeparators)];
    str_find = _strpbrk(v5, pSeparators);
    retval = (char*)str_find;
    if ( str_find )
    {
        idk_len = str_find - v5;
    }
    else
    {
        out_ = pFirstToken;
        idk_len = _strlen(v5);
    }
    if ( idk_len >= maxTokenLenght - 1 )
        idk_len = maxTokenLenght - 1;
    if ( out_ )
    {
        _strncpy(out_, v5, idk_len);
        out_[idk_len] = 0;
    }
    return retval;
}

char* stdString_GetQuotedStringContents(char *pSource, char *pDest, int destSize)
{
    char *result; // eax
    char *v4; // esi
    unsigned int v5; // edx

    if ( pDest )
        *pDest = 0;
    result = _strchr(pSource, '"');
    if ( result )
    {
        v4 = result + 1;
        result = _strchr(result + 1, '"');
        if ( result )
        {
            if ( pDest )
            {
                v5 = result - v4;
                if ( result - v4 >= (unsigned int)(destSize - 1) )
                    v5 = destSize - 1;
                _memcpy(pDest, v4, v5);
                pDest[v5] = 0;
            }
            ++result;
        }
    }
    return result;
}

int stdString_CharToWchar(char16_t *pwString, const char *pString, int maxChars)
{
    int result; // eax
    const char *v4; // esi
    char16_t *v5; // edx

    result = 0;
    if ( maxChars <= 0 )
    {
        v5 = pwString;
    }
    else
    {
        v4 = pString;
        v5 = pwString;
        do
        {
            if ( !*v4 )
                break;
            *v5 = *v4;
            ++v5;
            ++v4;
            ++result;
        }
        while ( result < maxChars );
    }
    if ( result < maxChars )
        *v5 = 0;
    return result;
}

int stdString_WcharToChar(char *pString, const char16_t *pwString, int maxChars)
{
    int result; // eax
    const char16_t *v4; // ecx
    char *v5; // esi

    result = 0;
    if ( maxChars <= 0 )
    {
        v5 = pString;
    }
    else
    {
        v4 = pwString;
        v5 = pString;
        do
        {
            if ( !*v4 )
                break;
            *v5 = *v4 <= 0xFFu ? *(char *)v4 : '?';
            ++v4;
            ++v5;
            ++result;
        }
        while ( result < maxChars );
    }
    if ( result < maxChars )
        *v5 = 0;
    return result;
}

int stdString_WstrRemoveCharsAt(char16_t *pwaStr, int idx, int numChars)
{
    int len = _wcslen(pwaStr);
    if ( idx < len )
    {
        int totalChars = len - idx;
        if ( numChars >= totalChars )
            numChars = totalChars;

        // Added: memcpy -> memmove
        memmove(&pwaStr[idx], &pwaStr[idx + numChars], sizeof(char16_t) * (totalChars - numChars + 1));
    }
    return len;
}

int stdString_wstrncat(char16_t *a1, int a2, int a3, char16_t *a4)
{
    char16_t *v4; // ebp
    size_t v5; // ebx
    signed int v6; // eax
    char16_t *v7; // edx
    int v8; // ebx
    intptr_t v9; // edi
    int v10; // ebx
    char16_t *v11; // ecx
    int v12; // edx
    int v13; // ebx
    int result; // eax
    char16_t *v15; // [esp+14h] [ebp+4h]

    v4 = a1;
    v5 = _wcslen(a1);
    v6 = _wcslen(a4);
    v7 = &a1[a3];
    v8 = v5 - a3 + 1;
    v15 = &a1[a3];
    v9 = (intptr_t)&v4[v6 + a3];
    if ( v8 >= a2 - a3 - v6 )
        v8 = a2 - a3 - v6;
    if ( v8 > 0 )
    {
        v10 = v8 - 1;
        if ( v10 >= 0 )
        {
            v11 = (char16_t *)(v9 + sizeof(char16_t) * v10);
            v12 = (intptr_t)v7 - v9;
            v13 = v10 + 1;
            do
            {
                *v11 = *(char16_t *)((char *)v11 + v12);
                --v11;
                --v13;
            }
            while ( v13 );
            v7 = v15;
        }
    }
    if ( v6 >= a2 - a3 - 1 )
        v6 = a2 - a3 - 1;
    _memcpy(v7, a4, sizeof(char16_t) * v6);
    result = a2;
    v4[a2 - 1] = 0;
    return result;
}

char16_t* stdString_CstrCopy(const char *pString)
{
    char16_t *v1; // ebp
    signed int v2; // eax
    char16_t *v3; // esi
    signed int v4; // ecx
    uint8_t v5; // dl

    { TWL_EXTRAM_SUGGEST(std_g_pHS); // Added: fill loop below stores 16-bit wchars
    v1 = (char16_t *)STD_ALLOC(sizeof(char16_t) * (_strlen(pString) + 1));
    TWL_EXTRAM_RESTORE(std_g_pHS); }
    v2 = 0;
    v3 = v1;
    v4 = _strlen(pString);
    for (v2 = 0; v2 < v4; v2++)
    {
        v5 = pString[v2];
        if ( !v5 )
            break;
        *v3 = v5;
        ++v3;
    }
    if ( v2 < v4 )
        *v3 = 0;
    v1[_strlen(pString)] = 0;
    return v1;
}

char* stdString_WcharCopy(char16_t *pwString)
{
    size_t v1; // eax
    char *v2; // esi
    signed int v3; // ebp
    signed int v4; // edi
    char16_t *v5; // ecx
    char *i; // edx

    v1 = _wcslen(pwString);
    { TWL_EXTRAM_SUGGEST(std_g_pHS); // Added: filled via 16-bit RMW below
    v2 = (char *)STD_ALLOC(v1 + 1);
    TWL_EXTRAM_RESTORE(std_g_pHS); }
    v3 = _wcslen(pwString);
    v4 = 0;
    v5 = pwString;
    for ( i = v2; v4 < v3; ++v4 )
    {
        if ( !*v5 )
            break;
        stdPlatform_WriteByte16(i, *v5 <= 0xFFu ? (uint8_t)*v5 : '?'); // Added: word-safe byte store
        ++v5;
        ++i;
    }
    if ( v4 < v3 )
        stdPlatform_WriteByte16(i, 0); // Added: word-safe
    stdPlatform_WriteByte16(&v2[_wcslen(pwString)], 0); // Added: word-safe
    return v2;
}

void stdString_CStrToLower(char *pStr)
{
    char *v1; // esi
    char result; // al

    v1 = pStr;
    for (result = *pStr; result; ++v1 )
    {
        *v1 = __tolower(result);
        result = v1[1];
    }
}

// Added: These were macros or something
char* stdString_SafeStrCopy(char* pDst, const char* pSrc, uint32_t lenDst)
{
    _strncpy(pDst, pSrc, lenDst - 1);
    pDst[lenDst - 1] = 0;
    return pDst;
}

char16_t* stdString_SafeWStrCopy(char16_t* pDst, const char16_t* pSrc, uint32_t lenDst)
{
    _wcsncpy(pDst, pSrc, lenDst - 1);
    pDst[lenDst - 1] = 0;
    return pDst;
}