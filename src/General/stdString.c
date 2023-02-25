#include "stdString.h"

#include "jk.h"
#include "stdPlatform.h"

char* stdString_FastCopy(const char *str)
{
    char *result; // eax
    char *v2; // edx
    unsigned int v3; // ecx
    char v4; // al
    char *v5; // edi
    const char *v6; // esi

    result = (char *)std_pHS->alloc(_strlen(str) + 1);
    v2 = result;
    if ( result )
    {
        v3 = _strlen(str) + 1;
        v4 = v3;
        v3 >>= 2;
        _memcpy(v2, str, 4 * v3);
        v6 = &str[4 * v3];
        v5 = &v2[4 * v3];
        v3 = (v3 & 0xFFFFFF00) | v4 & 0xFF;
        result = v2;
        _memcpy(v5, v6, v3 & 3);
    }
    return result;
}

// Added: wchar
wchar_t* stdString_FastWCopy(const wchar_t *str)
{
    if (!str) return NULL;

    wchar_t* result = (wchar_t*)std_pHS->alloc((_wcslen(str) + 1)* sizeof(wchar_t));
    stdString_SafeWStrCopy(result, str, _wcslen(str)+1);
    return result;
}

int stdString_snprintf(char *out, int num, char *fmt, ...)
{
    int result; // eax
    va_list va; // [esp+18h] [ebp+10h]

    va_start(va, fmt);
    result = __vsnprintf(out, num - 1, fmt, va);
    out[num - 1] = 0;
    return result;
}

char* stdString_CopyBetweenDelimiter(char *instr, char *outstr, int out_size, char *find_str)
{
    char *out_; // edi
    const char *v5; // ebx
    char *str_find; // eax
    char *retval; // ebp
    size_t idk_len; // esi

    out_ = outstr;
    if ( outstr )
        *outstr = 0;
    v5 = &instr[_strspn(instr, find_str)];
    str_find = _strpbrk(v5, find_str);
    retval = str_find;
    if ( str_find )
    {
        idk_len = str_find - v5;
    }
    else
    {
        out_ = outstr;
        idk_len = _strlen(v5);
    }
    if ( idk_len >= out_size - 1 )
        idk_len = out_size - 1;
    if ( out_ )
    {
        _strncpy(out_, v5, idk_len);
        out_[idk_len] = 0;
    }
    return retval;
}

char* stdString_GetQuotedStringContents(char *in, char *out, int out_size)
{
    char *result; // eax
    char *v4; // esi
    unsigned int v5; // edx

    if ( out )
        *out = 0;
    result = _strchr(in, '"');
    if ( result )
    {
        v4 = result + 1;
        result = _strchr(result + 1, '"');
        if ( result )
        {
            if ( out )
            {
                v5 = result - v4;
                if ( result - v4 >= (unsigned int)(out_size - 1) )
                    v5 = out_size - 1;
                _memcpy(out, v4, v5);
                out[v5] = 0;
            }
            ++result;
        }
    }
    return result;
}

int stdString_CharToWchar(wchar_t *a1, const char *a2, int a3)
{
    int result; // eax
    const char *v4; // esi
    wchar_t *v5; // edx

    result = 0;
    if ( a3 <= 0 )
    {
        v5 = a1;
    }
    else
    {
        v4 = a2;
        v5 = a1;
        do
        {
            if ( !*v4 )
                break;
            *v5 = *v4;
            ++v5;
            ++v4;
            ++result;
        }
        while ( result < a3 );
    }
    if ( result < a3 )
        *v5 = 0;
    return result;
}

int stdString_WcharToChar(char *a1, const wchar_t *a2, int a3)
{
    int result; // eax
    const wchar_t *v4; // ecx
    char *v5; // esi

    result = 0;
    if ( a3 <= 0 )
    {
        v5 = a1;
    }
    else
    {
        v4 = a2;
        v5 = a1;
        do
        {
            if ( !*v4 )
                break;
            *v5 = *v4 <= 0xFFu ? *(char *)v4 : '?';
            ++v4;
            ++v5;
            ++result;
        }
        while ( result < a3 );
    }
    if ( result < a3 )
        *v5 = 0;
    return result;
}

int stdString_WstrRemoveCharsAt(wchar_t *pwaStr, int idx, int numChars)
{
    int len = _wcslen(pwaStr);
    if ( idx < len )
    {
        int totalChars = len - idx;
        if ( numChars >= totalChars )
            numChars = totalChars;

        // Added: memcpy -> memmove
        memmove(&pwaStr[idx], &pwaStr[idx + numChars], sizeof(wchar_t) * (totalChars - numChars + 1));
    }
    return len;
}

int stdString_wstrncat(wchar_t *a1, int a2, int a3, wchar_t *a4)
{
    wchar_t *v4; // ebp
    size_t v5; // ebx
    signed int v6; // eax
    wchar_t *v7; // edx
    int v8; // ebx
    intptr_t v9; // edi
    int v10; // ebx
    wchar_t *v11; // ecx
    int v12; // edx
    int v13; // ebx
    int result; // eax
    wchar_t *v15; // [esp+14h] [ebp+4h]

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
            v11 = (wchar_t *)(v9 + sizeof(wchar_t) * v10);
            v12 = (intptr_t)v7 - v9;
            v13 = v10 + 1;
            do
            {
                *v11 = *(wchar_t *)((char *)v11 + v12);
                --v11;
                --v13;
            }
            while ( v13 );
            v7 = v15;
        }
    }
    if ( v6 >= a2 - a3 - 1 )
        v6 = a2 - a3 - 1;
    _memcpy(v7, a4, 2 * v6);
    result = a2;
    v4[a2 - 1] = 0;
    return result;
}

wchar_t* stdString_CstrCopy(const char *a1)
{
    wchar_t *v1; // ebp
    signed int v2; // eax
    wchar_t *v3; // esi
    signed int v4; // ecx
    uint8_t v5; // dl

    v1 = (wchar_t *)std_pHS->alloc(sizeof(wchar_t) * (_strlen(a1) + 1));
    v2 = 0;
    v3 = v1;
    v4 = _strlen(a1);
    for (v2 = 0; v2 < v4; v2++)
    {
        v5 = a1[v2];
        if ( !v5 )
            break;
        *v3 = v5;
        ++v3;
    }
    if ( v2 < v4 )
        *v3 = 0;
    v1[_strlen(a1)] = 0;
    return v1;
}

char* stdString_WcharCopy(wchar_t *a1)
{
    size_t v1; // eax
    char *v2; // esi
    signed int v3; // ebp
    signed int v4; // edi
    wchar_t *v5; // ecx
    char *i; // edx

    v1 = _wcslen(a1);
    v2 = (char *)std_pHS->alloc(v1 + 1);
    v3 = _wcslen(a1);
    v4 = 0;
    v5 = a1;
    for ( i = v2; v4 < v3; ++v4 )
    {
        if ( !*v5 )
            break;
        *i = *v5 <= 0xFFu ? *(char *)v5 : '?';
        ++v5;
        ++i;
    }
    if ( v4 < v3 )
        *i = 0;
    v2[_wcslen(a1)] = 0;
    return v2;
}

void stdString_CStrToLower(char *a1)
{
    char *v1; // esi
    char result; // al

    v1 = a1;
    for (result = *a1; result; ++v1 )
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

wchar_t* stdString_SafeWStrCopy(wchar_t* pDst, const wchar_t* pSrc, uint32_t lenDst)
{
    _wcsncpy(pDst, pSrc, lenDst - 1);
    pDst[lenDst - 1] = 0;
    return pDst;
}