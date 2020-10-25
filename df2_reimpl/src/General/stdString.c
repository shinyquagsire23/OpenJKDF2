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
