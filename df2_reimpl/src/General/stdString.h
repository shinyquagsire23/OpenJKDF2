#ifndef _STDSTRING_H
#define _STDSTRING_H

#include <stdint.h>

#define stdString_FastCopy_ADDR (0x0042F120)
#define stdString_snprintf_ADDR (0x0042F170)
#define stdString_CopyBetweenDelimiter_ADDR (0x0042F1A0)
#define stdString_GetQuotedStringContents_ADDR (0x0042F210)
#define stdString_CharToWchar_ADDR (0x0042F280)
#define stdString_WcharToChar_ADDR (0x0042F2C0)
#define stdString_wstrncpy_ADDR (0x0042F310)
#define stdString_wstrncat_ADDR (0x0042F360)
#define stdString_CstrCopy_ADDR (0x0042F400)
#define stdString_WcharCopy_ADDR (0x0042F470)
#define stdString_CStrToLower_ADDR (0x0042F4F0)


char* stdString_FastCopy(const char *str);
//static int (*stdString_snprintf)(char *out, int num, char *fmt, ...) = stdString_snprintf_ADDR;
int stdString_snprintf(char *out, int num, char *fmt, ...);
char* stdString_CopyBetweenDelimiter(char *instr, char *outstr, int out_size, char *find_str);
char* stdString_GetQuotedStringContents(char *in, char *out, int out_size);
int stdString_CharToWchar(uint16_t *a1, char *a2, int a3);
int stdString_WcharToChar(char *a1, uint16_t *a2, int a3);
int stdString_wstrncpy(wchar_t *a1, int a2, int a3);
int stdString_wstrncat(wchar_t *a1, int a2, int a3, wchar_t *a4);
wchar_t *__cdecl stdString_CstrCopy(const char *a1);
char* stdString_WcharCopy(wchar_t *a1);
void stdString_CStrToLower(char *a1);

#endif // _STDSTRING_H
