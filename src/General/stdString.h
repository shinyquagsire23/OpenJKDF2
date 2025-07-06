#ifndef _STDSTRING_H
#define _STDSTRING_H

#include "types.h"
#include "jk.h"

#ifdef __cplusplus
extern "C" {
#endif

#define stdString_FastCopy_ADDR (0x0042F120)
#define stdString_snprintf_ADDR (0x0042F170)
#define stdString_CopyBetweenDelimiter_ADDR (0x0042F1A0)
#define stdString_GetQuotedStringContents_ADDR (0x0042F210)
#define stdString_CharToWchar_ADDR (0x0042F280)
#define stdString_WcharToChar_ADDR (0x0042F2C0)
#define stdString_WstrRemoveCharsAt_ADDR (0x0042F310)
#define stdString_wstrncat_ADDR (0x0042F360)
#define stdString_CstrCopy_ADDR (0x0042F400)
#define stdString_WcharCopy_ADDR (0x0042F470)
#define stdString_CStrToLower_ADDR (0x0042F4F0)


char* stdString_FastCopy(const char *str);
wchar_t* stdString_FastWCopy(const wchar_t *str); // Added
int stdString_snprintf(char *out, int num, const char *fmt, ...);
char* stdString_CopyBetweenDelimiter(char *instr, char *outstr, int out_size, char *find_str);
char* stdString_GetQuotedStringContents(char *in, char *out, int out_size);
int stdString_CharToWchar(wchar_t *a1, const char *a2, int a3);
int stdString_WcharToChar(char *a1, const wchar_t *a2, int a3);
int stdString_WstrRemoveCharsAt(wchar_t *pwaStr, int idx, int numChars);
int stdString_wstrncat(wchar_t *a1, int a2, int a3, wchar_t *a4);
wchar_t* stdString_CstrCopy(const char *a1);
char* stdString_WcharCopy(wchar_t *a1);
void stdString_CStrToLower(char *a1);

// Added: These were macros or something
char* stdString_SafeStrCopy(char* pDst, const char* pSrc, uint32_t lenDst);
wchar_t* stdString_SafeWStrCopy(wchar_t* pDst, const wchar_t* pSrc, uint32_t lenDst);

#ifdef __cplusplus
}
#endif

#endif // _STDSTRING_H
