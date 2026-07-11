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


char* stdString_FastCopy(const char *pSource);
char16_t* stdString_FastWCopy(const char16_t *str); // Added
int stdString_snprintf(char *pStr, int size, const char *format, ...);
char* stdString_CopyBetweenDelimiter(char *pSource, char *pFirstToken, int maxTokenLenght, char *pSeparators);
char* stdString_GetQuotedStringContents(char *pSource, char *pDest, int destSize);
int stdString_CharToWchar(char16_t *pwString, const char *pString, int maxChars);
int stdString_WcharToChar(char *pString, const char16_t *pwString, int maxChars);
int stdString_WstrRemoveCharsAt(char16_t *pwaStr, int idx, int numChars);
int stdString_wstrncat(char16_t *a1, int a2, int a3, char16_t *a4);
char16_t* stdString_CstrCopy(const char *pString);
char* stdString_WcharCopy(char16_t *pwString);
void stdString_CStrToLower(char *pStr);

// Added: These were macros or something
char* stdString_SafeStrCopy(char* pDst, const char* pSrc, uint32_t lenDst);
char16_t* stdString_SafeWStrCopy(char16_t* pDst, const char16_t* pSrc, uint32_t lenDst);

#ifdef __cplusplus
}
#endif

#endif // _STDSTRING_H
