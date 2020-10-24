#ifndef _STDSTRING_H
#define _STDSTRING_H

#define stdString_FastCopy_ADDR (0x0042F120)
#define stdString_snprintf_ADDR (0x0042F170)
#define stdString_CopyBetweenDelimiter_ADDR)
#define stdString_GetQuotedStringContents_ADDR)

static int (*stdString_snprintf)(char *out, int num, char *fmt, ...) = stdString_snprintf_ADDR;


#endif // _STDSTRING_H
