#ifndef _STDSTRING_H
#define _STDSTRING_H

#define stdString_FastCopy_ADDR (0x0042F120)
#define stdString_snprintf_ADDR (0x0042F170)
#define stdString_CopyBetweenDelimiter_ADDR (0x0042F1A0)
#define stdString_GetQuotedStringContents_ADDR (0x0042F210)

char* stdString_FastCopy(const char *str);
//static int (*stdString_snprintf)(char *out, int num, char *fmt, ...) = stdString_snprintf_ADDR;
int stdString_snprintf(char *out, int num, char *fmt, ...);
char* stdString_CopyBetweenDelimiter(char *instr, char *outstr, int out_size, char *find_str);

#endif // _STDSTRING_H
