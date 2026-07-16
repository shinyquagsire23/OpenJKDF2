#ifndef _DWSTRING_H
#define _DWSTRING_H

#include "Dw/dwTypes.h"

// dwString — CString-like heap string + path helpers.
// DroidWorks.exe unit range: 0x4429e0-0x442d9x (plus COMDAT duplicates of
// dwString::Free at 0x436d80 and 0x442cd0; single implementation here).
//
// Dual-language header: the class is C++-only (dwString is a verifiably-C++
// unit, see DW/DECOMP_PROGRESS.md "Language"); C consumers see only an opaque
// forward declaration plus the four __cdecl free-function helpers below.

#ifdef __cplusplus

struct dwString
{
    uint32_t length;   // 0x00: chars in use, excluding NUL
    uint32_t capacity; // 0x04: allocated bytes (length + NUL fits)
    char* pBuffer;     // 0x08: heap buffer (NULL when empty/default-ctor'd)

    dwString();                                 // @442ac0 (dwString_CtorDefault)
    dwString(const char* pSrc, uint32_t len);   // @442ad0 (dwString_Ctor): len==0 -> strlen
    dwString(const dwString& src);              // @442b00 (dwString_CtorCopy)
    ~dwString();                                // calls Free() (the binary's dtor IS Free)

    // Free + zero all three members. Note: idempotent — the dtor also runs
    // after explicit Free() calls in translated code, so a second Free()
    // must be harmless. @442b70 (=0x436d80/0x442cd0)
    dwString* Free();

    // Assignment / editing (len==0 means "use strlen(pSrc)" throughout)
    dwString* Assign(const char* pSrc, uint32_t len);              // @442d00
    dwString* AssignString(const dwString* pSrc);                  // @442b30
    dwString* AssignCStr(const char* pSrc);                        // @442b50
    dwString* Append(const char* pSrc, uint32_t len);              // @442b80
    dwString* Insert(uint32_t pos, const char* pSrc, uint32_t len); // @442c00
    dwString* Erase(uint32_t start, uint32_t end);                 // @442c80

    // Ensure room for `needed` chars (+NUL); grows, or shrinks when
    // needed+1 < capacity/2. Returns nonzero if pBuffer is usable afterwards.
    int Reserve(uint32_t needed);                                  // @442d90

    // Deep-copy assignment delegating to AssignString (prevents accidental
    // shallow member copies now that dwString owns a heap buffer).
    dwString& operator=(const dwString& src);
}; // sizeof 0x0c

#else // !__cplusplus

// Opaque to C: only pointers cross the language boundary.
typedef struct dwString dwString;

#endif // __cplusplus

// __cdecl free-function helpers (they are plain functions in the binary too);
// callable from both C and C++.
#ifdef __cplusplus
extern "C" {
#endif

// Case-insensitive helpers (THE keyword comparator used by the DW GUI factories)
int  dwString_Equals(const char* pA, const char* pB);   // @4429e0: 1 if both non-NULL and CompareI == 0
int  dwString_CompareI(const char* pA, const char* pB); // @442a10: tolower-strcmp

// Path helpers: advance *ppStr in place
void dwString_FindExtension(char** ppStr); // @442a50: -> last '.' (unchanged if none)
void dwString_FindFilename(char** ppStr);  // @442a80: -> past last '\\' or ':' (unchanged if none)

#ifdef __cplusplus
}
#endif

#endif // _DWSTRING_H
