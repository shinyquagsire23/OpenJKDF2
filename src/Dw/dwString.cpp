// dwString — CString-like heap string + path helpers.
// Decompiled from DroidWorks.exe, unit range 0x4429e0-0x442d9x.
// dwString::Free exists as three byte-identical COMDATs in the binary
// (0x436d80, 0x442b70, 0x442cd0) — implemented once here.
//
// Allocation: the original went through the HostServices hooks
// (dwHS->alloc/realloc/free); this layer is desktop-only, so plain
// malloc/realloc/free are used (Note: behavioral 1:1).

#include "Dw/dwString.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// No module statics — no dwString_Startup needed (soft-reset rule).

// ------------------------------------------------------------------
// extern "C" free-function helpers
// ------------------------------------------------------------------

extern "C" int dwString_Equals(const char* pA, const char* pB)
{
    if (pA != NULL && pB != NULL) {
        if (dwString_CompareI(pA, pB) == 0)
            return 1;
    }
    return 0;
}

extern "C" int dwString_CompareI(const char* pA, const char* pB)
{
    int diff;
    char cA, cB;

    // Note: original called MSVC tolower on a sign-extended char; cast to
    // unsigned char here to keep libc tolower in defined territory.
    for (;;) {
        diff = tolower((unsigned char)*pA) - tolower((unsigned char)*pB);
        cA = *pA;
        pA++;
        if (cA == '\0')
            return diff;
        cB = *pB;
        pB++;
        if (cB == '\0')
            break;
        if (diff != 0)
            return diff;
    }
    return diff;
}

// Advance *ppStr to the LAST '.' in the string; left unchanged (at the start)
// when the string contains no dot. (Readable equivalent of the original's
// nested resume-at-last-dot scan; semantics verified identical.)
extern "C" void dwString_FindExtension(char** ppStr)
{
    char* pScan = *ppStr;
    char* pLastDot = *ppStr;

    for (; *pScan != '\0'; pScan++) {
        if (*pScan == '.')
            pLastDot = pScan;
    }
    *ppStr = pLastDot;
}

// Advance *ppStr past the last '\\' or ':' (i.e. to the basename); unchanged
// if the string has no path separator.
extern "C" void dwString_FindFilename(char** ppStr)
{
    char* pStart = *ppStr;
    char* pScan = pStart;
    char* pAfter;

    while (*pScan != '\0')
        pScan++;

    // Note: faithful to the original, including the quirk that an empty
    // string reads pStart[-1] before deciding (harmless in practice there,
    // since the buffers always sit past a heap/stack header).
    do {
        pAfter = pScan;
        pScan = pAfter - 1;
        if (pScan <= pStart || *pScan == '\\')
            break;
    } while (*pScan != ':');

    if (*pScan == '\\' || *pScan == ':')
        *ppStr = pAfter;
}

// ------------------------------------------------------------------
// dwString class methods
// ------------------------------------------------------------------

// @442ac0 (dwString_CtorDefault)
dwString::dwString()
{
    this->length = 0;
    this->capacity = 0;
    this->pBuffer = NULL;
}

// @442ad0 (dwString_Ctor): len==0 -> strlen
dwString::dwString(const char* pSrc, uint32_t len)
{
    this->length = 0;
    this->capacity = 0;
    this->pBuffer = NULL;
    this->Assign(pSrc, len);
}

// @442b00 (dwString_CtorCopy)
dwString::dwString(const dwString& src)
{
    this->length = 0;
    this->capacity = 0;
    this->pBuffer = NULL;
    this->Assign(src.pBuffer, src.length);
}

// The binary's dtor IS Free (COMDAT-folded); Free is idempotent so a dtor
// running after an explicit Free() call is harmless.
dwString::~dwString()
{
    this->Free();
}

// @442b30 (dwString_AssignString)
dwString* dwString::AssignString(const dwString* pSrc)
{
    return this->Assign(pSrc->pBuffer, pSrc->length);
}

// @442b50 (dwString_AssignCStr)
dwString* dwString::AssignCStr(const char* pSrc)
{
    return this->Assign(pSrc, 0);
}

// Deep-copy assignment delegating to AssignString (prevents accidental
// shallow member copies; self-assignment is caught by Assign's guard).
dwString& dwString::operator=(const dwString& src)
{
    this->AssignString(&src);
    return *this;
}

// @442b70 (=0x436d80/0x442cd0)
// Note: made idempotent (free + zero ALL THREE members unconditionally) —
// required because the dtor now also runs after explicit Free() calls in
// translated code. The original only zeroed under the pBuffer!=NULL check;
// same observable state either way.
dwString* dwString::Free()
{
    if (this->pBuffer != NULL)
        free(this->pBuffer);
    this->pBuffer = NULL;
    this->length = 0;
    this->capacity = 0;
    return this;
}

// @442b80 (dwString_Append)
dwString* dwString::Append(const char* pSrc, uint32_t len)
{
    uint32_t oldLen;
    uint32_t count;
    char* pDst;

    if (pSrc != NULL) {
        if (len == 0)
            len = (uint32_t)strlen(pSrc);
        oldLen = this->length;
        if (this->Reserve(oldLen + len)) {
            // copy stops at the source NUL OR after len chars, whichever first
            pDst = this->pBuffer + oldLen;
            count = 0;
            while (*pSrc != '\0' && count < len) {
                *pDst++ = *pSrc++;
                count++;
            }
            this->length = oldLen + count;
            this->pBuffer[this->length] = '\0';
        }
    }
    return this;
}

// @442c00 (dwString_Insert)
dwString* dwString::Insert(uint32_t pos, const char* pSrc, uint32_t len)
{
    if (pSrc != NULL) {
        if (len == 0)
            len = (uint32_t)strlen(pSrc);
        if (this->Reserve(this->length + len)) {
            // Note: no pos<=length validation in the original (quirk kept);
            // unsigned wrap on (length - pos) matches the binary.
            memmove(this->pBuffer + len + pos, this->pBuffer + pos,
                    (this->length - pos) + 1);
            // Unlike Append/Assign, Insert copies exactly len bytes (rep movs
            // in the binary) with no early stop at a source NUL.
            memcpy(this->pBuffer + pos, pSrc, len);
            this->length += len;
            this->pBuffer[this->length] = '\0';
        }
    }
    return this;
}

// @442c80 (dwString_Erase) — remove chars [start, end); end clamped to length.
dwString* dwString::Erase(uint32_t start, uint32_t end)
{
    if (end > this->length)
        end = this->length;
    if (this->length != 0 && start < end && start < this->length) {
        memmove(this->pBuffer + start, this->pBuffer + end,
                (this->length - end) + 1);
        this->length += start - end; // unsigned wrap == subtract (end - start)
        this->pBuffer[this->length] = '\0';
    }
    return this;
}

// @442d00 (dwString_Assign)
dwString* dwString::Assign(const char* pSrc, uint32_t len)
{
    char* pBuf;
    char* pDst;
    uint32_t count;

    pBuf = this->pBuffer;
    // self-assignment guard: skip entirely when pSrc points into our buffer
    if (pBuf != NULL && pSrc >= pBuf && pSrc <= pBuf + this->length)
        return this;

    if (pSrc == NULL) {
        this->length = 0;
        if (pBuf != NULL)
            *pBuf = '\0';
        return this;
    }

    if (len == 0)
        len = (uint32_t)strlen(pSrc);
    if (this->Reserve(len)) {
        pDst = this->pBuffer;
        count = 0;
        while (*pSrc != '\0' && count < len) {
            *pDst++ = *pSrc++;
            count++;
        }
        this->length = count;
        this->pBuffer[count] = '\0';
    }
    return this;
}

// @442d90 (dwString_Reserve)
int dwString::Reserve(uint32_t needed)
{
    uint32_t newCap;
    char* pNew;

    newCap = needed + 1;
    // Reallocates when too small (including capacity == needed+1, a quirk of
    // the original's <=), or shrinks when needed+1 < capacity/2.
    if (this->capacity <= newCap || newCap < (this->capacity >> 1)) {
        if (this->pBuffer == NULL)
            pNew = (char*)malloc(newCap);
        else
            pNew = (char*)realloc(this->pBuffer, newCap);
        if (pNew != NULL) {
            this->capacity = newCap;
            this->pBuffer = pNew;
        }
    }
    return this->pBuffer != NULL;
}
