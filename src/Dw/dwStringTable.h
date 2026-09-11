#ifndef _DWSTRINGTABLE_H
#define _DWSTRINGTABLE_H

// dwStringTable — STRINGTABLE name->string map loaded from a conf file.
// DroidWorks.exe unit range: 0x446130-0x4464dx (3 functions).
//
// C++-ONLY header: dwStringTable is a real class (verifiably C++ in the
// binary — MSVC SEH/EH frames around the dwConfFile/dwString work in
// ctor/dtor); it has no C consumers.

#ifndef __cplusplus
#error "Dw/dwStringTable.h is C++-only"
#endif

#include "Dw/dwTypes.h"
#include "Dw/dwString.h"
#include "Dw/dwList.h" // dwList/dwListNode circular list (parallel P1 unit)

// Engine header without extern "C" guards of its own — wrap at include site.
extern "C" {
#include "General/stdHashtbl.h"
}

struct dwStringTable
{
    // 0x00: circular dwList holding alternating key/value dwString* payloads
    // (key node, then its value node). Layout-identical to the binary's bare
    // sentinel pointer: dwList is a single dwListNode* member.
    dwList pairs;
    // 0x04: key-cstr -> value dwString* hash (NULL when the file had no pairs)
    tHashTable* pHash;
    // sizeof 0x8

    dwStringTable(const char* pFilename); // @446130 (dwStringTable_Ctor)
    ~dwStringTable();                     // @446340 (dwStringTable_Dtor)
    dwString* Find(const char* pName);    // @446450: NULL if absent
};

#endif // _DWSTRINGTABLE_H
