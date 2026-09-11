// dwStringTable — STRINGTABLE name->string map loaded from a conf file.
// DroidWorks.exe unit range: 0x446130-0x4464dx (3 functions).
//
// The ctor reads the file line-by-line via dwConfFile: the first token on a
// line is the key, the remainder of the line is the value. Each pair is
// appended as two consecutive dwString* nodes to the circular pairs dwList,
// then a stdHashtbl (sized ~7n/6) is built mapping key-cstr -> value
// dwString* for O(1) Find.
//
// Note: the original allocates through the DW operator-new/delete pair
// (idk_alloc / stdPlatform_FreeHandle in the Ghidra listing); this
// desktop-only layer uses plain new/delete (payloads) and dwList's
// malloc/free (nodes) per DW/DECOMP_PROGRESS.md. The MSVC SEH frame
// setup/teardown in ctor/dtor is the compiler's EH bookkeeping — here the
// C++ compiler emits the equivalent itself.
//
// No module statics — no _Startup/_Shutdown needed.

#include "Dw/dwStringTable.h"

#include <stdlib.h>
#include <ctype.h>

#include "Dw/dwConfFile.h"

// @446130
// The `pairs` member ctor (dwList @40b940) allocates + self-links the
// sentinel before the body runs, exactly like the original's inlined
// list-ctor prologue.
dwStringTable::dwStringTable(const char* pFilename)
    : pairs(), pHash(NULL)
{
    dwConfFile confFile;
    uint32_t numPairs = 0;

    dwConfFile_Open(&confFile, pFilename);
    while (!confFile.bEof)
    {
        char* pKey;
        char* pValue;

        dwConfFile_ReadLine(&confFile);
        pKey = dwConfFile_NextToken(&confFile);
        // Value = remainder of the line past any whitespace (NextToken
        // already skipped it; the original re-skips defensively).
        pValue = confFile.pCursor;
        while (*pValue && isspace((unsigned char)*pValue))
            pValue++;
        if (pKey && *pKey && pValue && *pValue && pKey != pValue)
        {
            // binary: operator new(0xc) + dwString ctor for each of key/value
            dwString* pKeyStr = new dwString(pKey, 0);
            dwString* pValStr = new dwString(pValue, 0);
            // Append at the tail: insert after the sentinel's prev.
            pairs.InsertAfter(pairs.pSentinel->pPrev, pKeyStr);
            pairs.InsertAfter(pairs.pSentinel->pPrev, pValStr);
            numPairs++;
        }
    }
    if (numPairs != 0)
    {
        pHash = stdHashtbl_New(numPairs / 6 + 1 + numPairs);
        if (pHash)
        {
            dwListNode* pNode = pairs.pSentinel->pNext;
            while (pNode != pairs.pSentinel)
            {
                // key node's dwString buffer -> value node's dwString*
                stdHashtbl_Add(pHash,
                               ((dwString*)pNode->pData)->pBuffer,
                               pNode->pNext->pData);
                pNode = pNode->pNext->pNext;
            }
        }
    }
    dwConfFile_Close(&confFile);
}

// @446340
dwStringTable::~dwStringTable()
{
    dwListNode* pNode;

    if (pHash)
    {
        stdHashtbl_Free(pHash);
    }

    // Unlink and free every node + delete its dwString payload (this loop is
    // inlined ahead of the dwList dtor in the original).
    pNode = pairs.pSentinel->pNext;
    while (pNode != pairs.pSentinel)
    {
        dwString* pStr = (dwString*)pNode->pData;
        dwListNode* pNext = pNode->pNext;
        pNode->pPrev->pNext = pNode->pNext;
        pNode->pNext->pPrev = pNode->pPrev;
        pNode->pNext = NULL;
        pNode->pPrev = NULL;
        free(pNode);
        if (pStr)
        {
            delete pStr; // ~dwString -> Free(); binary: dwString_Free + operator delete
        }
        pNode = pNext;
    }

    // Inlined dwList dtor in the original: drain any remaining nodes (none by
    // this point) and free the sentinel — exactly dwList::Free.
    pairs.Free();
}

// @446450
dwString* dwStringTable::Find(const char* pName)
{
    dwString* pResult = NULL;
    if (pHash && pName && *pName)
    {
        pResult = (dwString*)stdHashtbl_Find(pHash, pName);
    }
    return pResult;
}
