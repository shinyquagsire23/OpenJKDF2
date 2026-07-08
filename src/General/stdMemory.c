#include "stdMemory.h"

#include "stdPlatform.h"

void stdMemory_Startup()
{
    _memset(&stdMemory_g_curState, 0, sizeof(stdMemory_g_curState));
    stdMemory_bInitted = 1;
}

void stdMemory_Shutdown()
{
    stdMemory_bInitted = 0;
}

int stdMemory_Open()
{
    if ( stdMemory_bOpened )
        return 0;

    stdMemory_bOpened = 1;
    return 1;
}

void stdMemory_Close()
{
    stdMemoryAlloc *iter; // eax
    stdMemoryAlloc *iterNext; // esi

    if (!stdMemory_bOpened)
        return;

    if ( stdMemory_g_curState.totalAllocs || stdMemory_g_curState.totalBytes )
    {
        std_g_pHS->errorPrint("File\tLine\tSize\tNumber\n\n", 0, 0, 0, 0);
        iter = stdMemory_g_curState.header.prev;
        if ( stdMemory_g_curState.header.prev )
        {
            do
            {
                iterNext = iter->prev;
                std_g_pHS->errorPrint("%s\t%d\t%d\t%d\n\n", iter->filePath, iter->lineNum, iter->size, iter->num);
                iter = iterNext;
            }
            while ( iterNext );
        }
    }
    stdMemory_bOpened = 0;
}

stdMemoryAlloc* stdMemory_Malloc(unsigned int allocSize, char *filePath, int lineNum)
{
    stdMemoryAlloc *result; // eax
    stdMemoryAlloc *v4; // edx
    stdMemoryAlloc *v5; // ecx

    result = (stdMemoryAlloc *)STD_ALLOC(allocSize + 0x24);
    v4 = result;
    if ( result )
    {
        result->num = stdMemory_g_curState.totalAllocs;
        result->filePath = filePath;
        v5 = stdMemory_g_curState.header.prev;
        result->lineNum = lineNum;
        result->alloc = (void*)result;
        result->size = allocSize;
        result->prev = v5;
        if ( v5 )
            v5->next = result;
        result->next = &stdMemory_g_curState.header;
        _memset(&result[1], 0xCCu, allocSize);
        stdMemory_g_curState.header.prev = result;
        result->magic = 0x12345678;
        *(int *)((char *)&result[1].num + allocSize) = 0x12345678;

        if ( stdMemory_g_curState.maxBytes <= allocSize + stdMemory_g_curState.totalBytes )
            stdMemory_g_curState.maxBytes = allocSize + stdMemory_g_curState.totalBytes;

        stdMemory_g_curState.totalBytes += allocSize;
        ++stdMemory_g_curState.totalAllocs;
        result = v4 + 1;
    }
    return result;
}

void stdMemory_Free(stdMemoryAlloc *alloc)
{
    stdMemoryAlloc *v1; // edx
    stdMemoryAlloc *v2; // eax
    int v3; // edi
    int v4; // esi

    v1 = alloc - 1;
    _memset(alloc, 0xDDu, alloc[-1].size);
    v2 = alloc[-1].prev;
    if ( v2 )
        v2->next = v1->next;
    v3 = stdMemory_g_curState.totalBytes;
    v4 = stdMemory_g_curState.totalAllocs;
    v1->next->prev = v2;
    stdMemory_g_curState.totalBytes = v3 - v1->size;
    stdMemory_g_curState.totalAllocs = v4 - 1;
    STD_FREE(v1);
}

stdMemoryAlloc* stdMemory_Realloc(stdMemoryAlloc *alloc, int allocSize, char *filePath, int lineNum)
{
    stdMemoryAlloc *result; // eax
    stdMemoryAlloc *v5; // edx
    stdMemoryAlloc *v6; // eax
    int v7; // edi
    int v8; // esi
    int v9; // edi
    stdMemoryAlloc *v10; // ecx
    stdMemoryAlloc *v11; // ecx
    unsigned int v12; // edx

    if ( !alloc )
        return stdMemory_Malloc(allocSize, filePath, lineNum);
    if ( allocSize )
    {
        v9 = alloc[-1].size;
        result = (stdMemoryAlloc *)STD_REALLOC(&alloc[-1], allocSize + 0x24);
        if ( result )
        {
            result->filePath = filePath;
            v10 = result->prev;
            result->alloc = (void*)result;
            result->size = allocSize;
            result->lineNum = lineNum;
            if ( v10 )
                v10->next = result;
            v11 = result->next;
            if ( v11 )
                v11->prev = result;
            v12 = stdMemory_g_curState.maxBytes;
            result->magic = 305419896;
            *(int *)((char *)&result[1].num + allocSize) = 305419896;
            stdMemory_g_curState.totalBytes += allocSize - v9;
            if ( v12 <= stdMemory_g_curState.totalBytes )
                stdMemory_g_curState.maxBytes = stdMemory_g_curState.totalBytes;
            ++result;
        }
    }
    else
    {
        v5 = alloc - 1;
        _memset(alloc, 0xDDu, alloc[-1].size);
        v6 = alloc[-1].prev;
        if ( v6 )
            v6->next = v5->next;
        v7 = stdMemory_g_curState.totalBytes;
        v8 = stdMemory_g_curState.totalAllocs;
        v5->next->prev = v6;
        stdMemory_g_curState.totalBytes = v7 - v5->size;
        stdMemory_g_curState.totalAllocs = v8 - 1;
        STD_FREE(v5);
        result = 0;
    }
    return result;
}
