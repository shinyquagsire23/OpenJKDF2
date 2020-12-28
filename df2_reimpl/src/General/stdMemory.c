#include "stdMemory.h"

#include "stdPlatform.h"

void stdMemory_Startup()
{
    memset(&stdMemory_info, 0, sizeof(stdMemory_info));
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

void stdMemory_Dump()
{
    stdMemoryAlloc *iter; // eax
    stdMemoryAlloc *iterNext; // esi

    if (!stdMemory_bOpened)
        return;

    if ( stdMemory_info.nextNum || stdMemory_info.allocCur )
    {
        std_pHS->errorPrint("File\tLine\tSize\tNumber\n\n", 0, 0, 0, 0);
        iter = stdMemory_info.allocTop.prev;
        if ( stdMemory_info.allocTop.prev )
        {
            do
            {
                iterNext = iter->prev;
                std_pHS->errorPrint("%s\t%d\t%d\t%d\n\n", iter->filePath, iter->lineNum, iter->size, iter->num);
                iter = iterNext;
            }
            while ( iterNext );
        }
    }
    stdMemory_bOpened = 0;
}

stdMemoryAlloc* stdMemory_BlockAlloc(unsigned int allocSize, char *filePath, int lineNum)
{
    stdMemoryAlloc *result; // eax
    stdMemoryAlloc *v4; // edx
    stdMemoryAlloc *v5; // ecx

    result = (stdMemoryAlloc *)std_pHS->alloc(allocSize + 0x24);
    v4 = result;
    if ( result )
    {
        result->num = stdMemory_info.nextNum;
        result->filePath = filePath;
        v5 = stdMemory_info.allocTop.prev;
        result->lineNum = lineNum;
        result->alloc = (int)result;
        result->size = allocSize;
        result->prev = v5;
        if ( v5 )
            v5->next = result;
        result->next = &stdMemory_info.allocTop;
        memset(&result[1], 0xCCu, allocSize);
        stdMemory_info.allocTop.prev = result;
        result->magic = 0x12345678;
        *(int *)((char *)&result[1].num + allocSize) = 0x12345678;

        if ( stdMemory_info.allocMax <= allocSize + stdMemory_info.allocCur )
            stdMemory_info.allocMax = allocSize + stdMemory_info.allocCur;

        stdMemory_info.allocCur += allocSize;
        ++stdMemory_info.nextNum;
        result = v4 + 1;
    }
    return result;
}

void stdMemory_BlockFree(stdMemoryAlloc *alloc)
{
    stdMemoryAlloc *v1; // edx
    stdMemoryAlloc *v2; // eax
    int v3; // edi
    int v4; // esi

    v1 = alloc - 1;
    memset(alloc, 0xDDu, alloc[-1].size);
    v2 = alloc[-1].prev;
    if ( v2 )
        v2->next = v1->next;
    v3 = stdMemory_info.allocCur;
    v4 = stdMemory_info.nextNum;
    v1->next->prev = v2;
    stdMemory_info.allocCur = v3 - v1->size;
    stdMemory_info.nextNum = v4 - 1;
    std_pHS->free(v1);
}

stdMemoryAlloc* stdMemory_BlockRealloc(stdMemoryAlloc *alloc, int allocSize, char *filePath, int lineNum)
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
        return stdMemory_BlockAlloc(allocSize, filePath, lineNum);
    if ( allocSize )
    {
        v9 = alloc[-1].size;
        result = (stdMemoryAlloc *)std_pHS->realloc(&alloc[-1], allocSize + 0x24);
        if ( result )
        {
            result->filePath = filePath;
            v10 = result->prev;
            result->alloc = (int)result;
            result->size = allocSize;
            result->lineNum = lineNum;
            if ( v10 )
                v10->next = result;
            v11 = result->next;
            if ( v11 )
                v11->prev = result;
            v12 = stdMemory_info.allocMax;
            result->magic = 305419896;
            *(int *)((char *)&result[1].num + allocSize) = 305419896;
            stdMemory_info.allocCur += allocSize - v9;
            if ( v12 <= stdMemory_info.allocCur )
                stdMemory_info.allocMax = stdMemory_info.allocCur;
            ++result;
        }
    }
    else
    {
        v5 = alloc - 1;
        memset(alloc, 0xDDu, alloc[-1].size);
        v6 = alloc[-1].prev;
        if ( v6 )
            v6->next = v5->next;
        v7 = stdMemory_info.allocCur;
        v8 = stdMemory_info.nextNum;
        v5->next->prev = v6;
        stdMemory_info.allocCur = v7 - v5->size;
        stdMemory_info.nextNum = v8 - 1;
        std_pHS->free(v5);
        result = 0;
    }
    return result;
}
