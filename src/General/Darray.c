#include "Darray.h"

#include "jk.h"
#include "stdPlatform.h"

int Darray_New(Darray *array, int entrySize, int num)
{
    array->alloc = 0;
    array->entrySize = 0;
    array->size = 0;
    array->total = 0;
    array->dword10 = 0;
    array->entrySize = entrySize;
    array->dword10 = 0xDA88DA88;

    if ( !num )
        return 1;

    array->alloc = std_pHS->alloc(entrySize * num);
    if ( !array->alloc ) {
        std_pHS->errorPrint("Ran out of memory initializing Darray.\n");
        std_pHS->errorPrint("OpenJKDF2: entrySize=%x, num=%x\n", entrySize, num); // Added
    }
    array->size = num;
    return (array->alloc != 0);
}

void Darray_Free(Darray *array)
{
    return std_pHS->free(array->alloc);
}

void* Darray_NewEntry(Darray *array)
{
    void *result;

    if (array->total != array->size)
        return Darray_GetIndex(array, array->total++);

    array->size = (2 * array->size);
    if ( array->size < 4 )
        array->size = 4;

    array->alloc = (void*)std_pHS->realloc(array->alloc, array->size * array->entrySize);
    if (array->alloc)
    {
        return Darray_GetIndex(array, array->total++);
    }
    else
    {
        array->alloc = 0;
        array->entrySize = 0;
        array->size = 0;
        array->total = 0;
        array->dword10 = 0;
        std_pHS->errorPrint("Ran out of memory reallocating data for Darray.\n");
        return NULL;
    }
    return result;
}

void* Darray_GetIndex(Darray *array, int idx)
{
    return (char *)array->alloc + idx * array->entrySize;
}

void Darray_ClearAll(Darray *array)
{
    array->total = 0;
    _memset(array->alloc, 0, array->entrySize * array->size);
}

int Darray_sub_520CB0(Darray *a1, int (__cdecl *a2)(int, int), int a3)
{
    int v3; // edi

    v3 = 0;
    if (a1->total <= 0)
        return -1;
    while ( a2(a3, (int)(intptr_t)Darray_GetIndex(a1, v3)) )
    {
        if ( ++v3 >= a1->total )
            return -1;
    }
    return v3;
}
