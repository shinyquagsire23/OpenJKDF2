#ifndef _DARRAY_H
#define _DARRAY_H

#define Darray_New_ADDR (0x00520B50)
#define Darray_Free_ADDR (0x00520BC0)
#define Darray_NewEntry_ADDR (0x00520BE0)
#define Darray_GetIndex_ADDR (0x00520C60)
#define Darray_ClearAll_ADDR (0x00520C80)
#define Darray_sub_520CB0_ADDR (0x00520CB0)

typedef struct Darray
{
  void *alloc;
  unsigned int entrySize;
  unsigned int size;
  unsigned int total;
  int dword10;
  int bInitialized;
} Darray;

int Darray_New(Darray *array, int entrySize, int num);
void Darray_Free(Darray *array);
void* Darray_NewEntry(Darray *array);
void* Darray_GetIndex(Darray *array, int idx);
void Darray_ClearAll(Darray *array);
int Darray_sub_520CB0(Darray *a1, int (__cdecl *a2)(int, int), int a3);

#endif // _DARRAY_H
