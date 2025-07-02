#ifndef _STDMEMORY_H
#define _STDMEMORY_H

#include "types.h"
#include "globals.h"

#define stdMemory_Startup_ADDR (0x0043A1C0)
#define stdMemory_Shutdown_ADDR (0x0043A1E0)
#define stdMemory_Open_ADDR (0x0043A1F0)
#define stdMemory_Dump_ADDR (0x0043A210)
#define stdMemory_BlockAlloc_ADDR (0x0043A290)
#define stdMemory_BlockFree_ADDR (0x0043A340)
#define stdMemory_BlockRealloc_ADDR (0x0043A3A0)

#define daAlloc_ADDR (0x0043A4A0)
#define daFree_ADDR (0x0043A680)
#define daRealloc_ADDR (0x0043A760)

void stdMemory_Startup();
void stdMemory_Shutdown();
int stdMemory_Open();
void stdMemory_Dump();
stdMemoryAlloc* stdMemory_BlockAlloc(unsigned int allocSize, char *filePath, int lineNum);
void stdMemory_BlockFree(stdMemoryAlloc *alloc);
stdMemoryAlloc* stdMemory_BlockRealloc(stdMemoryAlloc *alloc, int allocSize, char *filePath, int lineNum);

//static void* (*daAlloc)(uint32_t) = (void*)daAlloc_ADDR;
//static void (*daFree)(void*) = (void*)daFree_ADDR;
//static void* (*daRealloc)(void*, uint32_t) = (void*)daRealloc_ADDR;

#endif // _STDMEMORY_H
