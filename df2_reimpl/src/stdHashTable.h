#ifndef _STDHASHTABLE_H
#define _STDHASHTABLE_H

#define stdHashTable_GetKeyVal_ADDR (0x437D80)

static void* (*stdHashTable_GetKeyVal)(void* table, const char *key) = stdHashTable_GetKeyVal_ADDR;

#endif // _STDHASHTABLE_H
