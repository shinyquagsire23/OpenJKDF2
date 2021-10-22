#ifndef _RDFACE_H
#define _RDFACE_H

#include "types.h"
#include "Engine/rdMaterial.h"

#define rdFace_New_ADDR       (0x0046D150)
#define rdFace_NewEntry_ADDR  (0x0046D1A0)
#define rdFace_Free_ADDR      (0x0046D1E0)
#define rdFace_FreeEntry_ADDR (0x0046D220)

rdFace *rdFace_New();
int rdFace_NewEntry(rdFace* out);
void rdFace_Free(rdFace *face);
void rdFace_FreeEntry(rdFace *face);

#endif // _RDFACE_H
