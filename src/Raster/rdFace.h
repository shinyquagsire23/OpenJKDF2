#ifndef _RDFACE_H
#define _RDFACE_H

#include "types.h"
#include "Engine/rdMaterial.h"

#define rdFace_New_ADDR       (0x0046D150)
#define rdFace_NewEntry_ADDR  (0x0046D1A0)
#define rdFace_Free_ADDR      (0x0046D1E0)
#define rdFace_FreeEntry_ADDR (0x0046D220)

enum RdFaceFlag // Polygon face flags i.e face type -> 3DO & SithSurface
{
    RD_FF_DOUBLE_SIDED = 0x1,
    RD_FF_TEX_TRANSLUCENT = 0x2,
    RD_FF_TEX_CLAMP_X = 0x4, // Didn't show correct results in JED port, assuming not used in JKDF2
    RD_FF_TEX_CLAMP_Y = 0x8, // Didn't show correct results in JED port, assuming not used in JKDF2
    RD_FF_TEX_FILTER_NEAREST = 0x10,
    RD_FF_ZWRITE_DISABLED = 0x20,
    RD_FF_3DO_LEDGE = 0x40, // Jones specific
    RD_FF_UNKNOWN_80 = 0x80,
    RD_FF_FOG_ENABLED = 0x100, // Jones specific
    RD_FF_3DO_WHIP_AIM = 0x200, // Jones specific
#ifdef ADDITIVE_BLEND
	RD_FF_ADDITIVE = 0x400
#endif
};

rdFace *rdFace_New();
int rdFace_NewEntry(rdFace* out);
void rdFace_Free(rdFace *face);
void rdFace_FreeEntry(rdFace *face);

#endif // _RDFACE_H
