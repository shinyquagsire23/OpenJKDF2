#ifndef _DWTYPES_H
#define _DWTYPES_H

// DroidWorks app-layer shared types.
//
// The DW layer (decompiled from DroidWorks.exe, see DW/DECOMP_PROGRESS.md) is
// self-contained: its ~114 structs are only referenced by src/Dw/ modules, so
// they live here instead of src/types.h (deviation agreed 2026-07-15).
//
// Conventions for the C translation of the original C++ layer:
//  - Each class becomes `struct dwFoo` with an explicit vtable pointer as its
//    first member (or at the original subobject offset for MSVC MI classes).
//  - Vtables become `struct dwFooVtbl` of function pointers; the slot order
//    matches the binary's vtable layout (see the dwWidget slot map in
//    CLAUDE.md / DW/PROGRESS.md).
//  - Secondary-base (MI) methods are wrapper functions that recover the outer
//    object via DW_CONTAINER_OF and forward to the real method.

#include "types.h"

// Recover the outer object from a pointer to an embedded member (used for the
// MSVC multiple-inheritance secondary-base subobjects, e.g. a screen's
// dwSegment base at +0x10).
#define DW_CONTAINER_OF(ptr, type, member) \
    ((type*)((char*)(ptr) - offsetof(type, member)))

// Forward declarations get added here as units land (P1+).

#endif // _DWTYPES_H
