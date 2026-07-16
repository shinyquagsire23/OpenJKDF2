#ifndef _DWTYPES_H
#define _DWTYPES_H

// DroidWorks app-layer shared types.
//
// The DW layer (decompiled from DroidWorks.exe, see DW/DECOMP_PROGRESS.md) is
// self-contained: its ~114 structs are only referenced by src/Dw/ modules, so
// they live here instead of src/types.h (deviation agreed 2026-07-15).
//
// Language policy (user-confirmed 2026-07-15; DW/DECOMP_PROGRESS.md
// "Architecture decisions" -> "Language", superseding the earlier all-C plan):
//  - Units that are *verifiably C++* in the binary (vtables, ctor/dtor pairs,
//    MSVC EH unwind frames around object locals, template COMDATs) are
//    idiomatic C++17 in `.cpp` files: real classes (`struct`-keyword,
//    all-public like the originals), real inheritance/virtual methods (the
//    compiler does the MI thunk work), Ghidra-traceable method names
//    (`dwWidget_Draw` -> `dwWidget::Draw`). NO STL substitution —
//    dwString/dwList stay hand-implemented to preserve behavior quirks.
//  - Genuinely procedural units stay pure C (`.c` compiled as C). The two
//    sides meet over an `extern "C"` FFI: engine headers lacking guards get
//    wrapped at the include site in `.cpp` files; DW headers consumed by C
//    carry `#ifdef __cplusplus extern "C"` guards, with C++ class types
//    reduced to opaque forward declarations in the C view (see dwString.h).

#include "types.h"

// Recover the outer object from a pointer to an embedded member. Still useful
// in the C units (and for intrusive-member back-pointers); the C++ units get
// MI subobject recovery from the compiler instead.
#define DW_CONTAINER_OF(ptr, type, member) \
    ((type*)((char*)(ptr) - offsetof(type, member)))

// Forward declarations get added here as units land (P1+).

#endif // _DWTYPES_H
