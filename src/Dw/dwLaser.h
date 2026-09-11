#ifndef _DWLASER_H
#define _DWLASER_H

// dwLaser — DroidWorks per-world laser/beam pool: persistent beams attached
// to things, drawn every frame as camera-facing cross-billboard quads, with
// an 8-bounce mirror raytrace for free (untargeted) beams.
//
// Ghidra (DroidWorks.exe) 0x46aa90-0x46b5cx, 9 functions:
//   dwLaser_Draw@0x46aa90            dwLaser_DrawBeamSegment@0x46aad0
//   dwLaser_DrawQuad@0x46adb0        dwLaser_TraceBeam@0x46b010
//   dwLaser_Add@0x46b3f0             dwLaser_FindByThing@0x46b530
//   dwLaser_FindById@0x46b570        dwLaser_Remove@0x46b5b0
//   dwLaser_Free@0x46b5c0
//
// Pool storage lives on SithWorld (numDwLasers/aDwLasers, DW_LASERS fields
// in types.h; entry type tDwLaser/sDwLaser also in types.h). COG surface:
//   addlaser(thing, color, width)        -> dwLaser_Add(world, thing, NULL, color, width)->id
//   addbeam(from, to, color, width)      -> dwLaser_Add(world, from, to, color, width)->id
//   removelaser(id)                      -> dwLaser_FindById + dwLaser_Remove
//   getlaserid(thing)                    -> dwLaser_FindByThing ? ->id : -1
// TraceBeam sends COG message 41 ("laserhit", DW-extended enum) to hit
// things/surfaces and reflects off materials whose name starts with "MIR".
//
// Integration points (owners: dwCog / shared-engine hookup, NOT this unit):
//   - the jkCog_addLaser/removeLaser/getLaserId stubs in src/Cog/jkCog.c;
//   - the render hook: DW's sithRender_DrawLasers@45e7d0 iterates the pool
//     each frame, drawing entries whose owner (and target, if set) is alive
//     (type != SITH_THING_FREE and !(thingflags & SITH_TF_DISABLED)) and
//     dwLaser_Remove-ing the rest;
//   - sithWorld_FreeEntry calls dwLaser_Free(pWorld).

#include "Dw/dwTypes.h"

// Genuinely-C unit (no C++ features in the binary); guarded for inclusion
// from the C++ DW units.
#ifdef __cplusplus
extern "C" {
#endif

#ifndef PLATFORM_DROIDWORKS
// Retro targets exclude src/Dw/* from the build; the shared-engine call sites
// (sithWorld_FreeEntry / sithRender_Draw) compile to dead no-ops (same
// pattern as dwMain.h).
#define dwLaser_Free(pWorld)
#define dwLaser_DrawAll()
#else

// Next laser id handed out by dwLaser_Add (binary: 0x52d988, initial 1).
extern uint32_t dwLaser_nextId;

// Note: no binary counterpart — statics reset for the soft-reset loop only.
void dwLaser_Startup();

// Draw one pool entry: straight owner->target beam when pTargetThing is set,
// otherwise the bouncing TraceBeam. @0x46aa90
void dwLaser_Draw(tDwLaser* pLaser);

// Draw a beam segment between two world points as two perpendicular quads
// (cross billboard) of the given half-width. @0x46aad0
void dwLaser_DrawBeamSegment(const rdVector3* pFrom, const rdVector3* pTo, rdMaterial* pMaterial, flex_t width);

// Clip + project + submit one solid-color world-space quad to rdCache.
// aQuad = 4 world-space corners. @0x46adb0
void dwLaser_DrawQuad(rdVector3* aQuad, rdMaterial* pMaterial);

// Raytrace an untargeted beam from its owner along the owner's look vector
// (up to 4000.0 per segment, 8 mirror bounces), drawing each segment,
// sending COG message 41 ("laserhit") to whatever it hits, and reflecting
// off "MIR*" materials. @0x46b010
void dwLaser_TraceBeam(tDwLaser* pLaser);

// Allocate a pool slot (pool grows by 5 slots at a time) and initialize the
// beam: owner, optional target, inline solid-color material (color = palette
// index) and half-width. Returns NULL on allocation failure. @0x46b3f0
tDwLaser* dwLaser_Add(SithWorld* pWorld, SithThing* pOwnerThing, SithThing* pTargetThing, int color, flex_t width);

// Find the (first) live-or-free slot owned by pThing / the live slot with
// the given id; NULL when absent. @0x46b530 / @0x46b570
tDwLaser* dwLaser_FindByThing(SithWorld* pWorld, SithThing* pThing);
tDwLaser* dwLaser_FindById(SithWorld* pWorld, uint32_t id);

// Release a slot back to the pool (clears the owner). pWorld is unused but
// kept from the binary signature. @0x46b5b0
void dwLaser_Remove(SithWorld* pWorld, tDwLaser* pLaser);

// Free the world's whole pool (sithWorld_FreeEntry hook). @0x46b5c0
void dwLaser_Free(SithWorld* pWorld);

// The binary's per-frame render pass sithRender_DrawLasers@0x45e780 (called
// by sithRender_Draw between the thing/alpha-thing passes and the alpha
// adjoins): sets sorting method 2, then draws every pool entry whose owner
// (and target, if set) is alive (type != SITH_THING_FREE and
// !(thingflags & SITH_TF_DESTROYED)) and removes the rest. Implemented in
// dwLaser.c because src/Dw is retro-excluded while sithRender.c is shared.
void dwLaser_DrawAll();

#endif // PLATFORM_DROIDWORKS

#ifdef __cplusplus
}
#endif

#endif // _DWLASER_H
