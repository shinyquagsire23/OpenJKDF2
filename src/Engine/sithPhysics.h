#ifndef _ENGINE_SITHPHYSICS_H
#define _ENGINE_SITHPHYSICS_H

#include "types.h"
#include "globals.h"

#define sithPhysics_FindFloor_ADDR (0x004F5550)
#define sithPhysics_ThingPhysIdk_inlined_ADDR (0x004F5870)
#define sithPhysics_UpdateThing_ADDR (0x004F5900)
#define sithPhysics_ApplyForce_ADDR (0x004F59B0)
#define sithPhysics_SetThingLook_ADDR (0x004F5A80)
#define sithPhysics_ApplyDrag_ADDR (0x004F5D50)
#define sithPhysics_ParseArg_ADDR (0x004F5EC0)
#define sithPhysics_ResetThingMovement_ADDR (0x004F61A0)
#define sithPhysics_GetThingHeight_ADDR (0x004F6210)
#define sithPhysics_UpdateThingPhysics_ADDR (0x004F6270)
#define sithPhysics_UpdatePlayerPhysics_ADDR (0x004F6860)
#define sithPhysics_UpdateUnderwaterThingPhysics_ADDR (0x004F6D80)
#define sithPhysics_UpdateAttachedThingPhysics_ADDR (0x004F7430)

MATH_FUNC void sithPhysics_FindFloor(SithThing *pThing, int bNoThingStateUpdate);
MATH_FUNC void sithPhysics_UpdateThing(SithThing *pThing, flex_t force);
MATH_FUNC void sithPhysics_ApplyForce(SithThing *pThing, rdVector3 *force);
MATH_FUNC void sithPhysics_SetThingLook(SithThing *pThing, const rdVector3 *pNormal, flex_t secDeltaTime);
MATH_FUNC void sithPhysics_ApplyDrag(rdVector3 *pVelocity, flex_t drag, flex_t mag, flex_t dragCoef);
MATH_FUNC int sithPhysics_ParseArg(StdConffileArg *pArg, SithThing *pThing, int adjNum);
MATH_FUNC void sithPhysics_ResetThingMovement(SithThing *pThing);
MATH_FUNC flex_t sithPhysics_GetThingHeight(SithThing *pThing);
MATH_FUNC void sithPhysics_UpdateThingPhysics(SithThing *pThing, flex_t secDeltaTime);
MATH_FUNC void sithPhysics_UpdatePlayerPhysics(SithThing *pThing, flex_t msDeltaTime);
MATH_FUNC void sithPhysics_UpdateUnderwaterThingPhysics(SithThing *pThing, flex_t secDeltaTime);
MATH_FUNC void sithPhysics_UpdateAttachedThingPhysics(SithThing *pThing, flex_t secDeltaTime);

//static void (*_sithPhysics_ThingPhysAttached)(SithThing *pThing, flex_t deltaSeconds) = (void*)sithPhysics_UpdateAttachedThingPhysics_ADDR;

#endif // _ENGINE_SITHPHYSICS_H