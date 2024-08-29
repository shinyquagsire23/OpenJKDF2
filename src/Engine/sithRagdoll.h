#ifndef _SITHRAGDOLL_H
#define _SITHRAGDOLL_H

#include "types.h"

#ifdef RAGDOLLS

int sithRagdoll_Startup();
void sithRagdoll_Shutdown();
int sithRagdoll_Load(sithWorld* world, int a2);
void sithRagdoll_Free(sithWorld* world);

rdRagdollSkeleton* sithRagdoll_LoadEntry(char* fpath);

#endif

#endif // _SITHRAGDOLL_H
