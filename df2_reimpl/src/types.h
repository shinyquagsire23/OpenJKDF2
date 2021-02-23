#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <windows.h>
#include "Primitives/rdVector.h"
#include "Primitives/rdMatrix.h"

// TODO find some headers for these
#define LPDDENUMCALLBACKA void*
#define LPDIRECTDRAW void*
#define LPDIRECTINPUTA void*
#define LPDIRECTPLAYLOBBYA void*
#define LPDIRECTSOUND void*

typedef struct IDirectSoundBuffer IDirectSoundBuffer;
typedef IDirectSoundBuffer* LPDIRECTSOUNDBUFFER;

typedef struct jkGuiElement jkGuiElement;
typedef struct jkGuiMenu jkGuiMenu;

typedef struct sithAIClass sithAIClass;
typedef struct sithCog sithCog;
typedef struct sithCogMsg sithCogMsg;
typedef struct sithSector sithSector;
typedef struct sithSound sithSound;
typedef struct sithSurface sithSurface;
typedef struct sithThing sithThing;
typedef struct sithWorld sithWorld;

typedef struct stdStrTable stdStrTable;
typedef struct stdConffileArg stdConffileArg;
typedef struct stdHashTable stdHashTable;
typedef struct stdVBuffer stdVBuffer;

typedef struct rdColormap rdColormap;
typedef struct rdSprite rdSprite;
typedef struct rdEdge rdEdge;
typedef struct rdMaterial rdMaterial;
typedef struct rdParticle rdParticle;
typedef struct rdClipFrustum rdClipFrustum;
typedef struct rdVertexIdxInfo rdVertexIdxInfo;
typedef struct rdProcEntry rdProcEntry;
typedef struct sithUnk3SearchEntry sithUnk3SearchEntry;
typedef struct sithPlayingSound sithPlayingSound;
typedef struct sithSoundClass sithSoundClass;
typedef struct sithAI sithAI;
typedef struct sithAICommand sithAICommand;
typedef struct sithActor sithActor;
typedef struct sithSurfaceInfo sithSurfaceInfo;

typedef struct common_functions common_functions;

#endif // TYPES_H
