#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <windows.h>

// TODO find some headers for these
#define LPDDENUMCALLBACKA void*
#define LPDIRECTDRAW void*
#define LPDIRECTINPUTA void*
#define LPDIRECTPLAYLOBBYA void*
#define LPDIRECTSOUND void*

typedef struct sithThing sithThing;
typedef struct jkGuiElement jkGuiElement;
typedef struct jkGuiMenu jkGuiMenu;
typedef struct stdVBuffer stdVBuffer;
typedef struct sithSurface sithSurface;
typedef struct sithSound sithSound;
typedef struct sithCog sithCog;
typedef struct stdStrTable stdStrTable;

#endif // TYPES_H
