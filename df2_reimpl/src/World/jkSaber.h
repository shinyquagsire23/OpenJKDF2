#ifndef _JKSABER_H
#define _JKSABER_H

#include "Primitives/rdMatrix.h"

#define jkSaber_Draw_ADDR (0x40B5E0)
#define jkSaber_PolylineRandidk_ADDR (0x40B590)

typedef struct sithThing sithThing;
typedef struct rdThing rdThing;

void jkSaber_PolylineRandidk(rdThing *thing);
void jkSaber_Draw(rdMatrix34 *posRotMat);

#endif // _JKSABER_H
