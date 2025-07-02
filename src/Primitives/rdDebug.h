#ifndef _RDDEBUG_H
#define _RDDEBUG_H

#include "types.h"

void rdDebug_DrawScreenLine3(rdVector3* v1, rdVector3* v2, uint32_t color);
void rdDebug_DrawLine3(rdVector3* v1, rdVector3* v2, uint32_t color);
void rdDebug_DrawBoundingBox(rdMatrix34* m, flex_t radius, uint32_t color);

#endif // _RDDEBUG_H
