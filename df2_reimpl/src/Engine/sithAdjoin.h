#ifndef _SITHADJOIN_H
#define _SITHADJOIN_H

#include "types.h"

typedef struct sithAdjoin
{
    uint32_t flags;
    sithSector* sector;
    sithSurface* surface;
    sithAdjoin *mirror;
    sithAdjoin *next;
    uint32_t field_14;
    float dist;
    uint32_t field_1C;
    uint32_t field_20;
    uint32_t field_24;
} sithAdjoin;

#endif // _SITHADJOIN_H
