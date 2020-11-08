#ifndef _SITHADJOIN_H
#define _SITHADJOIN_H

typedef struct sithSector sithSector;

typedef struct sithAdjoin
{
    uint32_t flags;
    sithSector* sector;
    uint32_t field_8;
    uint32_t field_C;
} sithAdjoin;

#endif // _SITHADJOIN_H
