#ifndef _RDCANVAS_H
#define _RDCANVAS_H

#include "rdMaterial.h"

typedef struct rdCanvas
{
    uint32_t bIdk;
    stdVBuffer* vbuffer;
    float screen_height_half;
    float screen_width_half;
    stdVBuffer* d3d_vbuf;
    uint32_t field_14;
    uint32_t xStart;
    uint32_t yStart;
    uint32_t widthMinusOne;
    uint32_t heightMinusOne;
} rdCanvas;

#endif // _RDCANVAS_H
