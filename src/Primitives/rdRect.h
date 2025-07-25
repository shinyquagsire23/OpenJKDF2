#ifndef _RDRECT_H
#define _RDRECT_H

#include <stdint.h>

typedef struct rdRect
{
    int32_t x;
    int32_t y;
    int32_t width;
    int32_t height;
} rdRect;

static inline int rdRect_ContainsPoint(rdRect* pRect, int32_t x, int32_t y) {
    if (!pRect) return 0;
    return (x >= pRect->x && x <= pRect->x + pRect->width)
            && (y >= pRect->y && y <= pRect->y + pRect->height);
}

#endif // _RDRECT_H
