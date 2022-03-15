#ifndef _RDPRIMIT2_H
#define _RDPRIMIT2_H

#include "types.h"
#include "globals.h"

#define rdPrimit2_DrawLine_ADDR (0x00446890)
#define rdPrimit2_DrawClippedLine_ADDR (0x00446AC0)
#define rdPrimit2_DrawCircle_ADDR (0x00446D10)
#define rdPrimit2_DrawRectangle_ADDR (0x00446E60)
#define rdPrimit2_DrawTriangle_ADDR (0x00446EE0)

int rdPrimit2_DrawLine(rdCanvas *pCanvas, int x1, int y1, int x2, int y2, uint16_t color16, int mask);
int rdPrimit2_DrawClippedLine(rdCanvas *pCanvas, int x1, int y1, int x2, int y2, uint16_t color16, int mask);
void rdPrimit2_DrawCircle(rdCanvas *pCanvas, int x1, int y1, float a4, float radius, uint16_t color16, int mask);
void rdPrimit2_DrawRectangle(rdCanvas *pCanvas, int x1, int y1, int x2, int y2, int16_t color, int mask);
void rdPrimit2_DrawTriangle(rdCanvas *pCanvas, int x1, int y1, int x2, int y2, int x3, int y3, int16_t color, int mask);

//static int (*rdPrimit2_DrawClippedLine)(rdCanvas *canvas, int x1, int y1, int x2, int y2, uint16_t color16, int mask) = (void*)rdPrimit2_DrawClippedLine_ADDR;
//static void (*rdPrimit2_DrawCircle)(rdCanvas *canvas, int x1, int y1, float a4, float radius, uint16_t color16, int mask) = (void*)rdPrimit2_DrawCircle_ADDR;

#endif // _RDPRIMIT2_H
