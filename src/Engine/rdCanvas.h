#ifndef _RDCANVAS_H
#define _RDCANVAS_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define rdCanvas_New_ADDR (0x0043AC20)
#define rdCanvas_NewEntry_ADDR (0x0043AC70)
#define rdCanvas_Free_ADDR (0x0043AD30)
#define rdCanvas_FreeEntry_ADDR (0x0043AD50)

rdCanvas* rdCanvas_New(int bIdk, stdVBuffer *vbuf1, stdVBuffer *vbuf2, int x, int y, int w, int h, int a8);
int rdCanvas_NewEntry(rdCanvas *canvas, int bIdk, stdVBuffer *vbuf, stdVBuffer *a4, int x, int y, int width, int height, int a9);
void rdCanvas_Free(rdCanvas *canvas);
void rdCanvas_FreeEntry(rdCanvas *canvas);

#ifdef __cplusplus
}
#endif

#endif // _RDCANVAS_H
