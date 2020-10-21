#ifndef _STDDISPLAY_H
#define _STDDISPLAY_H

#define stdDisplay_ddraw_waitforvblank_ADDR (0x004230A0)

static void (*stdDisplay_ddraw_waitforvblank)(void) = stdDisplay_ddraw_waitforvblank_ADDR;


#endif // _STDDISPLAY_H
