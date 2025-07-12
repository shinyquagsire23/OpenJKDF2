#ifndef _MAIN_JKHUDCAMERAVIEW_H
#define _MAIN_JKHUDCAMERAVIEW_H

#include "types.h"

void jkHudCameraView_Startup(void);
void jkHudCameraView_Shutdown(void);
MATH_FUNC int jkHudCameraView_Open(void);
void jkHudCameraView_Close(void);
MATH_FUNC void jkHudCameraView_Draw(void);

#endif // _MAIN_JKHUDCAMERAVIEW_H