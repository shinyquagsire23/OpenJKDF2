#include "jkGob.h"

#include "Main/jkGame.h"
#include "Win95/stdGob.h"

static int jkGob_bInit;

int jkGob_Startup()
{
    stdGob_Startup(pHS);
    jkGob_bInit = 1;
    return 1;
}

void jkGob_Shutdown()
{
#ifndef SDL2_RENDER
    jk_ChangeDisplaySettingsA(0, 0);
#endif
}
