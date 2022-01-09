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
    //jk_ChangeDisplaySettingsA(0, 0);
}
