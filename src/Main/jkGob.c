#include "jkGob.h"

#include "Main/jkGame.h"
#include "Win95/stdGob.h"

static int jkGob_bInit;

int jkGob_Startup()
{
    stdPlatform_Printf("OpenJKDF2: %s\n", __func__);
    
    stdGob_Startup(pHS);
    jkGob_bInit = 1;
    return 1;
}

void jkGob_Shutdown()
{
    stdPlatform_Printf("OpenJKDF2: %s\n", __func__);

#if !defined(SDL2_RENDER) && defined(WIN32)
    jk_ChangeDisplaySettingsA(0, 0);
#endif
}
