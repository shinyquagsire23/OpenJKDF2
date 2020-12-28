#include "sith.h"

#include "Main/jkGame.h"
#include "Engine/sithCamera.h"
#include "World/sithWorld.h"

void sith_UpdateCamera()
{
    if ( (g_submodeFlags & 8) == 0 )
    {
        if ( !++dword_8EE678 )
        {
            sithWorld_sub_4D0A20(sithWorld_pCurWorld);
            dword_8EE678 = 1;
        }
        sithCamera_FollowFocus(sithCamera_currentCamera);
        sithCamera_SetRdCameraAndRenderidk();
    }
}

