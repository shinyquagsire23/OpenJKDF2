#include "sith.h"

#include "Main/jkGame.h"
#include "Engine/sithCamera.h"
#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "jk.h"

void sith_UpdateCamera()
{
    if ( (g_submodeFlags & 8) == 0 )
    {
        if ( !++dword_8EE678 )
        {
            sithWorld_sub_4D0A20(sithWorld_pCurWorld);
            dword_8EE678 = 1;
        }
#ifdef QOL_IMPROVEMENTS
        // Set screen aspect ratio
        float aspect = sithCamera_currentCamera->rdCam.canvas->screen_width_half / sithCamera_currentCamera->rdCam.canvas->screen_height_half;
        rdCamera_SetFOV(&sithCamera_currentCamera->rdCam, jkPlayer_fov);
        rdCamera_SetAspectRatio(&sithCamera_currentCamera->rdCam, aspect);
#endif
        //sithCamera_currentCamera->rdCam.screenAspectRatio += 0.01;
        sithCamera_FollowFocus(sithCamera_currentCamera);
        sithCamera_SetRdCameraAndRenderidk();
    }
}

