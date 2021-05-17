#include "sith.h"

#include "Main/jkGame.h"
#include "Engine/sithCamera.h"
#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "General/sithStrTable.h"
#include "Engine/sithTimer.h"
#include "Engine/sithRender.h"
#include "World/sithUnk3.h"
#include "Win95/sithDplay.h"
#include "AI/sithAI.h"
#include "Engine/sithSprite.h"
#include "Engine/sithParticle.h"
#include "Engine/sithPuppet.h"
#include "AI/sithAIClass.h"
#include "Engine/sithSoundClass.h"
#include "Engine/sithMaterial.h"
#include "Engine/sithTemplate.h"
#include "Engine/sithModel.h"
#include "Engine/sithSurface.h"
#include "Engine/sithSound.h"
#include "Engine/sithSoundSys.h"
#include "World/sithWeapon.h"
#include "Engine/sithRender.h"
#include "jk.h"

int sith_Startup(struct common_functions *commonFuncs)
{
    int v1; // esi
    int v2; // esi
    int v3; // esi
    int v4; // esi
    int v5; // esi
    int v6; // eax
    int v7; // esi
    int v8; // esi
    int v9; // esi
    int v10; // esi
    int v11; // esi
    int v12; // esi
    int v13; // esi
    int v14; // esi
    int v15; // esi
    int v16; // esi
    int v17; // esi
    int v18; // esi
    int v19; // esi

    pSithHS = commonFuncs;
    v1 = sithStrTable_Startup() & 1;
    v2 = sithTimer_Startup() & v1;
    v3 = sithWorld_Startup() & v2;
    v4 = sithRender_Startup() & v3;
    v5 = sithUnk3_Startup() & v4;
    v6 = sithThing_Startup() & v5;
    v7 = sithCogVm_Startup() & v6;
    v8 = sithDplay_Startup() & v7;
    v9 = sithCog_Startup() & v8;
    v10 = sithAI_Startup() & v9;
    v11 = sithSprite_Startup() & v10;
    v12 = sithParticle_Startup() & v11;
    v13 = sithPuppet_Startup() & v12;
    v14 = sithAIClass_Startup() & v13;
    v15 = sithSoundClass_Startup() & v14;
    v16 = sithMaterial_Startup() & v15;
    v17 = sithTemplate_Startup() & v16;
    v18 = sithModel_Startup() & v17;
    v19 = sithSurface_Startup() & v18;
    sithSound_Startup();
    sithSoundSys_Startup();
    sithWeapon_Startup();
    _memset(&g_sithMode, 0, 0x18u);
    if ( !v19 )
        return 0;
    sith_bInitialized = 1;
    return 1;
}

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

int sith_Load(char *path)
{
    sithWorld_pStatic = sithWorld_New();
    sithWorld_pStatic->level_type_maybe |= 1;
    return sithWorld_Load(sithWorld_pStatic, path) != 0;
}
