#include "jkPlayer.h"

#include <math.h>
#include "General/stdString.h"
#include "General/stdFnames.h"
#include "General/stdFileUtil.h"
#include "Engine/sithAnimClass.h"
#include "Dss/sithGamesave.h"
#include "Engine/rdPuppet.h"
#include "Gameplay/sithTime.h"
#include "Engine/sithCamera.h"
#include "Raster/rdCache.h"
#include "Engine/rdPuppet.h"
#include "Engine/rdCamera.h"
#include "Engine/rdroid.h"
#include "Engine/rdColormap.h"
#include "World/sithTemplate.h"
#include "General/stdMath.h"
#include "Gameplay/sithInventory.h"
#include "Gameplay/jkSaber.h"
#include "World/sithThing.h"
#include "Gameplay/sithPlayer.h"
#include "World/sithWeapon.h"
#include "World/sithWorld.h"
#include "World/sithSector.h"
#include "Primitives/rdMatrix.h"
#include "Devices/sithControl.h"
#include "Main/jkHudInv.h"
#include "Main/jkGame.h"
#include "jk.h"
#include "Win95/Window.h"
#include "General/stdJSON.h"
#include "Platform/std3D.h"
#include "Main/sithCvar.h"
#ifdef DYNAMIC_POV
#include "World/sithSprite.h"
#endif


// DO NOT FORGET TO ADD TO jkPlayer_ResetVars()
#ifdef QOL_IMPROVEMENTS
int Window_isHiDpi_tmp = 0;
int Window_isFullscreen_tmp = 0;
int jkPlayer_fov = 90;
int jkPlayer_fovIsVertical = 1;
int jkPlayer_enableTextureFilter = 0;
int jkPlayer_enableOrigAspect = 0;
int jkPlayer_enableBloom = 0;
int jkPlayer_enableSSAO = 0;
int jkPlayer_fpslimit = 0;
int jkPlayer_enableVsync = 0;
float jkPlayer_ssaaMultiple = 1.0;
float jkPlayer_gamma = 1.0;
int jkPlayer_bEnableJkgm = 1;
int jkPlayer_bEnableTexturePrecache = 1;
int jkPlayer_bKeepCorpses = 0;
int jkPlayer_bFastMissionText = 0;
int jkPlayer_bUseOldPlayerPhysics = 0;
float jkPlayer_hudScale = 2.0;
float jkPlayer_crosshairLineWidth = 1.0;
float jkPlayer_crosshairScale = 1.0;
float jkPlayer_canonicalCogTickrate = CANONICAL_COG_TICKRATE;
float jkPlayer_canonicalPhysTickrate = CANONICAL_PHYS_TICKRATE;

int jkPlayer_setCrosshairOnLightsaber = 1;
int jkPlayer_setCrosshairOnFist = 1;
int jkPlayer_bHasLoadedSettingsOnce = 0;

#ifdef DECAL_RENDERING
int jkPlayer_enableDecals = 1;
#endif

#ifdef RAGDOLLS
int jkPlayer_ragdolls = 1;

int jkPlayer_debugRagdolls = 0;
#endif
#endif

#ifdef DYNAMIC_POV
static float jkPlayer_waggleVel = 1.0f;

static rdVector3 jkSaber_aimAngles;
static rdVector3 jkSaber_aimVector;
static rdVector3 jkSaber_swayOffset;
static rdVector3 jkPlayer_idleWaggleVec;
static float jkPlayer_idleWaggleSpeed;
static float jkPlayer_idleWaggleSmooth;
static float jkPlayer_povAutoAimFov;
static float jkPlayer_povAutoAimDist;
static rdVector3 jkPlayer_pushAngles;
static rdVector3 jkPlayer_muzzleOffset;
static rdVector3 jkPlayer_weaponWallAngles = {-40.0f, 25.0f, -10.0f };

rdVector3 jkPlayer_crosshairPos;
int jkPlayer_aimLock = 0;

static int jkPlayer_drawMuzzleFlash = 0;
static int jkPlayer_muzzleFlashNode = -1;
#endif

#ifdef FIXED_TIMESTEP_PHYS
int jkPlayer_bJankyPhysics = 0;
#endif

#ifdef JKM_DSS
jkPlayerInfo jkPlayer_aMotsInfos[NUM_JKPLAYER_THINGS] = {0};
jkBubbleInfo jkPlayer_aBubbleInfo[NUM_JKPLAYER_THINGS] = {0};
int jkPlayer_personality = 0;
float jkPlayer_aMultiParams[0x100];
#endif

#ifdef LIGHTSABER_MARKS
sithThing* jkSaber_paDecalThings[256];
int jkSaber_numDecalThings = 0;
#endif

int jkPlayer_aMotsFpBins[74] =
{
    // Category 1
    SITHBIN_F_JUMP,
    SITHBIN_F_PROJECT,
    SITHBIN_F_SEEING,
    SITHBIN_F_SPEED,
    SITHBIN_F_PUSH,
    0,
    0,
    0,
    
    // Category 2
    SITHBIN_F_PULL,
    SITHBIN_F_SABERTHROW,
    SITHBIN_F_GRIP,
    SITHBIN_F_FARSIGHT,
    0,
    0,
    0,
    0,
    
    // Category 3
    SITHBIN_F_PERSUASION,
    SITHBIN_F_HEALING,
    SITHBIN_F_BLINDING,
    SITHBIN_F_CHAINLIGHT,
    0,
    0,
    0,
    0,
    
    // Category 4
    SITHBIN_F_ABSORB,
    SITHBIN_F_DESTRUCTION,
    SITHBIN_F_DEADLYSIGHT,
    SITHBIN_F_PROTECTION,
    0,
    0,
    0,
    0,
    
    //
    // Category amounts per rank
    //

    // Rank 0
    0, 0, 0, 0,
    
    // Rank 1
    2, 0, 0, 0,
    
    // Rank 2
    2, 1, 0, 0,
    
    // Rank 3
    3, 1, 0, 0,
    
    // Rank 4
    4, 1, 0, 0,
    
    // Rank 5
    4, 2, 1, 0,
    
    // Rank 6
    4, 2, 2, 0,
    
    // Rank 7
    4, 2, 2, 1,
    
    // Rank 8
    4, 2, 2, 2,
    
    // Something else?
    3, 2, 1, 0,
    
    // End
    -1,
    0
};

// Added: cvars
void jkPlayer_StartupVars()
{
    sithCvar_RegisterInt("r_fov",                       90,                         &jkPlayer_fov,                      CVARFLAG_LOCAL);
    sithCvar_RegisterBool("r_fovIsVertical",            1,                          &jkPlayer_fovIsVertical,            CVARFLAG_LOCAL);
    sithCvar_RegisterBool("r_enableTextureFilter",      0,                          &jkPlayer_enableTextureFilter,      CVARFLAG_LOCAL);
    sithCvar_RegisterBool("r_enableOrigAspect",         0,                          &jkPlayer_enableOrigAspect,         CVARFLAG_LOCAL);
    sithCvar_RegisterBool("r_enableBloom",              0,                          &jkPlayer_enableBloom,              CVARFLAG_LOCAL);
    sithCvar_RegisterBool("r_enableSSAO",               0,                          &jkPlayer_enableSSAO,               CVARFLAG_LOCAL);
    sithCvar_RegisterInt("r_fpslimit",                  0,                          &jkPlayer_fpslimit,                 CVARFLAG_LOCAL);
    sithCvar_RegisterBool("r_enableVsync",              0,                          &jkPlayer_enableVsync,              CVARFLAG_LOCAL);
    sithCvar_RegisterFlex("r_ssaaMultiple",             1.0,                        &jkPlayer_ssaaMultiple,             CVARFLAG_LOCAL);
    sithCvar_RegisterFlex("r_gamma",                    1.0,                        &jkPlayer_gamma,                    CVARFLAG_LOCAL);
    sithCvar_RegisterBool("r_bEnableJkgm",              1,                          &jkPlayer_bEnableJkgm,              CVARFLAG_LOCAL|CVARFLAG_READONLY);
    sithCvar_RegisterBool("r_bEnableTexturePrecache",   1,                          &jkPlayer_bEnableTexturePrecache,   CVARFLAG_LOCAL|CVARFLAG_READONLY);
    sithCvar_RegisterBool("g_bKeepCorpses",             0,                          &jkPlayer_bKeepCorpses,             CVARFLAG_LOCAL);
    sithCvar_RegisterBool("menu_bFastMissionText",      0,                          &jkPlayer_bFastMissionText,         CVARFLAG_LOCAL);
    sithCvar_RegisterBool("g_bUseOldPlayerPhysics",     0,                          &jkPlayer_bUseOldPlayerPhysics,     CVARFLAG_LOCAL);
    sithCvar_RegisterFlex("hud_scale",                  2.0,                        &jkPlayer_hudScale,                 CVARFLAG_LOCAL|CVARFLAG_RESETHUD);
    sithCvar_RegisterFlex("hud_crosshairLineWidth",     1.0,                        &jkPlayer_crosshairLineWidth,       CVARFLAG_LOCAL|CVARFLAG_RESETHUD);
    sithCvar_RegisterFlex("hud_crosshairScale",         1.0,                        &jkPlayer_crosshairScale,           CVARFLAG_LOCAL|CVARFLAG_RESETHUD);
#ifdef DYNAMIC_POV
	sithCvar_RegisterFlex("hud_aimLock",                1.0,                        &jkPlayer_aimLock,                  CVARFLAG_LOCAL|CVARFLAG_RESETHUD);
#endif
#ifdef DECAL_RENDERING
	sithCvar_RegisterFlex("r_enableDecals",             1.0,                        &jkPlayer_enableDecals,             CVARFLAG_LOCAL | CVARFLAG_RESETHUD);
#endif
#ifdef RAGDOLLS
	sithCvar_RegisterInt("g_ragdolls", 1, &jkPlayer_ragdolls, CVARFLAG_LOCAL | CVARFLAG_UPDATABLE_DEFAULT);
	sithCvar_RegisterInt("r_debugRagdolls", 0, &jkPlayer_debugRagdolls, CVARFLAG_LOCAL | CVARFLAG_UPDATABLE_DEFAULT);
#endif
    sithCvar_RegisterBool("hud_setCrosshairOnLightsaber", 1,                        &jkPlayer_setCrosshairOnLightsaber, CVARFLAG_LOCAL);
    sithCvar_RegisterBool("hud_setCrosshairOnFist",     1,                          &jkPlayer_setCrosshairOnFist,       CVARFLAG_LOCAL);
    sithCvar_RegisterFlex("g_canonicalCogTickrate",     CANONICAL_COG_TICKRATE,     &jkPlayer_canonicalCogTickrate,     CVARFLAG_LOCAL);
    sithCvar_RegisterFlex("g_canonicalPhysTickrate",    CANONICAL_PHYS_TICKRATE,    &jkPlayer_canonicalPhysTickrate,    CVARFLAG_LOCAL);

    sithCvar_RegisterBool("r_hidpi",                     0,                         &Window_isHiDpi_tmp,                CVARFLAG_LOCAL|CVARFLAG_READONLY);
    sithCvar_RegisterBool("r_fullscreen",                0,                         &Window_isFullscreen_tmp,           CVARFLAG_LOCAL|CVARFLAG_READONLY);

#ifdef FIXED_TIMESTEP_PHYS
    sithCvar_RegisterBool("g_bJankyPhysics",             0,                         &jkPlayer_bJankyPhysics,            CVARFLAG_LOCAL);
#endif

#ifdef LIGHTSABER_TRAILS
	sithCvar_RegisterBool("g_saberTrails", 1, &jkSaber_trails, CVARFLAG_LOCAL | CVARFLAG_UPDATABLE_DEFAULT);
	sithCvar_RegisterFlex("g_saberTrailMinVel", 1.0f, &jkSaber_trailMinVel, CVARFLAG_LOCAL | CVARFLAG_UPDATABLE_DEFAULT);
	sithCvar_RegisterFlex("g_saberTrailMaxVel", 4.0f, &jkSaber_trailMaxVel, CVARFLAG_LOCAL | CVARFLAG_UPDATABLE_DEFAULT);
	sithCvar_RegisterFlex("g_saberTrailCutoff", 0.1f, &jkSaber_trailCutoff, CVARFLAG_LOCAL | CVARFLAG_UPDATABLE_DEFAULT);
	sithCvar_RegisterFlex("g_saberTrailShutter", 50.0f, &jkSaber_trailShutter, CVARFLAG_LOCAL | CVARFLAG_UPDATABLE_DEFAULT);
#endif
}

// Added: Clean reset
void jkPlayer_ResetVars()
{
#ifdef QOL_IMPROVEMENTS
    Window_isHiDpi_tmp = 0;
    Window_isFullscreen_tmp = 0;
    jkPlayer_fov = 90;
    jkPlayer_fovIsVertical = 1;
    jkPlayer_enableTextureFilter = 0;
    jkPlayer_enableOrigAspect = 0;
    jkPlayer_enableBloom = 0;
    jkPlayer_enableSSAO = 0;
    jkPlayer_fpslimit = 0;
    jkPlayer_enableVsync = 0;
    jkPlayer_ssaaMultiple = 1.0;
    jkPlayer_gamma = 1.0;
    jkPlayer_bEnableJkgm = 1;
    jkPlayer_bEnableTexturePrecache = 1;
    jkPlayer_bKeepCorpses = 0;
    jkPlayer_bFastMissionText = 0;
    jkPlayer_bUseOldPlayerPhysics = 0;
    jkPlayer_hudScale = 2.0;
    jkPlayer_crosshairLineWidth = 1.0;
    jkPlayer_crosshairScale = 1.0;
    jkPlayer_canonicalCogTickrate = CANONICAL_COG_TICKRATE;
    jkPlayer_canonicalPhysTickrate = CANONICAL_PHYS_TICKRATE;

    jkPlayer_setCrosshairOnLightsaber = 1;
    jkPlayer_setCrosshairOnFist = 1;

    jkPlayer_bHasLoadedSettingsOnce = 0;

#ifdef DECAL_RENDERING
	jkPlayer_enableDecals = 1;
#endif

#ifdef RAGDOLLS
	jkPlayer_debugRagdolls = 0;
#endif
#endif

#ifdef DYNAMIC_POV
	rdVector_Zero3(&jkSaber_aimAngles);
	rdVector_Zero3(&jkSaber_aimVector);
	rdVector_Zero3(&jkSaber_swayOffset);
	rdVector_Zero3(&jkPlayer_idleWaggleVec);
	rdVector_Zero3(&jkPlayer_pushAngles);
	rdVector_Zero3(&jkPlayer_muzzleOffset);
	rdVector_Zero3(&jkPlayer_crosshairPos);
	jkPlayer_idleWaggleSpeed = 0.0f;
	jkPlayer_idleWaggleSmooth = 0.0f;
	jkPlayer_aimLock = 0;
	jkPlayer_povAutoAimFov = 0.0f;
	jkPlayer_povAutoAimDist = 0.0f;
	jkPlayer_drawMuzzleFlash = 0;
	jkPlayer_muzzleFlashNode = -1;
#endif

#ifdef FIXED_TIMESTEP_PHYS
    jkPlayer_bJankyPhysics = 0;
#endif

#ifdef JKM_DSS
    memset(jkPlayer_aMotsInfos, 0, sizeof(jkPlayer_aMotsInfos));
    memset(jkPlayer_aBubbleInfo, 0, sizeof(jkPlayer_aBubbleInfo));
    jkPlayer_personality = 0;
    memset(jkPlayer_aMultiParams, 0, sizeof(jkPlayer_aMultiParams));
#endif
}

int jkPlayer_LoadAutosave()
{
    char tmp[128];

    jkPlayer_bLoadingSomething = 1;
    stdString_snprintf(tmp, 128, "%s%s", "_JKAUTO_", sithWorld_pCurrentWorld->map_jkl_fname);
    stdFnames_ChangeExt(tmp, "jks");
    return sithGamesave_Load(tmp, 0, 0);
}

int jkPlayer_LoadSave(char *path)
{
    jkPlayer_bLoadingSomething = 1;
    return sithGamesave_Load(path, 0, 1);
}

void jkPlayer_Startup()
{
    jkPlayer_InitThings();
    _memcpy(&jkSaber_rotateMat, &rdroid_identMatrix34, sizeof(jkSaber_rotateMat));
#ifdef LIGHTSABER_MARKS
	memset(jkSaber_paDecalThings, 0, sizeof(sithThing*) * 256);
#endif
}

// MOTS altered, also fixed the memleak lol
void jkPlayer_Shutdown()
{
    for (int i = 0; i < jkPlayer_numThings; i++ )
    {
        rdPolyLine_FreeEntry(&playerThings[i].polyline); // Added: prevent memleak

        if (playerThings[i].polylineThing.model3)
        {
            rdThing_FreeEntry(&playerThings[i].polylineThing);
            playerThings[i].polylineThing.model3 = 0;
        }

#ifdef LIGHTSABER_GLOW
		rdSprite_FreeEntry(&playerThings[i].glowSprite); // Added: prevent memleak

		if (playerThings[i].glowSpriteThing.sprite3)
		{
			rdThing_FreeEntry(&playerThings[i].glowSpriteThing);
			playerThings[i].glowSpriteThing.sprite3 = 0;
		}
#endif

        rdThing_FreeEntry(&playerThings[i].povModel); // Added: prevent memleak
#ifdef DYNAMIC_POV
		rdThing_FreeEntry(&playerThings[i].povSprite);
#endif
        rdThing_FreeEntry(&playerThings[i].rd_thing); // Added: fix memleak
    }
    _memset(playerThings, 0, sizeof(playerThings));
    
    for (int i = 0; i < jkPlayer_numOtherThings; i++)
    {
        if (jkPlayer_otherThings[i].polylineThing.model3)
        {
            rdThing_FreeEntry(&jkPlayer_otherThings[i].polylineThing);
            jkPlayer_otherThings[i].polylineThing.model3 = 0;
#ifdef LIGHTSABER_GLOW
			rdThing_FreeEntry(&jkPlayer_otherThings[i].glowSpriteThing);
			jkPlayer_otherThings[i].glowSpriteThing.sprite3 = 0;
#endif
        }
    }
    _memset(jkPlayer_otherThings, 0, sizeof(jkPlayer_otherThings));

#ifdef JKM_DSS
    for (int i = 0; i < NUM_JKPLAYER_THINGS; i++)
    {
        rdPolyLine_FreeEntry(&jkPlayer_aMotsInfos[i].polyline); // Added: prevent memleak

        if (jkPlayer_aMotsInfos[i].polylineThing.model3)
        {
            rdThing_FreeEntry(&jkPlayer_otherThings[i].polylineThing);
            jkPlayer_aMotsInfos[i].polylineThing.model3 = 0;
        }

#ifdef LIGHTSABER_GLOW
		rdSprite_FreeEntry(&jkPlayer_aMotsInfos[i].glowSprite); // Added: prevent memleak

		if (jkPlayer_aMotsInfos[i].glowSpriteThing.sprite3)
		{
			rdThing_FreeEntry(&playerThings[i].glowSpriteThing);
			jkPlayer_aMotsInfos[i].glowSpriteThing.sprite3 = 0;
		}
#endif

        rdThing_FreeEntry(&jkPlayer_aMotsInfos[i].povModel); // Added: prevent memleak
#ifdef DYNAMIC_POV
		rdThing_FreeEntry(&jkPlayer_aMotsInfos[i].povSprite);
#endif
        rdThing_FreeEntry(&jkPlayer_aMotsInfos[i].rd_thing); // Added: fix memleak
    }
    _memset(jkPlayer_aMotsInfos, 0, sizeof(jkPlayer_aMotsInfos));
#endif
    //nullsub_28_free();
    
}

void jkPlayer_Open()
{
    // MOTS added
    if (sithPlayer_pLocalPlayerThing && sithPlayer_pLocalPlayerThing->playerInfo) {
        sithPlayer_pLocalPlayerThing->playerInfo->personality = jkPlayer_personality;
    }
}

void jkPlayer_Close()
{
}

// MOTS altered
void jkPlayer_InitSaber()
{
    jkPlayer_numThings = jkPlayer_maxPlayers;
    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        jkPlayerInfo* playerInfoJk = &playerThings[i];
        sithPlayerInfo* playerInfo = &jkPlayer_playerInfos[i];

        playerInfoJk->actorThing = playerInfo->playerThing;
        if (playerInfo->playerThing) // Added
            playerInfo->playerThing->playerInfo = playerInfoJk;
        playerInfoJk->maxTwinkles = 8;
        playerInfoJk->twinkleSpawnRate = 16;
        playerInfoJk->bHasSuperWeapon = 0;
        playerInfoJk->bHasSuperShields = 0;
        if (playerInfo->playerThing) // Added
            playerInfo->playerThing->thingflags |= SITH_TF_RENDERWEAPON;
        playerInfoJk->bHasForceSurge = 0;
        
        // MOTS added
#ifdef JKM_DSS
        playerInfoJk->jkmUnk4 = 0;
        playerInfoJk->jkmUnk5 = 0;
        playerInfoJk->jkmUnk6 = 0;
#endif

        sithThing* saberSparks = sithTemplate_GetEntryByName("+ssparks_saber");
        sithThing* bloodSparks = sithTemplate_GetEntryByName("+ssparks_blood");
        sithThing* wallSparks = sithTemplate_GetEntryByName("+ssparks_wall");
        
        jkSaber_InitializeSaberInfo(playerThings[i].actorThing, "sabergreen1.mat", "sabergreen0.mat", 0.0032, 0.0018, 0.12, wallSparks, bloodSparks, saberSparks);
    }
}

void jkPlayer_InitThings()
{
    jkPlayer_numThings = jkPlayer_maxPlayers;
    for (int i = 0; i < jkPlayer_maxPlayers; i++)
    {
        jkPlayerInfo* playerInfoJk = &playerThings[i];
        sithPlayerInfo* playerInfo = &jkPlayer_playerInfos[i];

        playerInfoJk->actorThing = playerInfo->playerThing;

        // Added: Possible nullptr deref in co-op? wtf is this loop doing anyhow
        if (playerInfo->playerThing)
        {
            playerInfo->playerThing->playerInfo = playerInfoJk;
            playerInfo->playerThing->thingflags |= SITH_TF_RENDERWEAPON;
        }
    }

    int num = 0;
    jkPlayer_numOtherThings = 0;

    // Added: Properly serialize sabers.
#ifdef QOL_IMPROVEMENTS
    for (int i = 0; i < sithWorld_pCurrentWorld->numThingsLoaded; i++)
    {
        sithThing* thingIter = &sithWorld_pCurrentWorld->things[i];

        if (thingIter->type == SITH_THING_ACTOR 
            && thingIter->actorParams.typeflags & SITH_AF_BOSS 
            && thingIter->playerInfo )
        {
            thingIter->playerInfo->actorThing = thingIter;
            thingIter->playerInfo->rd_thing.model3 = 0;
            thingIter->thingflags |= SITH_TF_RENDERWEAPON;

            jkPlayer_numOtherThings++;
            num++;
        }
    }
#endif
    
    // Added: skip already initted
    jkPlayerInfo* playerInfoIter = &jkPlayer_otherThings[jkPlayer_numOtherThings];
    for (int i = 0; i < sithWorld_pCurrentWorld->numThingsLoaded; i++)
    {
        sithThing* thingIter = &sithWorld_pCurrentWorld->things[i];

        if (thingIter->type == SITH_THING_ACTOR 
            && thingIter->actorParams.typeflags & SITH_AF_BOSS 
            && playerInfoIter < &jkPlayer_otherThings[NUM_JKPLAYER_THINGS] // off by one?
            && !thingIter->playerInfo // Added: skip already initted
            ) 
        {
            playerInfoIter->actorThing = thingIter;
            thingIter->playerInfo = playerInfoIter;
            playerInfoIter->rd_thing.model3 = 0;
            thingIter->thingflags |= SITH_TF_RENDERWEAPON;

            // MOTS added: weird hack?
            if (Main_bMotsCompat && !playerInfoIter->polylineThing.polyline) {
                sithThing* saberSparks = sithTemplate_GetEntryByName("+ssparks_saber");
                sithThing* bloodSparks = sithTemplate_GetEntryByName("+ssparks_blood");
                sithThing* wallSparks = sithTemplate_GetEntryByName("+ssparks_wall");

                jkSaber_InitializeSaberInfo(thingIter, "saberred1.mat", "saberred0.mat", 0.0032, 0.0018, 0.12, wallSparks, bloodSparks, saberSparks);
            }

            playerInfoIter++;
            ++num;
        }
    }

    jkPlayer_numOtherThings = num;
}

void jkPlayer_nullsub_1(jkPlayerInfo* unk)
{
}

// MOTS altered? TODO
void jkPlayer_CreateConf(wchar_t *name)
{
    int v6; // ebp
    char *v7; // edi
    int *v8; // esi
    char *v9; // edi
    int *v10; // esi
    int v11; // [esp+10h] [ebp-144h]
    char a1[32]; // [esp+34h] [ebp-120h]
    char pathName[128]; // [esp+D4h] [ebp-80h]

#ifdef QOL_IMPROVEMENTS
    jkPlayer_ResetVars();
    sithCvar_ResetLocals();
#endif

    stdString_WcharToChar(a1, name, 31);
    a1[31] = 0;
    stdFileUtil_MkDir("player");
    stdFnames_MakePath(pathName, 128, "player", a1);
    stdFileUtil_MkDir(pathName);
    sithControl_InputInit();
    jkHudInv_InputInit();
    jkPlayer_SetRank(0);
    sithPlayer_SetBinAmt(SITHBIN_CHOICE, 0.0);
    sithWeapon_InitDefaults();
    jkGame_SetDefaultSettings();
    stdString_SafeWStrCopy(jkPlayer_playerShortName, name, 32);
    jkPlayer_setNumCutscenes = 0;
    v11 = sithControl_IsOpen();
    if ( v11 )
        sithControl_Close();
    jkPlayer_ReadConf(jkPlayer_playerShortName);

    if ( jkPlayer_setNumCutscenes <= 0 )
    {
LABEL_7:
        if ( jkPlayer_setNumCutscenes < 32 )
        {
            _strncpy(&jkPlayer_cutscenePath[32 * jkPlayer_setNumCutscenes], "01-02a.smk", 0x1Fu);
            jkPlayer_cutscenePath[32 * jkPlayer_setNumCutscenes + 31] = 0; // TODO macro 
            jkPlayer_aCutsceneVal[jkPlayer_setNumCutscenes] = 1;
            jkPlayer_setNumCutscenes = jkPlayer_setNumCutscenes + 1;
            jkPlayer_WriteConf(name);
            if ( v11 )
                sithControl_Open();
        }
    }
    else
    {
        char* pathIter = jkPlayer_cutscenePath;
        int count = 0;
        while ( 1 )
        {
            if ( !_memcmp(pathIter, "01-02a.smk", 0xBu) )
                break;
            ++count;
            pathIter += 32;
            if ( count >= jkPlayer_setNumCutscenes )
                goto LABEL_7;
        }
    }
    jkPlayer_WriteConf(name);
}

// MOTS altered
void jkPlayer_WriteConf(wchar_t *name)
{
    char nameTmp[32]; // [esp+0h] [ebp-A0h]
    char fpath[128]; // [esp+20h] [ebp-80h]
    char ext_fpath[256];
    char ext_fpath_cvars[256];

#ifdef QOL_IMPROVEMENTS
    sithCvar_SaveGlobals();
#endif

    if (!name[0]) return; // Added

    stdString_WcharToChar(nameTmp, name, 31);
    nameTmp[31] = 0;
    stdFnames_MakePath3(ext_fpath, 256, "player", nameTmp, "openjkdf2.json"); // Added
    stdFnames_MakePath3(ext_fpath_cvars, 256, "player", nameTmp, SITHCVAR_FNAME); // Added
    stdString_snprintf(fpath, 128, "player\\%s\\%s.plr", nameTmp, nameTmp);
    if ( stdConffile_OpenWrite(fpath) )
    {
        stdConffile_Printf("version %d\n", 1);
        stdConffile_Printf("diff %d\n", jkPlayer_setDiff);
        jkPlayer_WriteOptionsConf();
        sithWeapon_WriteConf();
        sithControl_WriteConf();
        if ( stdConffile_Printf("numCutscenes %d\n", jkPlayer_setNumCutscenes) )
        {
            char* pathIter = jkPlayer_cutscenePath;
            for (int i = 0; i < jkPlayer_setNumCutscenes; i++)
            {
                if ( !stdConffile_Printf("%s %d\n", pathIter, jkPlayer_aCutsceneVal[i]) )
                    break;
                pathIter += 32;
            }
        }
#ifdef QOL_IMPROVEMENTS
        stdJSON_SaveInt(ext_fpath, "fov", jkPlayer_fov);
        stdJSON_SaveBool(ext_fpath, "fovisvertical", jkPlayer_fovIsVertical);
        stdJSON_SaveBool(ext_fpath, "windowishidpi", Window_isHiDpi);
        stdJSON_SaveBool(ext_fpath, "windowfullscreen", Window_isFullscreen);
        stdJSON_SaveBool(ext_fpath, "texturefiltering", jkPlayer_enableTextureFilter);
        stdJSON_SaveBool(ext_fpath, "originalaspect", jkPlayer_enableOrigAspect);
        stdJSON_SaveInt(ext_fpath, "fpslimit", jkPlayer_fpslimit);
        stdJSON_SaveBool(ext_fpath, "enablevsync", jkPlayer_enableVsync);
        stdJSON_SaveBool(ext_fpath, "enablebloom", jkPlayer_enableBloom);
        stdJSON_SaveFloat(ext_fpath, "ssaamultiple", jkPlayer_ssaaMultiple);
        stdJSON_SaveInt(ext_fpath, "enablessao", jkPlayer_enableSSAO);
        stdJSON_SaveFloat(ext_fpath, "gamma", jkPlayer_gamma);
        stdJSON_SaveBool(ext_fpath, "bEnableJkgm", jkPlayer_bEnableJkgm);
        stdJSON_SaveBool(ext_fpath, "bEnableTexturePrecache", jkPlayer_bEnableTexturePrecache);
        stdJSON_SaveBool(ext_fpath, "bKeepCorpses", jkPlayer_bKeepCorpses);
        stdJSON_SaveBool(ext_fpath, "bFastMissionText", jkPlayer_bFastMissionText);
        stdJSON_SaveFloat(ext_fpath, "hudScale", jkPlayer_hudScale);
        stdJSON_SaveFloat(ext_fpath, "crosshairLineWidth", jkPlayer_crosshairLineWidth);
        stdJSON_SaveFloat(ext_fpath, "crosshairScale", jkPlayer_crosshairScale);
        stdJSON_SaveFloat(ext_fpath, "canonicalCogTickrate", jkPlayer_canonicalCogTickrate);
        stdJSON_SaveFloat(ext_fpath, "canonicalPhysTickrate", jkPlayer_canonicalPhysTickrate);

        stdJSON_SaveBool(ext_fpath, "bUseOldPlayerPhysics", jkPlayer_bUseOldPlayerPhysics);

        stdJSON_SaveBool(ext_fpath, "setCrosshairOnLightsaber", jkPlayer_setCrosshairOnLightsaber);
        stdJSON_SaveBool(ext_fpath, "setCrosshairOnFist", jkPlayer_setCrosshairOnFist);
#ifdef DYNAMIC_POV
		stdJSON_SaveBool(ext_fpath, "aimLock", jkPlayer_aimLock);
#endif
#ifdef DECAL_RENDERING
		stdJSON_SaveBool(ext_fpath, "decals", jkPlayer_enableDecals);
#endif
#endif
#ifdef FIXED_TIMESTEP_PHYS
        stdJSON_SaveBool(ext_fpath, "bJankyPhysics", jkPlayer_bJankyPhysics);
#endif

#ifdef QOL_IMPROVEMENTS
        Window_isHiDpi_tmp = Window_isHiDpi;
        Window_isFullscreen_tmp = Window_isFullscreen;
        sithCvar_SaveLocals(ext_fpath_cvars);
#endif

        stdConffile_CloseWrite();
    }
}

#ifdef QOL_IMPROVEMENTS
void jkPlayer_ParseLegacyExt()
{
    if (stdConffile_ReadLine())
    {
        _sscanf(stdConffile_aLine, "fov %d", &jkPlayer_fov);
    }

    if (stdConffile_ReadLine())
    {
        _sscanf(stdConffile_aLine, "fovisvertical %d", &jkPlayer_fovIsVertical);
        jkPlayer_fovIsVertical = !!jkPlayer_fovIsVertical;
    }

    int dpi_tmp = 0;
    if (stdConffile_ReadLine())
    {
        _sscanf(stdConffile_aLine, "windowishidpi %d", &dpi_tmp);
        dpi_tmp = !!dpi_tmp;
        Window_SetHiDpi(dpi_tmp);
    }

    int fulltmp = 0;
    if (stdConffile_ReadLine())
    {
        _sscanf(stdConffile_aLine, "windowfullscreen %d", &fulltmp);
        fulltmp = !!fulltmp;
        Window_SetFullscreen(fulltmp);
    }

    if (stdConffile_ReadLine())
    {
        _sscanf(stdConffile_aLine, "texturefiltering %d", &jkPlayer_enableTextureFilter);
        jkPlayer_enableTextureFilter = !!jkPlayer_enableTextureFilter;
    }

    if (stdConffile_ReadLine())
    {
        _sscanf(stdConffile_aLine, "originalaspect %d", &jkPlayer_enableOrigAspect);
        jkPlayer_enableOrigAspect = !!jkPlayer_enableOrigAspect;
    }

    if (stdConffile_ReadLine())
    {
        _sscanf(stdConffile_aLine, "fpslimit %d", &jkPlayer_fpslimit);
    }

    if (stdConffile_ReadLine())
    {
        _sscanf(stdConffile_aLine, "enablevsync %d", &jkPlayer_enableVsync);
        jkPlayer_enableVsync = !!jkPlayer_enableVsync;
    }

    if (stdConffile_ReadLine())
    {
        _sscanf(stdConffile_aLine, "enablebloom %d", &jkPlayer_enableBloom);
        jkPlayer_enableBloom = !!jkPlayer_enableBloom;
    }

    if (stdConffile_ReadLine())
    {
        if (_sscanf(stdConffile_aLine, "ssaamultiple %f", &jkPlayer_ssaaMultiple) != 1)
            jkPlayer_ssaaMultiple = 1.0;
    }

    if (stdConffile_ReadLine())
    {
        _sscanf(stdConffile_aLine, "enablessao %d", &jkPlayer_enableSSAO);
        jkPlayer_enableSSAO = !!jkPlayer_enableSSAO;
    }

    if (stdConffile_ReadLine())
    {
        if (_sscanf(stdConffile_aLine, "gamma %f", &jkPlayer_gamma) != 1)
            jkPlayer_gamma = 1.0;
    }
#ifdef DECAL_RENDERING
	if (stdConffile_ReadLine())
	{
		if (_sscanf(stdConffile_aLine, "decals %f", &jkPlayer_enableDecals) != 1)
			jkPlayer_enableDecals = 1.0;
	}
#endif
}
#endif

int jkPlayer_ReadConf(wchar_t *name)
{
    char *v4; // edi
    char v6[32]; // [esp+10h] [ebp-A0h]
    char fpath[256]; // Added: 128 -> 256
    char ext_fpath[256];
    char ext_fpath_cvars[256];

    int version = 0;
    if (!jkPlayer_VerifyWcharName(name))
        return 0;

    stdString_WcharToChar(v6, name, 31);
    v6[31] = 0;
    _wcsncpy(jkPlayer_playerShortName, name, 0x1Fu);
    jkPlayer_playerShortName[31] = 0;
    stdFnames_MakePath3(ext_fpath, 256, "player", v6, "openjkdf2.json");
    stdFnames_MakePath3(ext_fpath_cvars, 256, "player", v6, SITHCVAR_FNAME); // Added
    stdString_snprintf(fpath, 256, "player\\%s\\%s.plr", v6, v6); // Added: sprintf -> snprintf
    if (!stdConffile_OpenRead(fpath))
        return 0;

    if ( stdConffile_ReadLine() && _sscanf(stdConffile_aLine, "version %d", &version) == 1 && version == 1 && stdConffile_ReadLine() )
    {
        _sscanf(stdConffile_aLine, "diff %d", &jkPlayer_setDiff);
        if ( jkPlayer_setDiff < 0 )
        {
            jkPlayer_setDiff = 0;
        }
        else if ( jkPlayer_setDiff > 2 )
        {
            jkPlayer_setDiff = 2;
        }
        jkPlayer_ReadOptionsConf();
        sithWeapon_ReadConf();
        //jk_printf("%s\n", stdConffile_aLine);
        sithControl_ReadConf();

        // HACK
#ifdef TARGET_TWL
        sithControl_InputInit();
#endif
        if ( stdConffile_ReadArgs() )
        {
            if ( stdConffile_entry.numArgs >= 1u
              && !_memcmp(stdConffile_entry.args[0].key, "numcutscenes", 0xDu)
              && _sscanf(stdConffile_entry.args[1].value, "%d", &jkPlayer_setNumCutscenes) == 1 )
            {
                v4 = jkPlayer_cutscenePath;
                for (int i = 0; i < jkPlayer_setNumCutscenes; i++)
                {
                    if ( !stdConffile_ReadArgs() )
                        break;
                    if ( stdConffile_entry.numArgs < 2u )
                        break;
                    if ( _sscanf(stdConffile_entry.args[0].key, "%s", v4) != 1 )
                        break;
                    if ( _sscanf(stdConffile_entry.args[1].value, "%d", &jkPlayer_aCutsceneVal[i]) != 1 )
                        break;
                    v4 += 32;
                }
            }
        }
#ifdef QOL_IMPROVEMENTS
        // Unfortunately we have to live with our past mistakes and keep all of this parsing.
        jkPlayer_ParseLegacyExt();

        // New JSON parsing
        jkPlayer_fov = stdJSON_GetInt(ext_fpath, "fov", jkPlayer_fov);
        jkPlayer_fovIsVertical = stdJSON_GetBool(ext_fpath, "fovisvertical", jkPlayer_fovIsVertical);
        Window_isHiDpi_tmp = stdJSON_GetBool(ext_fpath, "windowishidpi", Window_isHiDpi);
        Window_isFullscreen_tmp = stdJSON_GetBool(ext_fpath, "windowfullscreen", Window_isFullscreen);
        jkPlayer_enableTextureFilter = stdJSON_GetBool(ext_fpath, "texturefiltering", jkPlayer_enableTextureFilter);
        jkPlayer_enableOrigAspect = stdJSON_GetBool(ext_fpath, "originalaspect", jkPlayer_enableOrigAspect);
        jkPlayer_fpslimit = stdJSON_GetInt(ext_fpath, "fpslimit", jkPlayer_fpslimit);
        jkPlayer_enableVsync = stdJSON_GetBool(ext_fpath, "enablevsync", jkPlayer_enableVsync);
        jkPlayer_enableBloom = stdJSON_GetBool(ext_fpath, "enablebloom", jkPlayer_enableBloom);
        jkPlayer_ssaaMultiple = stdJSON_GetFloat(ext_fpath, "ssaamultiple", jkPlayer_ssaaMultiple);
        jkPlayer_enableSSAO = stdJSON_GetInt(ext_fpath, "enablessao", jkPlayer_enableSSAO);
        jkPlayer_gamma = stdJSON_GetFloat(ext_fpath, "gamma", jkPlayer_gamma);

        jkPlayer_bEnableJkgm = stdJSON_GetBool(ext_fpath, "bEnableJkgm", jkPlayer_bEnableJkgm);
        jkPlayer_bEnableTexturePrecache = stdJSON_GetBool(ext_fpath, "bEnableTexturePrecache", jkPlayer_bEnableTexturePrecache);
        jkPlayer_bKeepCorpses = stdJSON_GetBool(ext_fpath, "bKeepCorpses", jkPlayer_bKeepCorpses);
        jkPlayer_bFastMissionText = stdJSON_GetBool(ext_fpath, "bFastMissionText", jkPlayer_bFastMissionText);
        jkPlayer_hudScale = stdJSON_GetFloat(ext_fpath, "hudScale", jkPlayer_hudScale);
        jkPlayer_crosshairLineWidth = stdJSON_GetFloat(ext_fpath, "crosshairLineWidth", jkPlayer_crosshairLineWidth);
        jkPlayer_crosshairScale = stdJSON_GetFloat(ext_fpath, "crosshairScale", jkPlayer_crosshairScale);
        jkPlayer_canonicalCogTickrate = stdJSON_GetFloat(ext_fpath, "canonicalCogTickrate", jkPlayer_canonicalCogTickrate);
        jkPlayer_canonicalPhysTickrate = stdJSON_GetFloat(ext_fpath, "canonicalPhysTickrate", jkPlayer_canonicalPhysTickrate);

        jkPlayer_bUseOldPlayerPhysics = stdJSON_GetBool(ext_fpath, "bUseOldPlayerPhysics", jkPlayer_bUseOldPlayerPhysics);

        jkPlayer_setCrosshairOnLightsaber = stdJSON_GetBool(ext_fpath, "setCrosshairOnLightsaber", jkPlayer_setCrosshairOnLightsaber);
        jkPlayer_setCrosshairOnFist = stdJSON_GetBool(ext_fpath, "setCrosshairOnFist", jkPlayer_setCrosshairOnFist);
#ifdef DYNAMIC_POV
		jkPlayer_aimLock = stdJSON_GetFloat(ext_fpath, "aimLock", jkPlayer_aimLock);
#endif

#ifdef DECAL_RENDERING
		jkPlayer_enableDecals = stdJSON_GetFloat(ext_fpath, "decals", jkPlayer_enableDecals);
#endif
#endif
#ifdef FIXED_TIMESTEP_PHYS
        jkPlayer_bJankyPhysics = stdJSON_GetBool(ext_fpath, "bJankyPhysics", jkPlayer_bJankyPhysics);
#endif

#ifdef QOL_IMPROVEMENTS
        sithCvar_LoadLocals(ext_fpath_cvars);

        if (jkPlayer_fov < FOV_MIN)
            jkPlayer_fov = FOV_MIN;
        if (jkPlayer_fov > FOV_MAX)
            jkPlayer_fov = FOV_MAX;

        Window_SetHiDpi(Window_isHiDpi_tmp);
        Window_SetFullscreen(Window_isFullscreen_tmp);

        std3D_UpdateSettings();

        jkPlayer_bHasLoadedSettingsOnce = 1;
#endif
        
        stdConffile_Close();
        return 1;
    }
    else
    {
        stdConffile_Close();
        jkPlayer_setDiff = 1;
        sithControl_InputInit();
        return 0;
    }
    return 0;
}

#ifdef DYNAMIC_POV
void jkPlayer_PovModelCallback(sithThing* thing, int track, uint32_t markerId)
{
	if(thing == playerThings[playerThingIdx].actorThing && markerId == 3)
	{
		// enable/disable
		jkPlayer_drawMuzzleFlash = sithTime_curMs + 50; // 50ms
		
		// randomize the cel
		if(thing->playerInfo->povSprite.sprite3 && thing->playerInfo->povSprite.sprite3->face.material)
		{
			int celCount = thing->playerInfo->povSprite.sprite3->face.material->num_texinfo;
			thing->playerInfo->povSprite.wallCel = min(_frand() * celCount, celCount - 1);
		}
	}
}

void jkPlayer_SetPovSprite(jkPlayerInfo* info, rdSprite* sprite)
{
	if (info->povSprite.type != 1 || info->povSprite.sprite3 != sprite)
	{
		rdThing_FreeEntry(&info->povSprite);
		rdThing_NewEntry(&info->povSprite, info->actorThing);
		if (sprite)
			rdThing_SetSprite3(&info->povSprite, sprite);
	}
	jkPlayer_drawMuzzleFlash = 0;
}
#endif

void jkPlayer_SetPovModel(jkPlayerInfo *info, rdModel3 *model)
{
    rdThing *thing; // esi

    thing = &info->povModel;
    if ( info->povModel.type != 1 || info->povModel.model3 != model )
    {
        rdThing_FreeEntry(&info->povModel);
        rdThing_NewEntry(thing, info->actorThing);

#ifdef DYNAMIC_POV
		jkPlayer_muzzleFlashNode = -1;
		jkPlayer_drawMuzzleFlash = 0;
#endif

        // Added: nullptr check, for fixing UAF on second world load
        if (model) {
            rdThing_SetModel3(thing, model);
            info->povModel.puppet = rdPuppet_New(thing);
#ifdef DYNAMIC_POV
			for (uint32_t i = 0; i < 4; i++)
			{
				rdPuppetTrack* track = &info->povModel.puppet->tracks[i];
				track->callback = jkPlayer_PovModelCallback;
			}

			// Look for a muzzle node, we do a search instead of using specific anim classes since weapons can have different hierarchy orders
			for (int i = 0; i < playerThings[playerThingIdx].povModel.model3->numHierarchyNodes; i++)
			{
				int l = _strlen(playerThings[playerThingIdx].povModel.model3->hierarchyNodes[i].name);
				if (l < 5) continue; // sanity check
				if (!__strcmpi(playerThings[playerThingIdx].povModel.model3->hierarchyNodes[i].name, "k_muzzle"))
				{
					jkPlayer_muzzleFlashNode = i;
					break;
				}
			}
#endif
        }
        else
        {
            info->povModel.puppet = NULL;
        }
    }
}

void jkPlayer_DrawPov()
{
    rdVector3 trans;
    rdMatrix34 viewMat;

    if (!playerThings[playerThingIdx].povModel.model3)
        return;

    if ( playerThings[playerThingIdx].povModel.puppet )
    {
        rdPuppet_UpdateTracks(playerThings[playerThingIdx].povModel.puppet, sithTime_deltaSeconds);
    }

    if ( !(sithCamera_currentCamera->cameraPerspective & 0xFC) && sithCamera_currentCamera->primaryFocus == sithWorld_pCurrentWorld->cameraFocus )
    {
        sithThing* player = playerThings[playerThingIdx].actorThing;

        // TODO: I think this explains some weird duplication
#ifndef QOL_IMPROVEMENTS
        float waggleAmt = (fabs(player->waggle) > 0.02 ? 0.02 : fabs(player->waggle)) * jkPlayer_waggleMag;
#else
        float waggleAmt = (fabs(player->waggle) > sithTime_deltaSeconds ? sithTime_deltaSeconds : fabs(player->waggle)) * jkPlayer_waggleMag; // scale animation to be in line w/ 50fps og limit
#endif
#ifdef DYNAMIC_POV
		if (jkPlayer_waggleVel < 0)
			waggleAmt = sithTime_deltaSeconds * jkPlayer_waggleMag;

		// don't freaking waggle while in the air/jumping, it looks funny
		if(player->attach_flags == 0 && jkPlayer_waggleVel >= 0.0f)
			waggleAmt = 0.0f;
#endif

        if ( waggleAmt == 0.0 )
            jkPlayer_waggleAngle = 0.0;
        else
            jkPlayer_waggleAngle = waggleAmt + jkPlayer_waggleAngle;

        // TODO is this a macro/func?
        float angleSin, angleCos;
        stdMath_SinCos(jkPlayer_waggleAngle, &angleSin, &angleCos);
        float velNorm = rdVector_Len3(&player->physicsParams.vel) / player->physicsParams.maxVel; // MOTS altered: uses 1.538462 for something (performance hack?)
        if (angleCos > 0) // verify?
            angleCos = -angleCos;
#ifdef DYNAMIC_POV
		if (jkPlayer_waggleVel < 0)
			velNorm = -jkPlayer_waggleVel;
		else
			velNorm *= jkPlayer_waggleVel;

		// Added: take into account rotvel to add a little dynamic rotation to the POV model
		rdMatrix34 rotateMatNoWaggle;
		if(!jkPlayer_aimLock)
		{
			float timeScale = 1.0f;
			if (g_debugmodeFlags & DEBUGFLAG_SLOWMO)
				timeScale = 0.2;

			static rdVector3 lastRotVelNorm = {0,0,0};
			rdVector3 rotVelNorm;
			rotVelNorm.x = -timeScale * player->physicsParams.angVel.x / player->physicsParams.maxRotVel;
			rotVelNorm.y = -timeScale * player->physicsParams.angVel.y / player->physicsParams.maxRotVel;
			rotVelNorm.z = -timeScale * player->physicsParams.angVel.z / player->physicsParams.maxRotVel;
			jkSaber_rotateVec.x = lastRotVelNorm.x + (rotVelNorm.x - lastRotVelNorm.x) * 0.8f;
			jkSaber_rotateVec.y = lastRotVelNorm.y + (rotVelNorm.y - lastRotVelNorm.y) * 0.8f;
			jkSaber_rotateVec.z = lastRotVelNorm.z + (rotVelNorm.z - lastRotVelNorm.z) * 0.8f;
			lastRotVelNorm = jkSaber_rotateVec;

			// Added: add a small rotation based on pitch
			static float lastPitch = 0.0f;
			float lerpPitch = (player->actorParams.eyePYR.x - lastPitch);
			jkSaber_rotateVec.x -= lerpPitch * 0.2f;
			lastPitch = lastPitch + lerpPitch * 0.2f;
			//jkSaber_rotateVec.x -= player->actorParams.eyePYR.x * 0.06f;

			rdMatrix_BuildRotate34(&rotateMatNoWaggle, &jkSaber_rotateVec);
			
			jkSaber_rotateVec.x += angleCos * jkPlayer_waggleVec.x * velNorm;
			jkSaber_rotateVec.y += angleSin * jkPlayer_waggleVec.y * velNorm;
			jkSaber_rotateVec.z += angleSin * jkPlayer_waggleVec.z * velNorm;
		}
		else
		{
			jkSaber_rotateVec.x = angleCos * jkPlayer_waggleVec.x * velNorm;
			jkSaber_rotateVec.y = angleSin * jkPlayer_waggleVec.y * velNorm;
			jkSaber_rotateVec.z = angleSin * jkPlayer_waggleVec.z * velNorm;
		}
#else
		jkSaber_rotateVec.x = angleCos * jkPlayer_waggleVec.x * velNorm;
		jkSaber_rotateVec.y = angleSin * jkPlayer_waggleVec.y * velNorm;
		jkSaber_rotateVec.z = angleSin * jkPlayer_waggleVec.z * velNorm;
#endif
        rdMatrix_BuildRotate34(&jkSaber_rotateMat, &jkSaber_rotateVec);

#ifdef SDL2_RENDER
        // Force weapon to draw in front of scene
        std3D_ClearZBuffer();
        rdSetZBufferMethod(RD_ZBUFFER_READ_WRITE);
        rdSetSortingMethod(2);
        rdSetOcclusionMethod(0);
#else
        // Force weapon to draw in front of scene
        rdSetZBufferMethod(RD_ZBUFFER_NOREAD_NOWRITE); // set RD_ZBUFFER_READ_WRITE to have guns clip through walls
        rdSetSortingMethod(2);
        rdSetOcclusionMethod(0);
#endif

#ifdef RGB_AMBIENT
		rdVector3 ambLight;
		rdVector_Copy3(&ambLight, &sithCamera_currentCamera->sector->ambientRGB);
		ambLight.x += sithCamera_currentCamera->sector->extraLight;
		ambLight.y += sithCamera_currentCamera->sector->extraLight;
		ambLight.z += sithCamera_currentCamera->sector->extraLight;
		rdCamera_SetAmbientLight(&sithCamera_currentCamera->rdCam, &ambLight);
		rdCamera_SetDirectionalAmbientLight(&sithCamera_currentCamera->rdCam, &sithCamera_currentCamera->sector->ambientSH);
#else
        float ambLight = sithCamera_currentCamera->sector->extraLight + sithCamera_currentCamera->sector->ambientLight;
        if ( ambLight < 0.0 )
        {
            ambLight = 0.0;
        }
        else if ( ambLight > 1.0 )
        {
            ambLight = 1.0;
        }
		rdCamera_SetAmbientLight(&sithCamera_currentCamera->rdCam, ambLight);
#endif

		rdColormap_SetCurrent(sithCamera_currentCamera->sector->colormap);

        rdMatrix_Copy34(&viewMat, &sithCamera_currentCamera->viewMat);
        rdVector_Copy3(&trans, &playerThings[playerThingIdx].actorThing->actorParams.eyeOffset);

#ifdef QOL_IMPROVEMENTS
		// Shift gun down slightly at higher aspect ratios
		// TODO just make a cvar-alike for this
		//trans.z += 0.007 * (1.0 / sithCamera_currentCamera->rdCam.screenAspectRatio);

		// drop the gun a little with higher FOVs, similar to Quake
		// this helps prevent the missing parts of the model from showing
		if(sithCamera_currentCamera->rdCam.fov > 90)
			trans.z += 0.0001f * (sithCamera_currentCamera->rdCam.fov - 90);
#endif

#ifdef DYNAMIC_POV
		// Added: idle sway
		if (!jkPlayer_aimLock)
		{
			float swayTime = sithTime_curSeconds * jkPlayer_idleWaggleSpeed * (180.0 / M_PI);

			stdMath_SinCos(swayTime, &angleSin, &angleCos);
			jkSaber_swayOffset.x = (angleSin * jkPlayer_idleWaggleVec.x - jkSaber_swayOffset.x) * min(sithTime_deltaSeconds, 0.02f) * jkPlayer_idleWaggleSmooth + jkSaber_swayOffset.x;

			stdMath_SinCos(2.0f * swayTime + 180.0f, &angleSin, &angleCos);
			jkSaber_swayOffset.z = (angleSin * jkPlayer_idleWaggleVec.z - jkSaber_swayOffset.z) * min(sithTime_deltaSeconds, 0.02f) * jkPlayer_idleWaggleSmooth + jkSaber_swayOffset.z;
		
			// add the sway offset
			trans.x += jkSaber_swayOffset.x;
			trans.z += jkSaber_swayOffset.z;

			// Added: drop/raise the gun a little when jumping/falling
			trans.z += stdMath_Clamp(0.005f * (player->physicsParams.vel.z / player->physicsParams.maxVel), -0.007f, 0.007f);
		}

		// smooth out crouching and slopes so it's not so static
		if (player->physicsParams.physflags & SITH_PF_CROUCHING)
			trans.z -= /*player->physicsParams.povOffset + */ 0.0025f;
#endif
        rdVector_Neg3Acc(&trans);
        rdMatrix_PreTranslate34(&viewMat, &trans);

#ifdef DYNAMIC_POV
		// Added: autoaim pov model orient
		rdMatrix34 invOrient;
		rdMatrix_InvertOrtho34(&invOrient, &viewMat);

		rdVector3 aimVector = {0.0f, 64.0f, 0.0f}; // default, 64 units forward

		// use the look vector + eye offset to get a better accuracy on the cursor, it's not exactly centered
		rdMatrix34 invLook;
		rdMatrix_InvertOrtho34(&invLook, &player->lookOrientation); // inverted so we get the local vector
		rdMatrix_PreTranslate34(&invLook, &player->actorParams.eyeOffset); // add eye offset
		rdMatrix_TransformVector34(&aimVector, &player->lookOrientation.lvec, &invLook);

		if (!jkPlayer_aimLock)
		{
			int hasTarget = 0;

			// calculate a coarse auto-aim for some sense of where the weapon is pointing 
			// since projectiles still come from the fireoffset, we don't want it to wander too far or be precise
			rdMatrix34 autoAimMat;
			sithThing* pTarget = NULL;
			if((sithWeapon_bAutoAim & 1) != 0 && !sithNet_isMulti)
				pTarget = sithWeapon_ProjectileAutoAim(&autoAimMat, player, &sithCamera_currentCamera->viewMat, &player->position, jkPlayer_povAutoAimFov, jkPlayer_povAutoAimDist);

			if(!pTarget)
			{
				// no target, do a sector/thing ray cast to adjust the crosshair distance
				rdVector3 hitPos;
				rdVector_Copy3(&hitPos, &player->position);
				rdVector_MultAcc3(&hitPos, &sithCamera_currentCamera->viewMat.lvec, 64.0f);
				sithSector* sector = sithCollision_GetSectorLookAt(player->sector, &player->position, &hitPos, 0.0);
				if (sector)
				{
					rdVector_Sub3(&aimVector, &hitPos, &player->position);
					rdMatrix_LookAt(&autoAimMat, &player->position, &hitPos, 0.0);
					hasTarget = 1;
				}
			}
			else
			{
				rdVector_Sub3(&aimVector, &pTarget->position, &player->position);
				hasTarget = 1;
			}

			if(hasTarget)
			{
				// apply inverse of the original look orient to get a local transform
				rdMatrix_PostMultiply34(&autoAimMat, &invOrient);
				rdMatrix_TransformVector34Acc(&aimVector, &invOrient);
				rdVector_Zero3(&autoAimMat.scale);

				// if we're very close to a wall or blocker, lower the weapon
				static const float aimDist = 0.1f;
				float aimLen = rdVector_Len3(&aimVector);
				rdVector3 pushAngles = { 0.0f, 0.0f, 0.0f };
				if(aimLen <= aimDist)
				{
					float aimDiff = (aimDist - aimLen) / aimDist;
					rdVector_Scale3(&pushAngles, &jkPlayer_weaponWallAngles, aimDiff);

					// adjust the aim vector to match
					rdVector_Rotate3Acc(&aimVector, &jkPlayer_pushAngles);
				}
				rdVector_Lerp3(&jkPlayer_pushAngles, &jkPlayer_pushAngles, &pushAngles, 8.0f * min(sithTime_deltaSeconds, 0.02f));
				rdMatrix_PreRotate34(&viewMat, &jkPlayer_pushAngles);

				// extract the angles so we can do a lazy interpolation
				rdVector3 angles;
				rdMatrix_ExtractAngles34(&autoAimMat, &angles);
			
				jkSaber_aimAngles.x = (angles.x - jkSaber_aimAngles.x) * 8.0f * min(sithTime_deltaSeconds, 0.02f) + jkSaber_aimAngles.x;
				jkSaber_aimAngles.y = (angles.y - jkSaber_aimAngles.y) * 8.0f * min(sithTime_deltaSeconds, 0.02f) + jkSaber_aimAngles.y;
				// ignore roll, it gets weird
				//jkSaber_aimAngles.z = (angles.z - jkSaber_aimAngles.z) * 8.0f * min(sithTime_deltaSeconds, 0.02f) + jkSaber_aimAngles.z;
			
				rdMatrix_BuildRotate34(&autoAimMat, &jkSaber_aimAngles);
				rdMatrix_PreMultiply34(&viewMat, &autoAimMat);
			}
		}
		jkSaber_aimVector.x = (aimVector.x - jkSaber_aimVector.x) * 8.0f * min(sithTime_deltaSeconds, 0.02f) + jkSaber_aimVector.x;
		jkSaber_aimVector.y = (aimVector.y - jkSaber_aimVector.y) * 8.0f * min(sithTime_deltaSeconds, 0.02f) + jkSaber_aimVector.y;
		jkSaber_aimVector.z = (aimVector.z - jkSaber_aimVector.z) * 8.0f * min(sithTime_deltaSeconds, 0.02f) + jkSaber_aimVector.z;
#endif
        rdMatrix_PreMultiply34(&viewMat, &jkSaber_rotateMat);

#ifdef DYNAMIC_POV
		// project the aim vector to the screen
		rdMatrix34 aimMat;
		rdMatrix_Identity34(&aimMat);
		rdMatrix_PreTranslate34(&aimMat, &trans);
		rdMatrix_PreTranslate34(&aimMat, &jkPlayer_muzzleOffset);
		if(!jkPlayer_aimLock)
			rdMatrix_PreMultiply34(&aimMat, &rotateMatNoWaggle);
		rdVector_Copy3(&aimVector, &jkSaber_aimVector);
		rdMatrix_TransformPoint34Acc(&aimVector, &aimMat);
		sithCamera_currentCamera->rdCam.fnProject(&jkPlayer_crosshairPos, &aimVector);

		if (playerThings[playerThingIdx].povModel.frameTrue != rdroid_frameTrue)
		{
			rdPuppet_BuildJointMatrices(&playerThings[playerThingIdx].povModel, &viewMat);
		}

		// if we have a muzzle node, do muzzle stuff
		if (jkPlayer_muzzleFlashNode >= 0 && jkPlayer_muzzleFlashNode < playerThings[playerThingIdx].povModel.model3->numHierarchyNodes)
		{
			// draw the muzzle flash while the timer is valid
			if (sithTime_curMs < jkPlayer_drawMuzzleFlash && playerThings[playerThingIdx].povSprite.sprite3)
			{
				rdMatrix34* muzzleMat = &playerThings[playerThingIdx].povModel.hierarchyNodeMatrices[jkPlayer_muzzleFlashNode];
				rdSprite_Draw(&playerThings[playerThingIdx].povSprite, muzzleMat);

				// add a light for the flash
				static rdLight muzzleLight;
				rdLight_NewEntry(&muzzleLight);
				muzzleLight.intensity = playerThings[playerThingIdx].povSprite.sprite3->radius * 2.0f;
#ifdef RGB_THING_LIGHTS
				rdMaterial_GetFillColor(&muzzleLight.color, playerThings[playerThingIdx].povSprite.sprite3->face.material, player->sector->colormap, playerThings[playerThingIdx].povSprite.wallCel, -1);
				rdVector_Scale3Acc(&muzzleLight.color, 1.0f / muzzleLight.intensity); // compensate for the low intensity/range
#endif
				// offset the light so it's on the top of the sprite, not the very center
				// this is to simulate more of an "area light" of the flash wrapping around the POV model
				rdVector3 pos;
				rdVector_Copy3(&pos, &muzzleMat->scale);
				rdVector_MultAcc3(&pos, &viewMat.uvec, playerThings[playerThingIdx].povSprite.sprite3->height);
				rdCamera_AddLight(rdCamera_pCurCamera, &muzzleLight, &pos);
			}

			// update the muzzle offset so we can use it in cog for weapon offsets etc
			// the offset is in the cameras local frame
			rdMatrix34 muzzleMat;
			rdMatrix_Copy34(&muzzleMat, &playerThings[playerThingIdx].povModel.hierarchyNodeMatrices[jkPlayer_muzzleFlashNode]);
			rdMatrix_PostMultiply34(&muzzleMat, &invOrient);
			rdVector_Copy3(&jkPlayer_muzzleOffset, &muzzleMat.scale);
		}
		else
		{
			rdVector_Zero3(&jkPlayer_muzzleOffset);
		}
#endif

        // Moved: see below.
#ifndef SDL2_RENDER
        // Render saber if applicable
        if (playerThings[playerThingIdx].actorThing->jkFlags & JKFLAG_SABERON)
        {
            jkSaber_Draw(&viewMat);
        }
#endif
        
        rdThing_Draw(&playerThings[playerThingIdx].povModel, &viewMat);

        rdCache_Flush();

        // Added: we want the polyline to render in draw order so the spheres don't clip, 
        // but we want the POV model to be aware of the depths still.
#ifdef SDL2_RENDER
        if (playerThings[playerThingIdx].actorThing->jkFlags & JKFLAG_SABERON)
        {
            //rdSetZBufferMethod(RD_ZBUFFER_READ_NOWRITE);
			rdSetSortingMethod(2);
            jkSaber_Draw(&viewMat);
        }
        rdCache_Flush(); // Added: force polyline to be underneath model
        rdSetZBufferMethod(RD_ZBUFFER_READ_WRITE);
#endif
    }
}

#ifdef QOL_IMPROVEMENTS

// split jkPlayer_renderSaberWeaponMesh so we can render the saber blade at the end with blending and proper sorting of the polyline
void jkPlayer_renderWeaponMesh(sithThing* thing)
{
	jkPlayerInfo* playerInfo = thing->playerInfo;
	if (!playerInfo)
		return;

	if (!thing->animclass)
		return;

	int primary_mesh = thing->animclass->bodypart_to_joint[JOINTTYPE_PRIMARYWEAP];
	rdMatrix34* primaryMat = &thing->rdthing.hierarchyNodeMatrices[primary_mesh];
	if (thing->jkFlags & JKFLAG_PERSUASION)
	{
		if (sithPlayer_pLocalPlayer->iteminfo[SITHBIN_F_SEEING].state & ITEMSTATE_ACTIVATE)
		{
			rdGeoMode_t oldGeoMode = thing->rdthing.curGeoMode;
			thing->rdthing.curGeoMode = thing->rdthing.desiredGeoMode;
			rdVector_Copy3(&thing->lookOrientation.scale, &thing->position);
			rdThing_Draw(&thing->rdthing, &thing->lookOrientation);

			thing->lookOrientation.scale.x = 0.0;
			thing->lookOrientation.scale.y = 0.0;
			thing->lookOrientation.scale.z = 0.0;
			thing->rdthing.curGeoMode = oldGeoMode;

			if (playerInfo->rd_thing.model3)
				rdThing_Draw(&playerInfo->rd_thing, primaryMat);
		}
		else
		{
			jkPlayer_renderSaberTwinkle(thing);
		}
	}
	else if (thing->rdthing.curGeoMode > RD_GEOMODE_NOTRENDERED)
	{
		if (playerInfo->rd_thing.model3)
			rdThing_Draw(&playerInfo->rd_thing, primaryMat);
	}
}

void jkPlayer_renderSaberBlade(sithThing* thing)
{
	jkPlayerInfo* playerInfo = thing->playerInfo;
	if (!playerInfo)
	{
		// Added: hackfix for weird blades?
		if (thing->actorParams.typeflags & SITH_AF_BOSS)
		{
			jk_printf("OpenJKDF2: Boss w/o a blade? Fixing... %p\n", thing);

			jkPlayer_FUN_00404fe0(thing);

			sithThing* saberSparks = sithTemplate_GetEntryByName("+ssparks_saber");
			sithThing* bloodSparks = sithTemplate_GetEntryByName("+ssparks_blood");
			sithThing* wallSparks = sithTemplate_GetEntryByName("+ssparks_wall");
			jkSaber_InitializeSaberInfo(thing, "saberred1.mat", "saberred0.mat", 0.0032, 0.0018, 0.12, wallSparks, bloodSparks, saberSparks);
		}
		return;
	}

	if (!thing->animclass)
		return;

	int primary_mesh = thing->animclass->bodypart_to_joint[JOINTTYPE_PRIMARYWEAP];
	int secondary_mesh = thing->animclass->bodypart_to_joint[JOINTTYPE_SECONDARYWEAP];

	// Attempt to find a proper secondary weapon hand
	if (thing->jkFlags & JKFLAG_DUALSABERS && primary_mesh == secondary_mesh && thing->rdthing.model3)
	{
		for (int i = 0; i < thing->rdthing.model3->numHierarchyNodes; i++)
		{
			int l = _strlen(thing->rdthing.model3->hierarchyNodes[i].name);
			if (l < 5) continue;

			if (!__strcmpi(thing->rdthing.model3->hierarchyNodes[i].name + (l - 5), "lhand"))
			{
				secondary_mesh = i;
				break;
			}
		}

		if (primary_mesh != secondary_mesh)
		{
			thing->animclass->bodypart_to_joint[JOINTTYPE_SECONDARYWEAP] = secondary_mesh;
		}
	}

	rdMatrix34* primaryMat = &thing->rdthing.hierarchyNodeMatrices[primary_mesh];
	rdMatrix34* secondaryMat = &thing->rdthing.hierarchyNodeMatrices[secondary_mesh];

	if (thing->jkFlags & JKFLAG_PERSUASION)
	{
		if (sithPlayer_pLocalPlayer->iteminfo[SITHBIN_F_SEEING].state & ITEMSTATE_ACTIVATE)
		{
			if (thing->jkFlags & JKFLAG_SABERON)
			{
				jkSaber_PolylineRand(&playerInfo->polylineThing);
				rdThing_Draw(&playerInfo->polylineThing, primaryMat);
			#ifdef LIGHTSABER_TRAILS
				jkSaber_DrawTrail(&playerInfo->polylineThing, &playerInfo->saberTrail[0], primaryMat);
			#endif
				if (thing->jkFlags & JKFLAG_DUALSABERS)
				{
					rdThing_Draw(&playerInfo->polylineThing, secondaryMat);
				#ifdef LIGHTSABER_TRAILS
					jkSaber_DrawTrail(&playerInfo->polylineThing, &playerInfo->saberTrail[1], secondaryMat);
				#endif
				}
			}
		}
	}
	else if (thing->rdthing.curGeoMode > RD_GEOMODE_NOTRENDERED)
	{
		if (thing->jkFlags & JKFLAG_SABERON)
		{
			jkSaber_PolylineRand(&playerInfo->polylineThing);
			rdThing_Draw(&playerInfo->polylineThing, primaryMat);
		#ifdef LIGHTSABER_TRAILS
			jkSaber_DrawTrail(&playerInfo->polylineThing, &playerInfo->saberTrail[0], primaryMat);
		#endif
			if (thing->jkFlags & JKFLAG_DUALSABERS)
			{
				rdThing_Draw(&playerInfo->polylineThing, secondaryMat);
			#ifdef LIGHTSABER_TRAILS
				jkSaber_DrawTrail(&playerInfo->polylineThing, &playerInfo->saberTrail[1], secondaryMat);
			#endif
			}
		}
	}
}

#else

void jkPlayer_renderSaberWeaponMesh(sithThing *thing)
{
    jkPlayerInfo* playerInfo = thing->playerInfo;
    if (!playerInfo) {
        // Added: hackfix for weird blades?
        if (thing->actorParams.typeflags & SITH_AF_BOSS ) {
            jk_printf("OpenJKDF2: Boss w/o a blade? Fixing... %p\n", thing);

            jkPlayer_FUN_00404fe0(thing);

            sithThing* saberSparks = sithTemplate_GetEntryByName("+ssparks_saber");
            sithThing* bloodSparks = sithTemplate_GetEntryByName("+ssparks_blood");
            sithThing* wallSparks = sithTemplate_GetEntryByName("+ssparks_wall");
            jkSaber_InitializeSaberInfo(thing, "saberred1.mat", "saberred0.mat", 0.0032, 0.0018, 0.12, wallSparks, bloodSparks, saberSparks);
        }
        return;
    }

    if (!thing->animclass)
        return;

    int primary_mesh = thing->animclass->bodypart_to_joint[JOINTTYPE_PRIMARYWEAP];
    int secondary_mesh = thing->animclass->bodypart_to_joint[JOINTTYPE_SECONDARYWEAP];

    // Attempt to find a proper secondary weapon hand
    if (thing->jkFlags & JKFLAG_DUALSABERS && primary_mesh == secondary_mesh && thing->rdthing.model3) {
        for (int i = 0; i < thing->rdthing.model3->numHierarchyNodes; i++)
        {
            int l = _strlen(thing->rdthing.model3->hierarchyNodes[i].name);
            if (l < 5) continue;

            if (!__strcmpi(thing->rdthing.model3->hierarchyNodes[i].name + (l - 5), "lhand")) {
                secondary_mesh = i;
                break;
            }
        }

        if (primary_mesh != secondary_mesh) {
            thing->animclass->bodypart_to_joint[JOINTTYPE_SECONDARYWEAP] = secondary_mesh;
        }
    }

    rdMatrix34* primaryMat = &thing->rdthing.hierarchyNodeMatrices[primary_mesh];
    rdMatrix34* secondaryMat = &thing->rdthing.hierarchyNodeMatrices[secondary_mesh];

    if (thing->jkFlags & JKFLAG_PERSUASION)
    {
        if ( sithPlayer_pLocalPlayer->iteminfo[SITHBIN_F_SEEING].state & ITEMSTATE_ACTIVATE )
        {
            rdGeoMode_t oldGeoMode = thing->rdthing.curGeoMode;
            thing->rdthing.curGeoMode = thing->rdthing.desiredGeoMode;
            rdVector_Copy3(&thing->lookOrientation.scale, &thing->position);
            rdThing_Draw(&thing->rdthing, &thing->lookOrientation);

            thing->lookOrientation.scale.x = 0.0;
            thing->lookOrientation.scale.y = 0.0;
            thing->lookOrientation.scale.z = 0.0;
            thing->rdthing.curGeoMode = oldGeoMode;

            if (playerInfo->rd_thing.model3)
                rdThing_Draw(&playerInfo->rd_thing, primaryMat);

            if (thing->jkFlags & JKFLAG_SABERON)
            {
                jkSaber_PolylineRand(&playerInfo->polylineThing);
                rdThing_Draw(&playerInfo->polylineThing, primaryMat);
                if ( thing->jkFlags & JKFLAG_DUALSABERS)
                    rdThing_Draw(&playerInfo->polylineThing, secondaryMat);
            }
        }
        else
        {
            jkPlayer_renderSaberTwinkle(thing);
        }
    }
    else if ( thing->rdthing.curGeoMode > RD_GEOMODE_NOTRENDERED)
    {
        if (playerInfo->rd_thing.model3)
            rdThing_Draw(&playerInfo->rd_thing, primaryMat);
        
        if (thing->jkFlags & JKFLAG_SABERON)
        {
            jkSaber_PolylineRand(&playerInfo->polylineThing);
            rdThing_Draw(&playerInfo->polylineThing, primaryMat);
            if (thing->jkFlags & JKFLAG_DUALSABERS)
                rdThing_Draw(&playerInfo->polylineThing, secondaryMat);
        }
    }
}

#endif

void jkPlayer_renderSaberTwinkle(sithThing *player)
{
    rdVector3 vTmp;
    rdMatrix34 matTmp;

    jkPlayerInfo* playerInfo = player->playerInfo;
    if ( sithTime_curMs > playerInfo->nextTwinkleRandMs )
    {
        playerInfo->bRenderTwinkleParticle = 1;
        
        //TODO: macro bug?
        if ((_frand() * (double)playerInfo->twinkleSpawnRate) <= playerInfo->maxTwinkles )
            playerInfo->numTwinkles = playerInfo->maxTwinkles;
        else
            playerInfo->numTwinkles = (int)(_frand() * (double)playerInfo->twinkleSpawnRate);

        playerInfo->nextTwinkleRandMs += 2000;
    }
    if ( playerInfo->bRenderTwinkleParticle )
    {
        if ( sithTime_curMs > playerInfo->nextTwinkleSpawnMs )
        {
            rdThing* rdthing = &playerInfo->actorThing->rdthing;
            playerInfo->nextTwinkleSpawnMs += 40;
            rdModel3* model = rdthing->model3;
            
            // Added: Changed both of these from `_frand() * max` to `_rand() % max`
            // to prevent an off-by-one heap buffer overflow.
            uint32_t meshIdx = model->hierarchyNodes[_rand() % model->numHierarchyNodes].meshIdx;

            if ( meshIdx != -1 && model->geosets[0].meshes[meshIdx].numVertices)
            {
                uint32_t vtxIdx = (_rand() % model->geosets[0].meshes[meshIdx].numVertices);

                rdModel3_GetMeshMatrix(rdthing, &playerInfo->actorThing->lookOrientation, meshIdx, &matTmp);
                rdMatrix_TransformPoint34(&vTmp, &model->geosets[0].meshes[meshIdx].vertices[vtxIdx], &matTmp);

                sithThing_Create(sithTemplate_GetEntryByName("+twinkle"), &vTmp, &matTmp, player->sector, 0);

                playerInfo->numTwinkles--;
                if ( !playerInfo->numTwinkles )
                    playerInfo->bRenderTwinkleParticle = 0;
            }
        }
    }
}

#ifdef DYNAMIC_POV
void jkPlayer_SetWaggle(sithThing *player, rdVector3 *waggleVec, float waggleMag, float velScale)
#else
void jkPlayer_SetWaggle(sithThing* player, rdVector3* waggleVec, float waggleMag)
#endif
{
    if ( player == playerThings[playerThingIdx].actorThing )
    {
        rdVector_Copy3(&jkPlayer_waggleVec, waggleVec);
        jkPlayer_waggleMag = waggleMag;
#ifdef DYNAMIC_POV
		jkPlayer_waggleVel = velScale;
#endif
    }
}

#ifdef DYNAMIC_POV
void jkPlayer_SetIdleWaggle(sithThing* player, rdVector3* waggleVec, float waggleSpeed, float waggleSmooth)
{
	if (player == playerThings[playerThingIdx].actorThing)
	{
		rdVector_Copy3(&jkPlayer_idleWaggleVec, waggleVec);
		jkPlayer_idleWaggleSpeed = waggleSpeed;
		jkPlayer_idleWaggleSmooth = waggleSmooth;
	}
}

void jkPlayer_GetMuzzleOffset(sithThing* player, rdVector3* muzzleOffset)
{
	if (player == playerThings[playerThingIdx].actorThing)
	{
		if(rdVector_Len3(&jkPlayer_muzzleOffset) > 0.0f)
			rdVector_Copy3(muzzleOffset, &jkPlayer_muzzleOffset);
		else
			rdVector_Zero3(&jkPlayer_muzzleOffset);
	}
	else
		rdVector_Zero3(&jkPlayer_muzzleOffset);
}

void jkPlayer_SetPovAutoAim(sithThing* player, float fov, float dist)
{
	if (player == playerThings[playerThingIdx].actorThing)
	{
		jkPlayer_povAutoAimFov = fov;
		jkPlayer_povAutoAimDist = dist;
	}
}
#endif

int jkPlayer_VerifyWcharName(wchar_t *name)
{
    wchar_t *v1; // edi
    wchar_t v2; // ax
    int v3; // ebx
    int v4; // esi
    int v5; // ecx
    int v7; // ecx
    int v9; // ecx

    v1 = name;
    v2 = *name;
    if ( *name )
    {
        v3 = 1;
        while ( 1 )
        {
            v4 = 0;
            v5 = v2 >= 0x20u && v2 <= 0x7Eu;
            if ( !v5 && v2 != 161 && (v2 < 0xBFu || v2 > 0xC4u) )
            {
                v7 = v2 >= 0xC7u && v2 <= 0xC8u;
                if ( !v7 && v2 != 202 && v2 != 205 && (v2 < 0xD1u || v2 > 0xD2u) )
                {
                    v9 = v2 >= 0xD4u && v2 <= 0xD6u;
                    if ( !v9
                      && v2 != 0xDA
                      && v2 != 220
                      && (v2 < 0xDFu || v2 > 0xE4u)
                      && (v2 < 0xE7u || v2 > 0xEFu)
                      && (v2 < 0xF1u || v2 > 0xF6u)
                      && (v2 < 0xF9u || v2 > 0xFCu) )
                    {
                        break;
                    }
                }
            }
            if ( v2 == '\\' || v2 == '/' || v2 == ':' || v2 == '*' || v2 == '?' || v2 == '"' || v2 == '<' || v2 == '.' || v2 == '>' || v2 == '|' )
                break;
            if ( _iswspace(v2) )
                v4 = 1;
            else
                v3 = 0;
            v2 = v1[1];
            ++v1;
            if ( !v2 )
                return v3 != 1 && v4 != 1;
        }
    }
    return 0;
}

int jkPlayer_VerifyCharName(char *name)
{
    wchar_t tmp[64];

    stdString_CharToWchar(tmp, name, 63);
    tmp[63] = 0;
    return jkPlayer_VerifyWcharName(tmp);
}

void jkPlayer_SetMpcInfo(wchar_t *name, char *model, char *soundclass, char *sidemat, char *tipmat)
{
    jkPlayer_mpcInfoSet = 1;
    
    // TODO macro these
    _strncpy(jkPlayer_model, model, 0x1Fu);
    jkPlayer_model[31] = 0;
    _strncpy(jkPlayer_soundClass, soundclass, 0x1Fu);
    jkPlayer_soundClass[31] = 0;
    _strncpy(jkPlayer_sideMat, sidemat, 0x1Fu);
    jkPlayer_sideMat[31] = 0;
    _strncpy(jkPlayer_tipMat, tipmat, 0x1Fu);
    jkPlayer_tipMat[31] = 0;
    _wcsncpy(jkPlayer_name, name, 0x1Fu);
    jkPlayer_name[31] = 0;
}

void jkPlayer_SetPlayerName(wchar_t *name)
{
    _wcsncpy(jkPlayer_name, name, 0x1Fu);
    jkPlayer_name[31] = 0;
}

int jkPlayer_GetMpcInfo(wchar_t *name, char *model, char *soundclass, char *sidemat, char *tipmat)
{
    _wcsncpy(name, jkPlayer_name, 0x1Fu);
    name[31] = 0;

    if (!jkPlayer_mpcInfoSet)
        return 0;

    _strncpy(model, jkPlayer_model, 0x1Fu);
    model[31] = 0;
    _strncpy(soundclass, jkPlayer_soundClass, 0x1Fu);
    soundclass[31] = 0;
    _strncpy(sidemat, jkPlayer_sideMat, 0x1Fu);
    sidemat[31] = 0;
    _strncpy(tipmat, jkPlayer_tipMat, 0x1Fu);
    tipmat[31] = 0;
    return 1;
}

void jkPlayer_SetChoice(signed int amt)
{
    sithPlayer_SetBinAmt(SITHBIN_CHOICE, (float)amt);
}

int jkPlayer_GetChoice()
{
    return (int)sithPlayer_GetBinAmt(SITHBIN_CHOICE);
}

//MOTS altered
float jkPlayer_CalcAlignment(int isMp)
{
    if (jkPlayer_GetChoice() == 1)
        return 100.0;
    if (jkPlayer_GetChoice() == 2)
        return -100.0;

    float alignment = jkPlayer_CalcStarsAlign();

    if (!isMp)
    {
        float pedsKilled = sithPlayer_GetBinAmt(SITHBIN_PEDS_KILLED);
        float totalPeds = sithPlayer_GetBinAmt(SITHBIN_PEDS_TOTAL);

        if (totalPeds <= 0.0) // Prevent div 0
            alignment -= -20.0;
        else
            alignment = (alignment - (pedsKilled / totalPeds) * 100.0) - -20.0;
            //alignment -= (pedsKilled / totalPeds * 100.0) - -20.0;
            // These are different between MinGW and Clang??
    }

    // TODO macro?
    if ( alignment > 100.0 )
        alignment = 100.0;
    if ( alignment < -100.0 )
        alignment = -100.0;

    sithPlayer_SetBinAmt(SITHBIN_ALIGNMENT, alignment);

    return alignment;
}

void jkPlayer_MpcInitBins(sithPlayerInfo* unk)
{
    float alignment; // [esp+8h] [ebp-E8h]
    jkPlayerMpcInfo info; // [esp+Ch] [ebp-E4h] BYREF

    jkPlayer_MPCParse(&info, unk, jkPlayer_playerShortName, jkPlayer_name, 1);
    jkPlayer_InitForceBins();
    if ( (unsigned int)(__int64)sithPlayer_GetBinAmt(SITHBIN_CHOICE) != 1 && (unsigned int)(__int64)sithPlayer_GetBinAmt(SITHBIN_CHOICE) != 2 )
    {
        alignment = jkPlayer_CalcStarsAlign();
        if ( alignment > 100.0 )
            alignment = 100.0;
        if ( alignment < -100.0 )
            alignment = -100.0;
        sithPlayer_SetBinAmt(SITHBIN_ALIGNMENT, alignment);
    }
}

// MOTS altered TODO
int jkPlayer_MPCParse(jkPlayerMpcInfo *info, sithPlayerInfo* unk, wchar_t *fname, wchar_t *name, int hasBins)
{
    int v6; // edi
    float a2; // [esp+Ch] [ebp-CCh] BYREF
    int v8; // [esp+10h] [ebp-C8h] BYREF
    char v9; // [esp+14h] [ebp-C4h] BYREF
    char a1a[32]; // [esp+18h] [ebp-C0h] BYREF
    char v11[32]; // [esp+38h] [ebp-A0h] BYREF
    char jkl_fname[128]; // [esp+58h] [ebp-80h] BYREF

    stdString_WcharToChar(a1a, fname, 31);
    a1a[31] = 0;
    stdString_WcharToChar(v11, name, 31);
    v11[31] = 0;
    _wcsncpy(jkPlayer_name, name, 0x1Fu);
    jkPlayer_name[31] = 0;
    _wcsncpy(info->name, name, 0x1Fu);
    info->name[31] = 0;
    _sprintf(jkl_fname, "player\\%s\\%s.mpc", a1a, v11);

    if (!stdConffile_OpenRead(jkl_fname))
        return 0;

    if ( stdConffile_ReadLine()
      && _sscanf(stdConffile_aLine, "version %d", &v8) == 1
      && v8 == 1
      && stdConffile_ReadLine()
      && _sscanf(stdConffile_aLine, "model: %s", jkPlayer_model) == 1
      && stdConffile_ReadLine()
      && _sscanf(stdConffile_aLine, "soundclass: %s", jkPlayer_soundClass) == 1
      && stdConffile_ReadLine()
      && _sscanf(stdConffile_aLine, "sidemat: %s", jkPlayer_sideMat) == 1
      && stdConffile_ReadLine()
      && _sscanf(stdConffile_aLine, "tipmat: %s", jkPlayer_tipMat) == 1 )
    {
        if (Main_bMotsCompat) {
            if (!stdConffile_ReadLine() || _sscanf(stdConffile_aLine, "personality: %d", &jkPlayer_personality) != 1) {
                stdConffile_Close();
                return 0;
            }
        }
        else {
            jkPlayer_personality = 1; // HACK: JK only has Jedi classes.
        }

        _strncpy(info->model, jkPlayer_model, 0x1Fu);
        info->model[31] = 0;
        _strncpy(info->soundClass, jkPlayer_soundClass, 0x1Fu);
        info->soundClass[31] = 0;
        _strncpy(info->sideMat, jkPlayer_sideMat, 0x1Fu);
        info->sideMat[31] = 0;
        _strncpy(info->tipMat, jkPlayer_tipMat, 0x1Fu);
        info->tipMat[31] = 0;
        info->personality = jkPlayer_personality; // MOTS added
        if ( hasBins )
        {
            jkPlayer_MPCBinRead();
        }
        info->jediRank = jkPlayer_GetJediRank();
        stdConffile_Close();

        
        jkPlayer_SetAmmoMaximums(jkPlayer_personality); // MOTS added
        jkPlayer_mpcInfoSet = 1;
        return 1;
    }
    else
    {
        stdConffile_Close();
        return 0;
    }

    return 0;
}

int jkPlayer_MPCWrite(sithPlayerInfo* unk, wchar_t *mpcName, wchar_t *playerName)
{
    int v4; // esi
    char mpcNameChar[32]; // [esp+10h] [ebp-C0h] BYREF
    char playerNameChar[32]; // [esp+30h] [ebp-A0h] BYREF
    char fpath[128]; // [esp+50h] [ebp-80h] BYREF

    stdString_WcharToChar(playerNameChar, playerName, 31);
    playerNameChar[31] = 0;
    stdString_WcharToChar(mpcNameChar, mpcName, 31);
    mpcNameChar[31] = 0;
    stdString_snprintf(fpath, 128, "player\\%s\\%s.mpc", mpcNameChar, playerNameChar);

    if (!stdConffile_OpenWrite(fpath))
        return 0;

    stdConffile_Printf("version %d\n", 1);
    if ( stdConffile_Printf("model: %s\n", jkPlayer_model)
      && stdConffile_Printf("soundclass: %s\n", jkPlayer_soundClass)
      && stdConffile_Printf("sidemat: %s\n", jkPlayer_sideMat)
      && stdConffile_Printf("tipmat: %s\n", jkPlayer_tipMat))
    {
        if (Main_bMotsCompat) {
            stdConffile_Printf("personality: %d\n", jkPlayer_personality);
        }

        v4 = jkPlayer_MPCBinWrite();
        stdConffile_CloseWrite();
        return v4;
    }
    stdConffile_CloseWrite();
    return 0;
}

int jkPlayer_MPCBinWrite()
{
    int v0; // esi
    double v1; // st7
    double v2; // st7

    if (!stdConffile_Printf("\nforcepowers:\n") )
        return 0;

    v0 = SITHBIN_FP_START;
    while ( 1 )
    {
        if ( !stdConffile_Printf("bin: %d value: %f\n", v0, sithPlayer_GetBinAmt(v0)) )
            break;

        if ( ++v0 > SITHBIN_FP_END )
        {
            return stdConffile_Printf("spendable stars: %f\n", sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS));
        }
    }

    return 0;
}

// MOTS added: weird xor crypt
int jkPlayer_MPCBinRead()
{
    float a2;
    int v3;

    stdConffile_ReadLine();
    for (int i = SITHBIN_FP_START; i <= SITHBIN_FP_END; ++i )
    {
        if ( !stdConffile_ReadLine() || _sscanf(stdConffile_aLine, "bin: %d value: %f\n", &v3, &a2) != 2 )
            return 0;

        sithPlayer_SetBinAmt(i, a2);
        sithPlayer_SetBinCarries(i, 1);
    }

    if ( !stdConffile_ReadLine() || _sscanf(stdConffile_aLine, "spendable stars: %f\n", &a2) != 1 )
        return 0;

    sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS, a2);
    return 1;
}

void jkPlayer_InitForceBins()
{
    for (int i = SITHBIN_FP_START; i <= SITHBIN_FP_END; ++i )
    {
        if ( i != SITHBIN_JEDI_RANK )
        {
            if ( sithPlayer_GetBinAmt(i) > 0.0 && jkPlayer_playerInfos[playerThingIdx].iteminfo[i].state & ITEMSTATE_CARRIES)
            {
                jkPlayer_playerInfos[playerThingIdx].iteminfo[i].state |= ITEMSTATE_AVAILABLE;
            }
            else
            {
                jkPlayer_playerInfos[playerThingIdx].iteminfo[i].state &= ~ITEMSTATE_AVAILABLE;
            }
        }
    }
}

int jkPlayer_GetAlignment()
{
    float v4;

    int bHasDarkPowers = 0;
    for (int i = SITHBIN_F_THROW; i <= SITHBIN_F_DESTRUCTION; ++i )
    {
        if ( sithPlayer_GetBinAmt(i) > 0.0 )
            bHasDarkPowers = 1;
    }

    int bHasLightPowers = 0;
    for (int j = SITHBIN_F_HEALING; j <= SITHBIN_F_ABSORB; ++j )
    {
        if ( sithPlayer_GetBinAmt(j) > 0.0 )
            bHasLightPowers = 1;
    }

    if (!bHasDarkPowers && !bHasLightPowers)
        return 0;

    if ( !bHasLightPowers )
    {
        v4 = jkPlayer_CalcAlignment(0); // not mp
        if ( v4 < 0.0 )
            return 2;

        if ( !bHasLightPowers )
            return 0;
    }
    if ( !bHasDarkPowers )
    {
        if ( (unsigned int)(__int64)sithPlayer_GetBinAmt(SITHBIN_CHOICE) == 1 )
        {
            v4 = 100.0;
        }
        else if ( (unsigned int)(__int64)sithPlayer_GetBinAmt(SITHBIN_CHOICE) == 2 )
        {
            v4 = -100.0;
        }
        else
        {
            v4 = jkPlayer_CalcAlignment(0); // not mp
        }
        if ( v4 > 0.0 )
            return 1;
    }
    return 0;
}

void jkPlayer_SetAccessiblePowers(int rank)
{
    //MOTS TODO
    if (Main_bMotsCompat) {
#ifdef DEBUG_QOL_CHEATS
        for (int i = SITHBIN_FP_START; i <= SITHBIN_FP_END; ++i )
        {
            if ( i != SITHBIN_JEDI_RANK )
                jkPlayer_playerInfos[playerThingIdx].iteminfo[i].state |= ITEMSTATE_CARRIES;
        }
#endif
        return;
    }

    for (int i = SITHBIN_FP_START; i <= SITHBIN_FP_END; ++i )
    {
        if ( i != SITHBIN_JEDI_RANK )
            jkPlayer_playerInfos[playerThingIdx].iteminfo[i].state &= ~ITEMSTATE_CARRIES;
    }

    if ( rank )
    {
        for (int j = SITHBIN_FP_START; j <= SITHBIN_F_PULL; ++j )
        {
            if ( j != SITHBIN_JEDI_RANK )
                jkPlayer_playerInfos[playerThingIdx].iteminfo[j].state |= ITEMSTATE_CARRIES;
        }

        if ( rank > 3 )
        {
            jkPlayer_playerInfos[playerThingIdx].iteminfo[SITHBIN_F_HEALING].state |= ITEMSTATE_CARRIES;
            jkPlayer_playerInfos[playerThingIdx].iteminfo[SITHBIN_F_THROW].state |= ITEMSTATE_CARRIES;
            
            if ( rank > 4 )
            {
                jkPlayer_playerInfos[playerThingIdx].iteminfo[SITHBIN_F_PERSUASION].state |= ITEMSTATE_CARRIES;
                jkPlayer_playerInfos[playerThingIdx].iteminfo[SITHBIN_F_GRIP].state |= ITEMSTATE_CARRIES;
                
                if ( rank > 5 )
                {
                    jkPlayer_playerInfos[playerThingIdx].iteminfo[SITHBIN_F_BLINDING].state |= ITEMSTATE_CARRIES;
                    jkPlayer_playerInfos[playerThingIdx].iteminfo[SITHBIN_F_LIGHTNING].state |= ITEMSTATE_CARRIES;
                    if ( rank > 6 )
                    {
                        jkPlayer_playerInfos[playerThingIdx].iteminfo[SITHBIN_F_ABSORB].state |= ITEMSTATE_CARRIES;
                        jkPlayer_playerInfos[playerThingIdx].iteminfo[SITHBIN_F_DESTRUCTION].state |= ITEMSTATE_CARRIES;
                    }
                }
            }
        }
    }
}

void jkPlayer_ResetPowers()
{
    for (int i = SITHBIN_FP_START; i <= SITHBIN_FP_END; ++i )
    {
        if ( i != SITHBIN_JEDI_RANK )
            sithPlayer_SetBinAmt(i, 0.0);
    }
}

int jkPlayer_WriteConfSwap(jkPlayerInfo* unk, int a2, char *a3)
{
    int v3; // ebx
    int v4; // edx
    char *v5; // ebp
    int v7; // eax
    int v8; // ecx
    int v9; // ebp
    char *v10; // edi
    int *v11; // esi
    int v12; // [esp+10h] [ebp-A4h]
    char v13[32]; // [esp+14h] [ebp-A0h] BYREF
    char v14[128]; // [esp+34h] [ebp-80h] BYREF

    v3 = sithControl_IsOpen();
    v12 = v3;
    if ( v3 )
        sithControl_Close();
    jkPlayer_ReadConf(jkPlayer_playerShortName);
    v4 = 0;
    if ( jkPlayer_setNumCutscenes <= 0 )
    {
LABEL_8:
        if ( jkPlayer_setNumCutscenes >= 32 )
            return 0;
        _strncpy(&jkPlayer_cutscenePath[32 * jkPlayer_setNumCutscenes], a3, 0x1Fu);
        v7 = jkPlayer_setNumCutscenes;
        v8 = 32 * jkPlayer_setNumCutscenes;
        jkPlayer_aCutsceneVal[jkPlayer_setNumCutscenes] = a2;
        jkPlayer_setNumCutscenes = v7 + 1;
        jkPlayer_cutscenePath[v8 + 31] = 0;
        stdString_WcharToChar(v13, jkPlayer_playerShortName, 31);
        v13[31] = 0;
        stdString_snprintf(v14, 128, "player\\%s\\%s.plr", v13, v13);
        if ( stdConffile_OpenWrite(v14) )
        {
            stdConffile_Printf("version %d\n", 1);
            stdConffile_Printf("diff %d\n", jkPlayer_setDiff);
            jkPlayer_WriteOptionsConf();
            sithWeapon_WriteConf();
            sithControl_WriteConf();
            if ( stdConffile_Printf("numCutscenes %d\n", jkPlayer_setNumCutscenes) )
            {
                v9 = 0;
                if ( jkPlayer_setNumCutscenes > 0 )
                {
                    v10 = jkPlayer_cutscenePath;
                    v11 = jkPlayer_aCutsceneVal;
                    do
                    {
                        if ( !stdConffile_Printf("%s %d\n", v10, *v11) )
                            break;
                        ++v9;
                        ++v11;
                        v10 += 32;
                    }
                    while ( v9 < jkPlayer_setNumCutscenes );
                }
            }
            stdConffile_CloseWrite();
        }
        if ( v3 )
            sithControl_Open();
    }
    else
    {
        v5 = jkPlayer_cutscenePath;
        while ( _strcmp(v5, a3) )
        {
            ++v4;
            v5 += 32;
            if ( v4 >= jkPlayer_setNumCutscenes )
            {
                v3 = v12;
                goto LABEL_8;
            }
        }
    }
    return 1;
}

int jkPlayer_WriteCutsceneConf()
{
    int v0; // esi
    char *v1; // ebx
    int *i; // edi

    if ( !stdConffile_Printf("numCutscenes %d\n", jkPlayer_setNumCutscenes) )
        return 0;
    v0 = 0;
    if ( jkPlayer_setNumCutscenes > 0 )
    {
        v1 = jkPlayer_cutscenePath;
        for ( i = jkPlayer_aCutsceneVal; stdConffile_Printf("%s %d\n", v1, *i); ++i )
        {
            ++v0;
            v1 += 32;
            if ( v0 >= jkPlayer_setNumCutscenes )
                return 1;
        }
        return 0;
    }
    return 1;
}

int jkPlayer_ReadCutsceneConf()
{
    int v0; // esi
    int *v1; // ebx
    char *i; // edi

    if ( stdConffile_ReadArgs()
      && stdConffile_entry.numArgs
      && !_strcmp(stdConffile_entry.args[0].key, "numcutscenes")
      && _sscanf(stdConffile_entry.args[1].value, "%d", &jkPlayer_setNumCutscenes) == 1 )
    {
        v0 = 0;
        if ( jkPlayer_setNumCutscenes <= 0 )
            return 1;
        v1 = jkPlayer_aCutsceneVal;
        for ( i = jkPlayer_cutscenePath;
              stdConffile_ReadArgs()
           && stdConffile_entry.numArgs >= 2u
           && _sscanf(stdConffile_entry.args[0].key, "%s", i) == 1
           && _sscanf(stdConffile_entry.args[1].value, "%d", v1) == 1;
              i += 32 )
        {
            ++v0;
            ++v1;
            if ( v0 >= jkPlayer_setNumCutscenes )
                return 1;
        }
    }
    return 0;
}

void jkPlayer_FixStars()
{
    int v0; // ebx
    int v1; // esi
    int i; // edi
    int v3; // esi
    __int64 v4; // rax
    __int64 v5; // rax
    __int64 v6; // rax
    __int64 v7; // rax
    __int64 v8; // rax
    __int64 v9; // rax
    __int64 v10; // rax
    __int64 v11; // rax
    __int64 v12; // rax
    __int64 v13; // rax
    __int64 v14; // rax
    __int64 v15; // rax
    __int64 v16; // rax
    float a2; // [esp+0h] [ebp-14h]
    float a2a; // [esp+0h] [ebp-14h]
    float a2b; // [esp+0h] [ebp-14h]
    float a2c; // [esp+0h] [ebp-14h]
    float a2d; // [esp+0h] [ebp-14h]
    float a2e; // [esp+0h] [ebp-14h]
    float a2f; // [esp+0h] [ebp-14h]
    float a2g; // [esp+0h] [ebp-14h]
    float a2h; // [esp+0h] [ebp-14h]
    float a2i; // [esp+0h] [ebp-14h]
    float a2j; // [esp+0h] [ebp-14h]
    float a2k; // [esp+0h] [ebp-14h]
    float a2l; // [esp+0h] [ebp-14h]
    float a2m; // [esp+0h] [ebp-14h]

    // MOTS TODO
    if (Main_bMotsCompat) return;

    v0 = 3 * jkPlayer_GetJediRank();
    v1 = (__int64)sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS);
    for ( i = SITHBIN_FP_START; i <= SITHBIN_FP_END; ++i )
    {
        if ( i != SITHBIN_JEDI_RANK && i != SITHBIN_F_PROTECTION && i != SITHBIN_F_DEADLYSIGHT )
            v1 += (__int64)sithPlayer_GetBinAmt(i);
    }
    if ( v0 > v1 )
    {
        a2 = (float)(v0 - v1);
        sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS, a2);
        return;
    }
    if ( v0 < v1 )
    {
        v3 = v1 - v0;
        if ( v3 > 0 )
        {
            while ( 1 )
            {
                v4 = (__int64)sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS);
                if ( (int)v4 > 0 )
                    break;
                v5 = (__int64)sithPlayer_GetBinAmt(SITHBIN_F_DESTRUCTION);
                if ( (int)v5 > 0 )
                {
                    a2b = (float)(v5 - 1);
                    sithPlayer_SetBinAmt(SITHBIN_F_DESTRUCTION, a2b);
                    goto LABEL_37;
                }
                v6 = (__int64)sithPlayer_GetBinAmt(SITHBIN_F_ABSORB);
                if ( (int)v6 > 0 )
                {
                    a2c = (float)(v6 - 1);
                    sithPlayer_SetBinAmt(SITHBIN_F_ABSORB, a2c);
                    goto LABEL_37;
                }
                v7 = (__int64)sithPlayer_GetBinAmt(SITHBIN_F_LIGHTNING);
                if ( (int)v7 > 0 )
                {
                    a2d = (float)(v7 - 1);
                    sithPlayer_SetBinAmt(SITHBIN_F_LIGHTNING, a2d);
                    goto LABEL_37;
                }
                v8 = (__int64)sithPlayer_GetBinAmt(SITHBIN_F_BLINDING);
                if ( (int)v8 > 0 )
                {
                    a2e = (float)(v8 - 1);
                    sithPlayer_SetBinAmt(SITHBIN_F_BLINDING, a2e);
                    goto LABEL_37;
                }
                v9 = (__int64)sithPlayer_GetBinAmt(SITHBIN_F_GRIP);
                if ( (int)v9 > 0 )
                {
                    a2f = (float)(v9 - 1);
                    sithPlayer_SetBinAmt(SITHBIN_F_GRIP, a2f);
                    goto LABEL_37;
                }
                v10 = (__int64)sithPlayer_GetBinAmt(SITHBIN_F_PERSUASION);
                if ( (int)v10 > 0 )
                {
                    a2g = (float)(v10 - 1);
                    sithPlayer_SetBinAmt(SITHBIN_F_PERSUASION, a2g);
                    goto LABEL_37;
                }
                v11 = (__int64)sithPlayer_GetBinAmt(SITHBIN_F_THROW);
                if ( (int)v11 > 0 )
                {
                    a2h = (float)(v11 - 1);
                    sithPlayer_SetBinAmt(SITHBIN_F_THROW, a2h);
                    goto LABEL_37;
                }
                v12 = (__int64)sithPlayer_GetBinAmt(SITHBIN_F_HEALING);
                if ( (int)v12 > 0 )
                {
                    a2i = (float)(v12 - 1);
                    sithPlayer_SetBinAmt(SITHBIN_F_HEALING, a2i);
                    goto LABEL_37;
                }
                v13 = (__int64)sithPlayer_GetBinAmt(SITHBIN_F_PULL);
                if ( (int)v13 > 0 )
                {
                    a2j = (float)(v13 - 1);
                    sithPlayer_SetBinAmt(SITHBIN_F_PULL, a2j);
                    goto LABEL_37;
                }
                v14 = (__int64)sithPlayer_GetBinAmt(SITHBIN_F_SEEING);
                if ( (int)v14 > 0 )
                {
                    a2k = (float)(v14 - 1);
                    sithPlayer_SetBinAmt(SITHBIN_F_SEEING, a2k);
                    goto LABEL_37;
                }
                v15 = (__int64)sithPlayer_GetBinAmt(SITHBIN_F_SPEED);
                if ( (int)v15 > 0 )
                {
                    a2l = (float)(v15 - 1);
                    sithPlayer_SetBinAmt(SITHBIN_F_SPEED, a2l);
                    goto LABEL_37;
                }
                v16 = (__int64)sithPlayer_GetBinAmt(SITHBIN_F_JUMP);
                if ( (int)v16 > 0 )
                {
                    a2m = (float)(v16 - 1);
                    sithPlayer_SetBinAmt(SITHBIN_F_JUMP, a2m);
                    goto LABEL_37;
                }
LABEL_38:
                if ( v3 <= 0 )
                    return;
            }
            a2a = (float)(v4 - 1);
            sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS, a2a);
LABEL_37:
            --v3;
            goto LABEL_38;
        }
    }
}

float jkPlayer_CalcStarsAlign()
{
    float alignment = 0.0;

    // MOTS: Return 0.0 always
    if (Main_bMotsCompat) return 0.0;

    for (int i = SITHBIN_F_THROW; i <= SITHBIN_F_DESTRUCTION; ++i )
    {
        float amt = sithPlayer_GetBinAmt(i);
        alignment -= amt * 6.25;
    }
    
    for (int j = SITHBIN_F_HEALING; j <= SITHBIN_F_ABSORB; ++j )
    {
        float amt = sithPlayer_GetBinAmt(j);
        alignment -= amt * -6.25;
    }
    
    return alignment;
}

int jkPlayer_SetProtectionDeadlysight()
{
    // MOTS TODO
    if (Main_bMotsCompat) return 0;

    int rank = jkPlayer_GetJediRank();

    int hasNoDarkside = 1;
    for (int i = SITHBIN_F_THROW; i <= SITHBIN_F_DESTRUCTION; ++i )
    {
        if (sithPlayer_GetBinAmt(i) > 0.0)
            hasNoDarkside = 0;
    }

    int hasFullDarkside = 1;
    for (int j = SITHBIN_F_THROW; j <= SITHBIN_F_DESTRUCTION; ++j )
    {
        if (sithPlayer_GetBinAmt(j) < 4.0)
            hasFullDarkside = 0;
    }

    int hasNoLightside = 1;
    for (int k = SITHBIN_F_HEALING; k <= SITHBIN_F_ABSORB; ++k )
    {
        if (sithPlayer_GetBinAmt(k) > 0.0)
            hasNoLightside = 0;
    }

    int hasFullLightside = 1;
    for (int l = SITHBIN_F_HEALING; l <= SITHBIN_F_ABSORB; ++l )
    {
        if (sithPlayer_GetBinAmt(l) < 4.0)
            hasFullLightside = 0;
    }

    int hasNoNeutral = 1;
    for (int m = SITHBIN_FP_START; m <= SITHBIN_F_PULL; ++m )
    {
        if (m == SITHBIN_JEDI_RANK) continue;
        if (sithPlayer_GetBinAmt(m) > 0.0)
            hasNoNeutral = 0;
    }

    if (rank == 8)
    {
        if ( hasFullLightside && hasNoDarkside && hasNoNeutral )
        {
            sithPlayer_SetBinAmt(SITHBIN_F_PROTECTION, 4.0);
            sithPlayer_SetBinCarries(SITHBIN_F_PROTECTION, 1);
            sithPlayer_SetBinAmt(SITHBIN_F_DEADLYSIGHT, 0.0);
            sithPlayer_SetBinCarries(SITHBIN_F_DEADLYSIGHT, 0);
            return 1;
        }
        if ( hasFullDarkside && hasNoLightside && hasNoNeutral )
        {
            sithPlayer_SetBinAmt(SITHBIN_F_DEADLYSIGHT, 4.0);
            sithPlayer_SetBinCarries(SITHBIN_F_DEADLYSIGHT, 1);
            sithPlayer_SetBinAmt(SITHBIN_F_PROTECTION, 0.0);
            sithPlayer_SetBinCarries(SITHBIN_F_PROTECTION, 0);
            return 2;
        }
        sithPlayer_SetBinAmt(SITHBIN_F_PROTECTION, 0.0);
        sithPlayer_SetBinCarries(SITHBIN_F_PROTECTION, 0);
        sithPlayer_SetBinAmt(SITHBIN_F_DEADLYSIGHT, 0.0);
        sithPlayer_SetBinCarries(SITHBIN_F_DEADLYSIGHT, 0);
    }
    return 0;
}

void jkPlayer_DisallowOtherSide(int rank)
{
    // MOTS TODO
    if (Main_bMotsCompat) return;

    float align = jkPlayer_CalcStarsAlign();

    if ( rank < 7 )
        return;

    if ( align <= 0.0 )
    {
        if ( align >= 0.0 )
        {
            for (int i = SITHBIN_F_THROW; i < SITHBIN_F_DESTRUCTION; i++)
                sithPlayer_SetBinCarries(i, 1);
            for (int k = SITHBIN_F_HEALING; k <= SITHBIN_F_ABSORB; ++k )
                sithPlayer_SetBinCarries(k, 1);
        }
        else
        {
            for (int i = SITHBIN_F_THROW; i < SITHBIN_F_DESTRUCTION; i++)
                sithPlayer_SetBinCarries(i, 1);
            for (int l = SITHBIN_F_HEALING; l <= SITHBIN_F_ABSORB; ++l )
                sithPlayer_SetBinCarries(l, 0);
        }
    }
    else
    {
        for (int m = SITHBIN_F_THROW; m <= SITHBIN_F_DESTRUCTION; ++m )
            sithPlayer_SetBinCarries(m, 0);
        for (int n = SITHBIN_F_HEALING; n <= SITHBIN_F_ABSORB; ++n )
            sithPlayer_SetBinCarries(n, 1);
    }
}

int jkPlayer_WriteOptionsConf()
{
    return stdConffile_Printf("fullsubtitles %d\n", jkPlayer_setFullSubtitles)
        && stdConffile_Printf("disablecutscenes %d\n", jkPlayer_setDisableCutscenes)
        && stdConffile_Printf("rotateoverlaymap %d\n", jkPlayer_setRotateOverlayMap)
        && stdConffile_Printf("drawstatus %d\n", jkPlayer_setDrawStatus)
        && stdConffile_Printf("crosshair %d\n", jkPlayer_setCrosshair)
        && stdConffile_Printf("sabercam %d\n", jkPlayer_setSaberCam);
}

int jkPlayer_ReadOptionsConf()
{
    return stdConffile_ReadLine()
        && _sscanf(stdConffile_aLine, "fullsubtitles %d\n", &jkPlayer_setFullSubtitles) == 1
        && stdConffile_ReadLine()
        && _sscanf(stdConffile_aLine, "disablecutscenes %d\n", &jkPlayer_setDisableCutscenes) == 1
        && stdConffile_ReadLine()
        && _sscanf(stdConffile_aLine, "rotateoverlaymap %d\n", &jkPlayer_setRotateOverlayMap) == 1
        && stdConffile_ReadLine()
        && _sscanf(stdConffile_aLine, "drawstatus %d\n", &jkPlayer_setDrawStatus) == 1
        && stdConffile_ReadLine()
        && _sscanf(stdConffile_aLine, "crosshair %d\n", &jkPlayer_setCrosshair) == 1
        && stdConffile_ReadLine()
        && _sscanf(stdConffile_aLine, "sabercam %d\n", &jkPlayer_setSaberCam) == 1;
}

int jkPlayer_GetJediRank()
{
    return (int)(__int64)(sithPlayer_GetBinAmt(SITHBIN_JEDI_RANK));
}

void jkPlayer_SetRank(int rank)
{
    sithPlayer_SetBinAmt(SITHBIN_JEDI_RANK, (float)rank);
}

// MOTS added
static char* jkPlayer_aClassNames[5] = {
    "single",
    "jedi",
    "bounty",
    "scout",
    "soldier",
};

// MOTS added
uint32_t jkPlayer_ChecksumExtra(uint32_t hash)
{
    int iVar1;
    uint32_t uVar2;
    int64_t lVar3;
    int local_8c;
    float local_88;
    int local_84;
    char local_80 [128];
    
    for (uVar2 = 0; uVar2 < 5; uVar2++) 
    {
        stdString_snprintf(local_80, 128, "misc\\per\\%s.per", jkPlayer_aClassNames[uVar2]); // Added: sprintf -> snprintf
        if (stdConffile_OpenRead(local_80)) 
        {
            if ((stdConffile_ReadLine() && (iVar1 = _sscanf(stdConffile_aLine,"version %d",&local_84), iVar1 == 1)) && (local_84 == 2)) {
                hash = hash + 2;
                while (((stdConffile_ReadLine() && (iVar1 = _sscanf(stdConffile_aLine,"param %d: %f",&local_8c,&local_88), iVar1 == 2)) && ((-1 < local_8c && (local_8c < 0x100))))) {
                    iVar1 = local_8c + 1;
                    lVar3 = (int64_t)(local_88 * 1000.0);
                    hash = hash + (iVar1 + uVar2) * ((uint32_t)lVar3 ^ 0x5b32a);
                    iVar1 = stdConffile_ReadLine();
                }
            }
            stdConffile_Close();
        }
    }
    return hash;
}

// MOTS added
jkPlayerInfo* jkPlayer_FUN_00404fe0(sithThing *pPlayerThing)
{
#ifdef JKM_DSS
    int iVar3;
    
    iVar3 = 0;
    for (iVar3 = 0; iVar3 < NUM_JKPLAYER_THINGS; iVar3++) {
        if (jkPlayer_aMotsInfos[iVar3].actorThing)
            continue;

        jkPlayer_aMotsInfos[iVar3].actorThing = pPlayerThing;
        jkPlayer_aMotsInfos[iVar3].thing_id = pPlayerThing->thing_id;
        jkPlayer_aMotsInfos[iVar3].rd_thing.model3 = NULL;

        pPlayerThing->thingflags |= SITH_TF_RENDERWEAPON;
        pPlayerThing->playerInfo = &jkPlayer_aMotsInfos[iVar3];
        
        return pPlayerThing->playerInfo;
    }
#endif
    return NULL;
}

// NOTS added
int jkPlayer_SetAmmoMaximums(int classIdx)
{
    if (!Main_bMotsCompat) return 1;

#ifdef JKM_DSS
    int iVar1;
    float *pfVar2;
    int local_8c;
    float local_88;
    int local_84;
    char local_80 [128];
    
    if ((classIdx < 0) || (4 < classIdx)) {
        classIdx = 0;
    }
    _sprintf(local_80,"misc\\per\\%s.per", jkPlayer_aClassNames[classIdx]);
    iVar1 = stdConffile_OpenRead(local_80);
    if (iVar1 != 0) {
        iVar1 = stdConffile_ReadLine();
        if (((iVar1 != 0) && (iVar1 = _sscanf(stdConffile_aLine,"version %d",&local_84), iVar1 == 1)) && (local_84 == 2)) {
            pfVar2 = jkPlayer_aMultiParams;
            for (iVar1 = 0x100; iVar1 != 0; iVar1 = iVar1 + -1) {
                *pfVar2 = 0.0;
                pfVar2 = pfVar2 + 1;
            }
            iVar1 = stdConffile_ReadLine();
            while( 1 ) {
                if (iVar1 == 0) {
                    stdConffile_Close();
                    jkHudInv_FixAmmoMaximums();
                    pfVar2 = jkPlayer_aMultiParams + 51;
                    do {
                        iVar1 = (int)pfVar2[-1];
                        if ((-1 < iVar1) && (iVar1 < 200)) {
                            sithInventory_aDescriptors[iVar1].ammoMax = *pfVar2;
                        }
                        pfVar2 = pfVar2 + 2;
                    } while (pfVar2 < &jkPlayer_aMultiParams[61]);
                    return 1;
                }
                iVar1 = _sscanf(stdConffile_aLine,"param %d: %f",&local_8c,&local_88);
                if (((iVar1 != 2) || (local_8c < 0)) || (0xff < local_8c)) break;
                jkPlayer_aMultiParams[local_8c] = local_88;
                iVar1 = stdConffile_ReadLine();
            }
        }
        stdConffile_Close();
        return 0;
    }
#endif
    return 0;
}

// MOTS added
void jkPlayer_idkEndLevel(void)
{
    if (!Main_bMotsCompat) return;

    int lVar3 = (int)sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS);
    int lVar4 = (int)sithPlayer_GetBinAmt(SITHBIN_NEW_STARS);
    int lVar5 = (int)sithPlayer_GetBinAmt(SITHBIN_F_DEFENSE);
    int local_4 = lVar3 + lVar4 + (lVar5 * 2);

    for (int iVar1 = SITHBIN_F_DEFENSE; iVar1 <= SITHBIN_FP_END; iVar1++) {
        if ((iVar1 != SITHBIN_JEDI_RANK) && (iVar1 != SITHBIN_F_DEFENSE)) {
            lVar3 = (int)sithPlayer_GetBinAmt(iVar1);
            local_4 = local_4 + lVar3;
        }
    }

    local_4 = local_4 / 3;
    if (local_4 < 0) {
        local_4 = 0;
    }
    else if (8 < local_4) {
        local_4 = 8;
    }

    sithPlayer_SetBinAmt(SITHBIN_JEDI_RANK,(float)local_4);
}

// MOTS added
int jkPlayer_SyncForcePowers(int rank,int bIsMulti)
{
#ifdef DEBUG_QOL_CHEATS
    return 0;
#endif

    int *piVar2;
    int iVar3;
    float *pfVar4;
    int iVar5;
    int iVar6;
    double dVar8;
    float fVar9;
    int *local_c;
    int local_8;
    int local_4;
    
    if (rank < 0) {
        rank = 0;
    }
    else if (8 < rank) {
        rank = 8;
    }

    if (bIsMulti == 0) 
    {
        sithPlayer_SetBinAmt(SITHBIN_F_DEFENSE,0.0);
        if (((0 < rank) &&
            (fVar9 = sithPlayer_GetBinAmt(SITHBIN_F_JUMP), fVar9 < 1.0)) &&
           (fVar9 = sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS), 0.0 < fVar9)) 
        {
            sithPlayer_SetBinAmt(SITHBIN_F_JUMP,1.0);
            fVar9 = sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS);
            sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS,(float)(fVar9 - 1.0));
        }

        if (((1 < rank) &&
            (fVar9 = sithPlayer_GetBinAmt(SITHBIN_F_PULL), fVar9 < 1.0)) &&
           (fVar9 = sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS), 0.0 < fVar9)) 
        {
            sithPlayer_SetBinAmt(SITHBIN_F_PULL,1.0);
            fVar9 = sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS);
            sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS,(float)(fVar9 - 1.0));
        }

        if (((3 < rank) && (fVar9 = sithPlayer_GetBinAmt(SITHBIN_F_SEEING), fVar9 < 1.0)) &&
           (fVar9 = sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS), 0.0 < fVar9)) 
        {
            sithPlayer_SetBinAmt(SITHBIN_F_SEEING,1.0);
            fVar9 = sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS);
            sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS,(float)(fVar9 - 1.0));
        }

        iVar3 = rank;
        if (((4 < rank) && (fVar9 = sithPlayer_GetBinAmt(SITHBIN_F_PERSUASION), fVar9 < 1.0)) &&
           (fVar9 = sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS), 0.0 < fVar9)) 
        {
            sithPlayer_SetBinAmt(SITHBIN_F_PERSUASION,1.0);
            fVar9 = sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS);
            sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS,(float)(fVar9 - 1.0));
        }
    }
    else 
    {
        iVar3 = rank * 3 + (int)jkPlayer_aMultiParams[119] * 2;
        pfVar4 = jkPlayer_aMultiParams + 0x77;

        do {
            if ((pfVar4 != jkPlayer_aMultiParams + 0x78) && (pfVar4 != jkPlayer_aMultiParams + 0x77)
               ) {
                iVar3 = iVar3 + (int)*pfVar4;
            }
            pfVar4 = pfVar4 + 1;
        } while (pfVar4 < &jkPlayer_aMultiParams[0x8C]);

        fVar9 = sithPlayer_GetBinAmt(SITHBIN_F_DEFENSE);
        if (fVar9 < jkPlayer_aMultiParams[119]) {
            sithPlayer_SetBinAmt(SITHBIN_F_DEFENSE,jkPlayer_aMultiParams[119]);
        }
        iVar5 = SITHBIN_F_DEFENSE;
        pfVar4 = jkPlayer_aMultiParams + 0x77;

        do {
            if ((pfVar4 != jkPlayer_aMultiParams + 0x78) && (pfVar4 != jkPlayer_aMultiParams + 0x77)
               ) {
                fVar9 = sithPlayer_GetBinAmt(iVar5);
                if (fVar9 < *pfVar4) {
                    sithPlayer_SetBinAmt(iVar5,*pfVar4);
                }
            }
            pfVar4 = pfVar4 + 1;
            iVar5 = iVar5 + 1;
        } while (pfVar4 < &jkPlayer_aMultiParams[0x8C]);
    }

    iVar5 = (int)sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS) + (int)sithPlayer_GetBinAmt(SITHBIN_F_DEFENSE) * 2;
    iVar6 = SITHBIN_F_DEFENSE;
    do 
    {
        if ((iVar6 != SITHBIN_JEDI_RANK) && (iVar6 != SITHBIN_F_DEFENSE)) {
            iVar5 += (int)sithPlayer_GetBinAmt(iVar6);
        }
        iVar6 = iVar6 + 1;
    } while (iVar6 < SITHBIN_BACTATANK);

    int bVar7 = bIsMulti != 0;
    bIsMulti = 0;
    if (bVar7) 
    {
        if (iVar3 < iVar5) {
            iVar5 = iVar5 - iVar3;
            iVar3 = (int)sithPlayer_GetBinAmt(SITHBIN_SPEND_STARS);
            if (iVar3 < iVar5) {
                iVar5 = iVar5 - iVar3;
                sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS,0.0);
                if (0 < iVar5) {
                    do {
                        fVar9 = sithPlayer_GetBinAmt(SITHBIN_F_DEFENSE);
                        if (fVar9 <= jkPlayer_aMultiParams[119]) break;
                        iVar5 = iVar5 + -2;
                        fVar9 = sithPlayer_GetBinAmt(SITHBIN_F_DEFENSE);
                        sithPlayer_SetBinAmt(SITHBIN_F_DEFENSE,(float)(fVar9 - 1.0));
                    } while (0 < iVar5);

                    if (0 < iVar5) {
                        iVar3 = SITHBIN_F_DEFENSE;
                        pfVar4 = jkPlayer_aMultiParams + 0x77;
                        do {
                            if ((pfVar4 != jkPlayer_aMultiParams + 0x78) &&
                               (pfVar4 != jkPlayer_aMultiParams + 0x77)) {
                                while ((0 < iVar5 &&
                                       (fVar9 = sithPlayer_GetBinAmt(iVar3),
                                       *pfVar4 < fVar9))) {
                                    fVar9 = sithPlayer_GetBinAmt(iVar3);
                                    sithPlayer_SetBinAmt(iVar3,(float)(fVar9 - 1.0));
                                    iVar5 = iVar5 + -1;
                                    if (iVar5 == 0) goto LAB_0040747a;
                                }
                            }
                            pfVar4 = pfVar4 + 1;
                            iVar3 = iVar3 + 1;
                        } while (pfVar4 < &jkPlayer_aMultiParams[0x8C]);
LAB_0040747a:
                        bIsMulti = 0;
                        goto LAB_004074a0;
                    }
                }
                bIsMulti = -iVar5;
            }
            else {
                sithPlayer_SetBinAmt(SITHBIN_SPEND_STARS,(float)(iVar3 - iVar5));
                bIsMulti = 0;
            }
        }
        else {
            bIsMulti = iVar3 - iVar5;
        }
    }
LAB_004074a0:
    for (iVar5 = SITHBIN_FP_START; iVar5 <= SITHBIN_FP_END; iVar5++)
    {
        if (iVar5 != SITHBIN_JEDI_RANK) {
            jkPlayer_playerInfos[playerThingIdx].iteminfo[iVar5].state &= ~ITEMSTATE_CARRIES;
        }
    }

    if ((0 < rank) ||
       (fVar9 = sithPlayer_GetBinAmt(SITHBIN_F_DEFENSE), 
       0.0 < fVar9)) 
    {
        jkPlayer_playerInfos[playerThingIdx].iteminfo[SITHBIN_F_DEFENSE].state |= ITEMSTATE_CARRIES;
    }
    local_4 = 3;
    local_c = jkPlayer_aMotsFpBins + 0x18;
    do 
    {
        if (jkPlayer_aMotsFpBins[(int)sithPlayer_GetBinAmt(SITHBIN_F_DEFENSE) + 0x44] < local_4) {
            local_8 = 0;
        }
        else {
            local_8 = jkPlayer_aMotsFpBins[local_4 + rank * 4 + 0x20];
        }
        iVar3 = 0;
        iVar5 = 8;
        piVar2 = local_c;
        do {
            if ((*piVar2 != 0) &&
               (fVar9 = sithPlayer_GetBinAmt(*piVar2), 0.0 < fVar9)) {
                iVar3 = iVar3 + 1;
            }
            iVar6 = playerThingIdx;
            piVar2 = piVar2 + 1;
            iVar5 = iVar5 + -1;
        } while (iVar5 != 0);

        if (iVar3 < local_8) {
            iVar3 = 8;
            piVar2 = local_c;
            do {
                if (*piVar2 != 0) {
                    jkPlayer_playerInfos[playerThingIdx].iteminfo[*piVar2].state |= ITEMSTATE_CARRIES;
                }
                piVar2 = piVar2 + 1;
                iVar3 = iVar3 + -1;
            } while (iVar3 != 0);
        }
        else {
            iVar5 = 0;
            piVar2 = local_c;
            do {
                if (iVar3 <= local_8) break;
                iVar6 = *piVar2;
                if ((iVar6 != 0) && (jkPlayer_aMultiParams[iVar6 + 100] < 1.0)) {
                    bIsMulti = bIsMulti + (int)sithPlayer_GetBinAmt(iVar6);
                    sithPlayer_SetBinAmt(iVar6,0.0);
                }
                iVar5 = iVar5 + 1;
                piVar2 = piVar2 + 1;
            } while (iVar5 < 8);

            iVar3 = 8;
            piVar2 = local_c;
            do {
                iVar5 = *piVar2;
                if ((iVar5 != 0) &&
                   (fVar9 = sithPlayer_GetBinAmt(iVar5), 0.0 < fVar9)) {
                    jkPlayer_playerInfos[playerThingIdx].iteminfo[iVar5].state |= ITEMSTATE_CARRIES;
                }
                piVar2 = piVar2 + 1;
                iVar3 = iVar3 + -1;
            } while (iVar3 != 0);

        }
        local_c = local_c + -8;
        local_4 = local_4 + -1;
        if (local_c < jkPlayer_aMotsFpBins) {
            return bIsMulti;
        }
    } while( 1 );

    return bIsMulti;
}
