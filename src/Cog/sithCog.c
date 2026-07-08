#include "sithCog.h"

#include "jk.h"
#include "types.h"
#include "Devices/sithConsole.h"
#include "Cog/sithCogFunction.h"
#include "Cog/sithCogFunctionThing.h"
#include "Cog/sithCogFunctionPlayer.h"
#include "Cog/sithCogFunctionAI.h"
#include "Cog/sithCogFunctionSurface.h"
#include "Cog/sithCogFunctionSector.h"
#include "Cog/sithCogFunctionSound.h"
#include "Cog/sithCogExec.h"
#include "Cog/sithCogParse.h"
#include "Cog/jkCog.h"
#include "Gameplay/sithEvent.h"
#include "Devices/sithSound.h"
#include "Engine/sithKeyFrame.h"
#include "World/sithMaterial.h"
#include "World/sithModel.h"
#include "World/sithTemplate.h"
#include "Gameplay/sithTime.h"
#include "World/sithSurface.h"
#include "AI/sithAIClass.h"
#include "General/stdHashtbl.h"
#include "General/stdString.h"
#include "World/sithSector.h"
#include "World/sithThing.h"
#include "Main/jkGame.h"
#include "Main/Main.h"
#include "stdPlatform.h"
#include "Dss/sithDSSCog.h"
#include "Dss/sithMulti.h"

#include "jk.h"

static int32_t sithCog_bInitted = 0;

// MOTS altered
int32_t sithCog_Startup()
{
    struct cogSymbol a2; // [esp+8h] [ebp-10h]

    sithCog_g_pSymbolTable = sithCogParse_AllocSymbolTable(SITHCOG_SYMBOL_LIMIT); // MOTS altered, DW altered, changed from 512 to 1024
    if (!sithCog_g_pSymbolTable )
    {
        stdPrintf(pSithHS->errorPrint, ".\\Cog\\sithCog.c", 118, "Could not allocate COG symboltable.");
        return 0;
    }
  
    sithCog_g_pHashtable = stdHashtbl_New(256);
    if (!sithCog_g_pHashtable)
    {
        stdPrintf(pSithHS->errorPrint, ".\\Cog\\sithCog.c", 124, "Could not allocate COG hashtable.");
        return 0;
    }
    sithCog_g_pSymbolTable->bucket_idx = 0x100;
    sithCogFunction_Startup(sithCog_g_pSymbolTable);
    sithCogFunctionThing_Startup(sithCog_g_pSymbolTable);
    sithCogFunctionAI_Startup(sithCog_g_pSymbolTable);
    sithCogFunctionSurface_Startup(sithCog_g_pSymbolTable);
    sithCogFunctionSound_Startup(sithCog_g_pSymbolTable);
    sithCogFunctionSector_Startup(sithCog_g_pSymbolTable);
    sithCogFunctionPlayer_Startup(sithCog_g_pSymbolTable);
	sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 1, "activate");
	sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 1, "activated");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 3, "startup");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 4, "timer");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 5, "blocked");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 6, "entered");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 7, "exited");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 8, "crossed");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 9, "sighted");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 10, "damaged");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 11, "arrived");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 12, "killed");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 13, "pulse");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 14, "touched");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 15, "created");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 16, "loading");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 17, "selected");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 18, "deselected");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 20, "changed");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 21, "deactivated");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 22, "shutdown");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 23, "respawn");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 2, "removed");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 19, "autoselect");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 24, "aievent");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 25, "skill");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 26, "taken");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 27, "user0");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 28, "user1");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 29, "user2");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 30, "user3");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 31, "user4");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 32, "user5");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 33, "user6");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 34, "user7");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 35, "newplayer");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 36, "fire");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 37, "join");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 38, "leave");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 39, "splash");
    sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 40, "trigger");
    if (Main_bDwCompat) {
        sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 41, "laserhit");
        sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 42, "cut");
        sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 43, "injected");
        sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 44, "powerplug");
        sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 45, "welded");
        sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 46, "tugged");
        sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 48, "used");
        sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 47, "converse");
    }
    else if (Main_bMotsCompat) {
        sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 41, "preblock");
        sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 42, "escaped");
        sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 43, "attachkilled");
        sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 44, "playeraction");
    }
    sithCog_AddFloatSymbol(sithCog_g_pSymbolTable, "global0", 0);
    sithCog_AddFloatSymbol(sithCog_g_pSymbolTable, "global1", 0);
    sithCog_AddFloatSymbol(sithCog_g_pSymbolTable, "global2", 0);
    sithCog_AddFloatSymbol(sithCog_g_pSymbolTable, "global3", 0);
    sithCog_AddFloatSymbol(sithCog_g_pSymbolTable, "global4", 0);
    sithCog_AddFloatSymbol(sithCog_g_pSymbolTable, "global5", 0);
    sithCog_AddFloatSymbol(sithCog_g_pSymbolTable, "global6", 0);
    sithCog_AddFloatSymbol(sithCog_g_pSymbolTable, "global7", 0);
    sithCog_AddFloatSymbol(sithCog_g_pSymbolTable, "global8", 0);
    sithCog_AddFloatSymbol(sithCog_g_pSymbolTable, "global9", 0);
    sithCog_AddFloatSymbol(sithCog_g_pSymbolTable, "global10", 0);
    sithCog_AddFloatSymbol(sithCog_g_pSymbolTable, "global11", 0);
    sithCog_AddFloatSymbol(sithCog_g_pSymbolTable, "global12", 0);
    sithCog_AddFloatSymbol(sithCog_g_pSymbolTable, "global13", 0);
    sithCog_AddFloatSymbol(sithCog_g_pSymbolTable, "global14", 0);
    sithCog_AddFloatSymbol(sithCog_g_pSymbolTable, "global15", 0);
    sithEvent_RegisterTask(4, sithCog_TimerEventTask, 0, 2);
    sithCog_bInitted = 1;
    return 1;
}

// Added: Register all new COG verbs last
int32_t sithCog_StartupEnhanced()
{
    if (!Main_bEnhancedCogVerbs) return 1;

    SithCogSymbolTable* ctx = sithCog_g_pSymbolTable;

    // Generic
    if (!Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunction_Pow, "pow");
        sithCog_RegisterFunction(ctx, sithCogFunction_Wakeup, "wakeup");

        sithCog_RegisterFunction(ctx,sithCogFunction_VectorEqual,"vectorequal");

        sithCog_RegisterFunction(ctx,sithCogFunction_FireProjectileData,"fireprojectiledata");
        sithCog_RegisterFunction(ctx,sithCogFunction_FireProjectileLocal,"fireprojectilelocal");

        sithCog_RegisterFunction(ctx,sithCogFunction_GetWeaponBin,"getweaponbin");

        sithCog_RegisterFunction(ctx,sithCogFunction_SendMessageExRadius,"sendmessageexradius");

        sithCog_RegisterFunction(ctx,sithCogFunction_WorldFlash,"worldflash");

        sithCog_RegisterFunction(ctx,sithCogFunction_SetCameraZoom,"setcamerazoom");

        sithCog_RegisterFunction(ctx,sithCogFunction_GetActionCog,"getactioncog");
        sithCog_RegisterFunction(ctx,sithCogFunction_SetActionCog,"setactioncog");

        sithCog_RegisterFunction(ctx,sithCogFunction_Sin,"sin");
        sithCog_RegisterFunction(ctx,sithCogFunction_Cos,"cos");
        sithCog_RegisterFunction(ctx,sithCogFunction_Tan,"tan");
        sithCog_RegisterFunction(ctx,sithCogFunction_GetCogFlags,"getcogflags");
        sithCog_RegisterFunction(ctx,sithCogFunction_SetCogFlags,"setcogflags");
        sithCog_RegisterFunction(ctx,sithCogFunction_ClearCogFlags,"clearcogflags");
        sithCog_RegisterFunction(ctx,sithCogFunction_DebugBreak,"debugbreak");
        sithCog_RegisterFunction(ctx,sithCogFunction_GetSysDate,"getsysdate");
        sithCog_RegisterFunction(ctx,sithCogFunction_GetSysTime,"getsystime");
    }
    
    // Droidworks generic
    if (!Main_bDwCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunction_SetCameraFocii, "setcamerafocii");
    }

    // AI
    if (!Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionAI_FirstThingInCone,"firstthingincone");
        sithCog_RegisterFunction(ctx, sithCogFunctionAI_NextThingInCone,"nextthingincone");
    }
    
#ifdef JKM_AI
    if (!Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionAI_AIGetAlignment, "aigetalignment");
        sithCog_RegisterFunction(ctx, sithCogFunctionAI_AISetAlignment, "aisetalignment");
        sithCog_RegisterFunction(ctx, sithCogFunctionAI_AISetInterest, "aisetinterest");
        sithCog_RegisterFunction(ctx, sithCogFunctionAI_AIGetInterest, "aigetinterest");
        sithCog_RegisterFunction(ctx, sithCogFunctionAI_AISetDistractor, "aisetdistractor");
        sithCog_RegisterFunction(ctx, sithCogFunctionAI_AIAddAlignmentPriority, "aiaddalignmentpriority");
        sithCog_RegisterFunction(ctx, sithCogFunctionAI_AIRemoveAlignmentPriority, "airemovealignmentpriority");
    
        //TODO: actor_rc.cog references a "AISetMoveTarget"?
    }
#endif

    // Player
    if (!Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionPlayer_KillPlayerQuietly, "killplayerquietly");
    }

    // Sector
    if (!Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx,sithCogFunctionSector_ChangeAllSectorsLight,"changeallsectorslight");
        sithCog_RegisterFunction(ctx,sithCogFunctionSector_FindSectorAtPos,"findsectoratpos");
        sithCog_RegisterFunction(ctx,sithCogFunctionSector_IsSphereInSector,"issphereinsector");
        sithCog_RegisterFunction(ctx,sithCogFunctionSector_GetSectorAmbientLight,"getsectorambientlight");
        sithCog_RegisterFunction(ctx,sithCogFunctionSector_SetSectorAmbientLight,"setsectorambientlight");
    }

    // Sound
    if (!Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionSound_PlaySoundThingLocal, "playsoundthinglocal");
        sithCog_RegisterFunction(ctx, sithCogFunctionSound_PlaySoundPosLocal, "playsoundposlocal");
        
        sithCog_RegisterFunction(ctx,sithCogFunctionSound_PlaySoundThing,"playvoicething");
        sithCog_RegisterFunction(ctx,sithCogFunctionSound_PlaySoundPos,"playvoicepos");
        sithCog_RegisterFunction(ctx,sithCogFunctionSound_PlaySoundLocal,"playvoicelocal");
        sithCog_RegisterFunction(ctx,sithCogFunctionSound_PlaySoundGlobal,"playvoiceglobal");
    }

    // Surface
    if (!Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetSurfaceVertexLight, "getsurfacevertexlight");
        sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SetSurfaceVertexLight, "setsurfacevertexlight");
        sithCog_RegisterFunction(ctx, sithCogFunctionSurface_GetSurfaceVertexLightRGB, "getsurfacevertexlightrgb");
        sithCog_RegisterFunction(ctx, sithCogFunctionSurface_SetSurfaceVertexLightRGB, "setsurfacevertexlightrgb");
    }

    // Thing
    
    if (!Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_CreateThingLocal, "createthinglocal");

        sithCog_RegisterFunction(ctx, sithCogFunctionThing_CreateThingAtPosOwner, "createthingatposowner");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_CreateThingAtPos, "createthingatposold");

        sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingParent, "setthingparent");

        sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingPosEx, "setthingposex");

        sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingLVecPYR, "getthinglvecpyr");

        sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetCurInvWeapon, "getcurinvweapon2");

        sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetActorWeapon, "getactorweapon2");

        sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingLookPYR, "setthinglookpyr");

        sithCog_RegisterFunction(ctx,sithCogFunctionThing_GetThingGuid,"getthingguid");
        sithCog_RegisterFunction(ctx,sithCogFunctionThing_GetGuidThing,"getguidthing");

        sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingMaxVelocity, "getthingmaxvelocity");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingMaxVelocity, "setthingmaxvelocity");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetThingMaxAngularVelocity, "getthingmaxangularvelocity");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetThingMaxAngularVelocity, "setthingmaxangularvelocity");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetActorHeadPYR, "getactorheadpyr");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetHeadPYR, "setactorheadpyr");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetJointAngle, "setthingjointangle");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetJointAngle, "getthingjointangle");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetMaxHeadPitch, "setthingmaxheadpitch");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetMinHeadPitch, "setthingminheadpitch");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_InterpolatePYR, "interpolatepyr");
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_SetWeaponTarget, "setweapontarget");

        // TODO: weap_eweb_m.cog references a "SetThingCollide" verb? Superceded by "SetThingCollideSize"?
        // TODO: exp_hrail.cog references a "GetUserData" verb? Superceded by "GetThingUserData"?
    }

    // Present in files, but registered?
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(ctx, sithCogFunctionThing_GetCurInvWeaponMots, "getcurinvweapon");
    }


    // JK
    if (!Main_bMotsCompat && !Main_bDwCompat) {
        sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 45, "enterbubble");
        sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 46, "exitbubble");
    }
    
    if (!Main_bMotsCompat) {
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_PrintUniVoice, "jkprintunivoice");

        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_GetSaberSideMat, "jkgetsabersidemat");

        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_SyncForcePowers, "jksyncforcepowers");

        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_BeginCutscene,"jkbegincutscene");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_EndCutscene,"jkendcutscene");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_StartupCutscene,"jkstartupcutscene");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_GetMultiParam,"jkgetmultiparam");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_InsideLeia,"insideleia");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_CreateBubble,"jkcreatebubble");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_DestroyBubble,"jkdestroybubble");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_GetBubbleDistance,"jkgetbubbledistance");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_ThingInBubble,"jkthinginbubble");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_GetFirstBubble,"jkgetfirstbubble");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_GetNextBubble,"jkgetnextbubble");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_GetBubbleType,"jkgetbubbletype");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_GetBubbleRadius,"jkgetbubbleradius");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_SetBubbleType,"jksetbubbletype");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_SetBubbleRadius,"jksetbubbleradius");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_Screenshot,"jkscreenshot");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_GetOpenFrames,"jkgetopenframes");
    }
    
    if (!Main_bDwCompat) {
        // Added for droidwork tests
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_dwGetActivateBin, "dwGetActivateBin");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_stub1Args, "dwsetreftopic");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_addBeam, "addbeam");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_addLaser, "addlaser");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_removeLaser, "removelaser");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_getLaserId, "getlaserid");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_stub0Args, "dwFlashInventory");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_dwPlayCammySpeech, "dwplaycammyspeech");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_stub0Args, "dwfreezeplayer");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_stub0Args, "dwunfreezeplayer");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_stub2Args, "dwplaycharacterspeech");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCog_stub0Args, "dwcleardialog");
    }

    // JK13
    if (!Main_bMotsCompat && !Main_bDwCompat)
    {
        //sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 40, "trigger");
        sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 44, "playeraction");
        sithCog_AddIntSymbol(sithCog_g_pSymbolTable, 47, "hotkey");

        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_GetThingAttachSurface, "getthingattachsurface");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_GetThingAttachThing, "getthingattachthing");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_GetCameraFov, "getcamerafov");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_GetCameraOffset, "getcameraoffset");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_SetCameraFov, "setcamerafov");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_SetCameraOffset, "setcameraoffset");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_Absolute, "absolute");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_Arccosine, "arccosine");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_Arcsine, "arcsine");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_Arctangent, "arctangent");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_Ceiling, "ceiling");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_Cosine, "cosine");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_Floor, "floor");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_Power, "power");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_Randomflex, "randomflex");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_Randomint, "randomint");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_Sine, "sine");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_Squareroot, "squareroot");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_GetHotkeyCog, "gethotkeycog");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_SetHotkeyCog, "sethotkeycog");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_IsAdjoin, "isadjoin");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_SetGameSpeed, "setgamespeed");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_GetThingHeadLvec, "getthingheadlvec");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_GetThingHeadPitch, "getthingheadpitch");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_GetThingHeadPYR, "getthingheadpyr");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_GetThingPYR, "getthingpyr");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_SetThingHeadPYR, "setthingheadpyr");
        //sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_SetThingPosEx, "setthingposex");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_SetThingPYR, "setthingpyr");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_SetThingLRUVecs, "setthingrluvecs");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_SetThingSector, "setthingsector");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_RestoreJoint, "restorejoint");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_GetThingAirDrag, "getthingairdrag");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_GetThingEyeOffset, "getthingeyeoffset");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_GetThingHeadPitchMax, "getthingheadpitchmax");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_GetThingHeadPitchMin, "getthingheadpitchmin");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_GetThingJumpSpeed, "getthingjumpspeed");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_SetThingAirDrag, "setthingairdrag");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_SetThingEyeOffset, "setthingeyeoffset");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_SetThingHeadPitchMinMax, "setthingheadpitchminmax");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_SetThingJumpSpeed, "setthingjumpspeed");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_SetThingMesh, "setthingmesh");
        //sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_SetThingParent, "setthingparent");
        sithCog_RegisterFunction(sithCog_g_pSymbolTable, jkCogExt_SetSaberFaceFlags, "jksetsaberfaceflags");
    }

    return 1;
}

void sithCog_Shutdown()
{
    sithCogParse_FreeSymbolTable(sithCog_g_pSymbolTable);
    if ( sithCog_g_pHashtable )
    {
        stdHashtbl_Free(sithCog_g_pHashtable);
        sithCog_g_pHashtable = 0;
    }
    sithCogParse_FreeParseTree();
    sithCog_bInitted = 0;

    // Added: sithCogExec var clean reset
    sithCogExec_009d39b0 = 0;
    sithCogExec_pIdkMotsCtx = NULL;
    sithCog_pActionCog = NULL;
    sithCog_actionCogIdk = 0;
}

int32_t sithCog_Open()
{
    SithWorld *world; // ecx
    int32_t result; // eax
    sithCog *v2; // ebx
    SithCogSymbolRef *v3; // ebp
    sithCog *v5; // ebp
    SithCogSymbolRef *v6; // ebx
    char *v7; // esi
    SithCogSymbol *v8; // edx
    uint32_t v10; // [esp+4h] [ebp-14h]
    uint32_t v12; // [esp+8h] [ebp-10h]
    char *v13; // [esp+Ch] [ebp-Ch]
    SithCogSymbol *v14; // [esp+10h] [ebp-8h]
    SithWorld *world_; // [esp+14h] [ebp-4h]

    world = sithWorld_g_pCurrentWorld;
    world_ = sithWorld_g_pCurrentWorld;
    if ( sithCog_bOpened )
        return 0;
    if ( sithWorld_g_pStaticWorld )
    {
        v2 = sithWorld_g_pStaticWorld->cogs;
        for (int32_t i = 0; i < sithWorld_g_pStaticWorld->numCogsLoaded; i++)
        {
            for (int32_t j = 0; j < v2->cogscript->numIdk; j++)
            {
                v3 = &v2->cogscript->aIdk[j];
                if ( _strlen(v3->value) )
                    sithCog_ParseSymbolRef(&v2->pSymbolTable->buckets[v3->hash], v3, v3->value);
            }
#ifdef COG_HEAP_INIT_ARGS
            // Added: static-world cogs never consume jkl init strings; drop them
            if (v2->aInitArgs) {
                SITH_FREE(v2->aInitArgs);
                v2->aInitArgs = NULL;
            }
#endif
            sithCog_SendMessage(v2++, SITH_MESSAGE_LOADING, 0, 0, 0, 0, 0);
            world = world_;
        }
    }
    sithCog* cogs = world->cogs;
    v12 = 0;
    if ( world->numCogsLoaded )
    {
        SithCogSymbolRef* idk = NULL;
        while ( 1 )
        {
            v10 = 0;
            v6 = cogs->cogscript->aIdk;
            if ( cogs->cogscript->numIdk )
                break;
LABEL_25:
#ifdef COG_HEAP_INIT_ARGS
            // Added: the init strings were only needed for the linking above
            if (cogs->aInitArgs) {
                SITH_FREE(cogs->aInitArgs);
                cogs->aInitArgs = NULL;
            }
#endif
            sithCog_SendMessage(cogs++, SITH_MESSAGE_LOADING, 0, 0, 0, 0, 0);
            if (++v12 >= world_->numCogsLoaded )
                goto LABEL_26;
        }

#ifdef COG_HEAP_INIT_ARGS
        v13 = cogs->aInitArgs; // may be NULL (no jkl args / arg-less cog)
#else
        v13 = cogs->field_4BC;
#endif
        while ( 1 )
        {
            idk = &cogs->cogscript->aIdk[v10];
            v8 = &cogs->pSymbolTable->buckets[idk->hash];
            v14 = v8;
            if ( (idk->flags & 1) != 0 )
            {
                if ( _strlen(idk->value) )
                    sithCog_ParseSymbolRef(v8, v6, idk->value);
                goto LABEL_24;
            }
            else if ( v13 && _strlen(v13) ) { // Added: v13 NULL guard for COG_HEAP_INIT_ARGS
                sithCog_ParseSymbolRef(v8, v6, v13);
                v8 = v14;
            }
            else if ( _strlen(idk->value) )
            {
                sithCog_ParseSymbolRef(v8, v6, idk->value);
                v8 = v14;
            }
            if (v13) // Added: NULL guard for COG_HEAP_INIT_ARGS
                v13 += 32;
            sithCog_LinkCog(cogs, v6, v8);


LABEL_24:
            ++v6;
            if (++v10 >= cogs->cogscript->numIdk )
                goto LABEL_25;
        }
    }
LABEL_26:
    result = 1;
    sithCog_bOpened = 1;
    return result;
}

// MOTS altered
void sithCog_Close()
{
    if ( sithCog_bOpened )
    {
        sithCog_BroadcastMessageEx(SITH_MESSAGE_SHUTDOWN, 0, 0, 0, 0, 0.0, 0.0, 0.0, 0.0);
        sithCog_numSectorLinks = 0;
        sithCog_numSurfaceLinks = 0;
        sithCog_numThingLinks = 0;
        sithCog_g_pMasterCog = 0;
        sithCog_pActionCog = NULL; // MOTS added
        sithCog_actionCogIdk = -1; // MOTS added
        sithCog_bOpened = 0;
    }
}

// MOTS altered?
int sithCog_ReadCogsListText(SithWorld *world, int a2)
{
    int32_t num_cogs; // esi
    int32_t result; // eax
    sithCog *cogs; // eax
    uint32_t v7; // eax
    int32_t *v8; // ebx
    sithCog *v9; // eax
    uint32_t v15; // eax
    SithCogSymbolTable *cogscript_symboltable; // edx
    int32_t v17; // ecx
    SithCogScript *v18; // ebp
    char **v19; // edi
    char *v21; // esi
    uint32_t v22; // [esp+10h] [ebp-88h]
    uint32_t v23; // [esp+14h] [ebp-84h]
    char cog_fpath[32]; // [esp+18h] [ebp-80h] BYREF

    if ( a2 )
        return 0;
    stdConffile_ReadArgs();
    if ( _strcmp(stdConffile_g_entry.args[0].value, "world") || _strcmp(stdConffile_g_entry.args[1].value, "cogs") )
        return 0;
    num_cogs = _atoi(stdConffile_g_entry.args[2].value);
    if ( !num_cogs )
        return 1;
    { TWL_EXTRAM_SUGGEST(pSithHS); // Added: word-width fields (fpath is debug-only)
    cogs = (sithCog *)SITH_ALLOC(sizeof(sithCog) * num_cogs);
    TWL_EXTRAM_RESTORE(pSithHS); }
    world->cogs = cogs;
    if ( cogs )
    {
        stdPlatform_Memzero32(cogs, sizeof(sithCog) * num_cogs); // Added: word-safe
        world->numCogs = num_cogs;
        world->numCogsLoaded = 0;
        while ( stdConffile_ReadArgs() )
        {
            if ( !_strcmp(stdConffile_g_entry.args[0].value, "end") )
                break;
            if ( stdConffile_g_entry.numArgs < 2u )
                return 0;
            v9 = sithCog_Load(stdConffile_g_entry.args[1].value);

            //printf("%s\n", stdConffile_g_entry.args[1].value);

            if ( v9 )
            {
                v18 = v9->cogscript;
                v23 = 0;
#ifdef COG_HEAP_INIT_ARGS
                // Added: exact-size init-arg strings, freed after linking in sithCog_Open
                v9->aInitArgs = NULL;
                if (v9->cogscript->numIdk) {
                    v9->aInitArgs = (char*)SITH_ALLOC(32 * v9->cogscript->numIdk);
                    if (v9->aInitArgs)
                        _memset(v9->aInitArgs, 0, 32 * v9->cogscript->numIdk);
                }
                v21 = v9->aInitArgs;
#else
                v21 = &v9->field_4BC[0];
#endif
                v22 = 2;
                for (v23 = 0; v23 < v9->cogscript->numIdk; v23++)
                {
                    //printf("%s\n", stdConffile_g_entry.args[v22].value);
                    if ( v21 && (v18->aIdk[v23].flags & 1) == 0 && stdConffile_g_entry.numArgs > v22 )
                    {
                        stdString_SafeStrCopy(v21, stdConffile_g_entry.args[v22].value, 32);
                        v21 += 32;
                        ++v22;
                    }
                }
            }
        }
        result = 1;
    }
    else
    {
        stdPrintf(pSithHS->errorPrint, ".\\Cog\\sithCog.c", 883, "Memory alloc failure initializing COGs.\n", 0, 0, 0, 0);
        result = 0;
    }
    return result;
}

sithCog* sithCog_Load(const char *fpath)
{
    uint32_t cogIdx; // eax
    SithCogSymbolTable *result; // eax
    sithCog *cog; // ebx
    SithCogScript *v7; // eax
    SithCogScript *v8; // esi
    uint32_t v9; // eax
    char cog_fpath[128]; // [esp+10h] [ebp-80h] BYREF

    cogIdx = sithWorld_g_pLastLoadedWorld->numCogsLoaded;
    if ( cogIdx >= sithWorld_g_pLastLoadedWorld->numCogs )
        return 0;

    cog = &sithWorld_g_pLastLoadedWorld->cogs[cogIdx];
    cog->selfCog = cogIdx;
    if (sithWorld_g_pLastLoadedWorld->level_type_maybe & 1)
    {
        cog->selfCog |= 0x8000;
    }
    _sprintf(cog_fpath, "%s%c%s", "cog", '\\', fpath);
    v7 = (SithCogScript *)stdHashtbl_Find(sithCog_g_pHashtable, fpath);
    if ( v7 )
    {
        v8 = v7;
    }
    else
    {
        v9 = sithWorld_g_pLastLoadedWorld->numCogScriptsLoaded;
        if ( v9 < sithWorld_g_pLastLoadedWorld->numCogScripts && (v8 = &sithWorld_g_pLastLoadedWorld->cogScripts[v9], sithCogParse_Load(cog_fpath, v8, 0)) )
        {
            stdHashtbl_Add(sithCog_g_pHashtable, cog_fpath, v8); // Added: v8 -> no v8 for cog_fpath
            ++sithWorld_g_pLastLoadedWorld->numCogScriptsLoaded;
        }
        else
        {
            v8 = 0;
        }
    }
    if ( !v8 )
        return 0;
#ifdef SITH_DEBUG_STRUCT_NAMES
    stdString_SafeStrCopy(cog->cogscript_fpath, cog_fpath, 32); // v8 -> no v8 for cog_fpath
#endif
    cog->cogscript = v8;
    cog->flags = v8->flags;
    cog->pSymbolTable = sithCogParse_DuplicateSymbolTable(v8->pSymbolTable);
    if ( cog->pSymbolTable )
    {
        sithWorld_g_pLastLoadedWorld->numCogsLoaded++;
        return cog;
    }
    return NULL;
}

int32_t sithCog_ParseSymbolRef(SithCogSymbol *cogSymbol, SithCogSymbolRef *cogIdk, char *val)
{
    SithCogSymbol *v5; // esi
    SithCogSymbol *v7; // ecx
    SithCogSymbol *v9; // esi
    rdMaterial *v10; // eax
    sithSound *v12; // eax
    SithThing *v14; // eax
    rdModel3 *v15; // eax
    rdKeyframe *v17; // eax
    SithAIClass *v19; // eax
#ifdef COG_COMPRESS_VAR_SIZE
    flex32_t tmpx, tmpy, tmpz;
    cog_flex_t* pVec;
#endif

    switch ( cogIdk->type )
    {
        case COG_TYPE_FLEX:
            cogSymbol->val.type = COG_VARTYPE_FLEX;
            cogSymbol->val.dataAsFloat[0] = _atof(val); // FLEXTODO
            return 1;

        case COG_TYPE_TEMPLATE:
            cogSymbol->val.type = COG_VARTYPE_INT;
            v14 = sithTemplate_GetTemplate(val);
            if ( !v14 )
            {
                cogSymbol->val.data[0] = -1;
                return 0;
            }
            cogSymbol->val.data[0] = v14->thingIdx;
            return 1;

        case COG_TYPE_KEYFRAME:
            cogSymbol->val.type = COG_VARTYPE_INT;
            v17 = sithKeyFrame_LoadEntry(val);
            
            if ( !v17 )
            {
                cogSymbol->val.data[0] = -1;
                return 0;
            }

            // HACK HACK HACK HACK HACK somehow some keyframes aren't being set correctly?
            if (!(v17->id & 0x8000)) {
                v17->id = (v17 - sithWorld_g_pCurrentWorld->keyframes) & 0xFFFF;
                if (v17->id >= 0x8000)
                {
                    v17->id = (v17 - sithWorld_g_pStaticWorld->keyframes) | 0x8000;
                }
            }
            else {
                v17->id = (v17 - sithWorld_g_pStaticWorld->keyframes) | 0x8000;
            }

            cogSymbol->val.data[0] = v17->id;
            return 1;
        case COG_TYPE_SOUND:
            cogSymbol->val.type = COG_VARTYPE_INT;
            v12 = sithSound_Load(val, 0);
            if ( !v12 )
            {
                cogSymbol->val.data[0] = -1;
                return 0;
            }
            cogSymbol->val.data[0] = v12->id;
            return 1;
        case COG_TYPE_MATERIAL:
            cogSymbol->val.type = COG_VARTYPE_INT;
            v10 = sithMaterial_Load(val, 0, 0);
            if ( !v10 )
            {
                cogSymbol->val.data[0] = -1;
                return 0;
            }
            cogSymbol->val.data[0] = v10->id;
            return 1;
        case COG_TYPE_VECTOR:
            cogSymbol->val.type = COG_VARTYPE_VECTOR;
#ifndef COG_COMPRESS_VAR_SIZE
            if (_sscanf(val, "(%f/%f/%f)", &cogSymbol->val.dataAsFloat[0], &cogSymbol->val.dataAsFloat[1], &cogSymbol->val.dataAsFloat[2]) == 3 )
            {
                return 1;
            }
            else
            {
                cogSymbol->val.dataAsFloat[0] = 0.0;
                cogSymbol->val.dataAsFloat[1] = 0.0;
                cogSymbol->val.dataAsFloat[2] = 0.0;
                return 0;
            }
#else
            pVec = (cog_flex_t*)SITH_ALLOC(sizeof(cog_flex_t)*3);
            if (pVec) {
                cogSymbol->val.dataAsPtrs[0] = (intptr_t)pVec;
                if (_sscanf(val, "(%f/%f/%f)", &tmpx, &tmpy, &tmpz) == 3 )
                {
                    pVec[0] = tmpx;
                    pVec[1] = tmpy;
                    pVec[2] = tmpz;
                    return 1;
                }
                else
                {
                    pVec[0] = 0.0f;
                    pVec[1] = 0.0f;
                    pVec[2] = 0.0f;
                    return 0;
                }
            }
            else {
                cogSymbol->val.dataAsPtrs[0] = 0;
                return 0;
            }
#endif
            break;

        case COG_TYPE_MODEL:
            cogSymbol->val.type = COG_VARTYPE_INT;
            v15 = sithModel_Load(val, 1);
            if ( !v15 )
            {
                cogSymbol->val.data[0] = -1;
                return 0;
            }
            cogSymbol->val.data[0] = v15->id;
            return 1;

        case COG_TYPE_AICLASS:
            cogSymbol->val.type = COG_VARTYPE_INT;
            v19 = sithAIClass_Load(val);
            if ( v19 )
            {
                cogSymbol->val.data[0] = v19->index;
                return 1;
            }
            else
            {
                cogSymbol->val.data[0] = -1;
                return 0;
            }
            break;

        default:
            cogSymbol->val.type = COG_VARTYPE_INT;
            cogSymbol->val.data[0] = _atoi(val);
            return 1;
    }
}

int32_t sithCog_LinkCog(sithCog *cog, SithCogSymbolRef *idk, SithCogSymbol *symbol)
{
    cog_int_t v3 = symbol->val.data[0];
    if ( v3 < 0 )
        return 0;
    switch ( idk->type )
    {
        case 3:
            if ( v3 >= sithWorld_g_pCurrentWorld->numThingsLoaded )
                return 0;
            return sithCog_LinkCogToThing(cog, &sithWorld_g_pCurrentWorld->things[v3], idk->linkid, idk->mask);
        case 5:
            if ( v3 >= sithWorld_g_pCurrentWorld->numSectors )
                return 0;
            return sithCog_LinkCogToSector(cog, &sithWorld_g_pCurrentWorld->sectors[v3], idk->linkid, idk->mask);
        case 6:
            if ( v3 >= sithWorld_g_pCurrentWorld->numSurfaces )
                return 0;
            return sithCog_LinkCogToSurface(cog, &sithWorld_g_pCurrentWorld->surfaces[v3], idk->linkid, idk->mask);
    }
    return 1;
}

void sithCog_ThingSendMessage(SithThing *a1, SithThing *a2, int32_t msg)
{
    sithCog_ThingSendMessageEx(a1, a2, msg, 0.0, 0.0, 0.0, 0.0);
}

cog_flex_t sithCog_ThingSendMessageEx(SithThing *sender, SithThing *receiver, SITH_MESSAGE message, cog_flex_t param0, cog_flex_t param1, cog_flex_t param2, cog_flex_t param3)
{
    //return _sithCog_SendMessageFromThingEx(sender, receiver, message, param0, param1, param2, param3);
    int32_t v7; // ebx
    int32_t v8; // ebp
    sithCog *v9; // eax
    cog_flex_t v10; // st7
    cog_flex_t v11; // st7
    sithCog *v12; // eax
    cog_flex_t v13; // st7
    cog_flex_t v14; // st7
    cog_flex_t v16; // st7
    cog_flex_t v17; // st7
    cog_flex_t v19; // [esp+10h] [ebp-8h]
    int32_t receivera; // [esp+20h] [ebp+8h]

    v19 = 0.0;
    if ( message == SITH_MESSAGE_DAMAGED )
        v19 = param0;
    if ( receiver )
    {
        v7 = receiver->thingIdx;
        v8 = 3;
        receivera = 1 << receiver->type;
    }
    else
    {
        v7 = -1;
        v8 = 0;
        receivera = 1;
    }
    v9 = sender->class_cog;
    if ( v9 )
    {
#ifdef DEBUG_QOL_CHEATS
        if (receiver == sithPlayer_g_pLocalPlayerThing && message == SITH_MESSAGE_ACTIVATE) {
#ifdef SITH_DEBUG_STRUCT_NAMES
            jk_printf("OpenJKDF2: Debug thing cog class %s\n", v9->cogscript_fpath);
#endif
        }
#endif

        if ( message == SITH_MESSAGE_DAMAGED )
        {
            v10 = sithCog_SendMessageEx(v9, SITH_MESSAGE_DAMAGED, SENDERTYPE_THING, sender->thingIdx, v8, v7, 0, param0, param1, param2, param3);
            if ( v10 != -9999.9873046875 )
            {
                v19 = v10;
                param0 = v10;
            }
        }
        else
        {
            v11 = sithCog_SendMessageEx(v9, message, SENDERTYPE_THING, sender->thingIdx, v8, v7, 0, param0, param1, param2, param3);
            if ( v11 != -9999.9873046875 )
            {
                v19 = v11 + v19;
            }
        }
    }
    v12 = sender->capture_cog;
    if ( v12 )
    {
#ifdef DEBUG_QOL_CHEATS
        if (receiver == sithPlayer_g_pLocalPlayerThing && message == SITH_MESSAGE_ACTIVATE) {
#ifdef SITH_DEBUG_STRUCT_NAMES
            jk_printf("OpenJKDF2: Debug thing cog capture %s\n", v12->cogscript_fpath);
#endif
        }
#endif
        if ( message == SITH_MESSAGE_DAMAGED )
        {
            v13 = sithCog_SendMessageEx(v12, SITH_MESSAGE_DAMAGED, SENDERTYPE_THING, sender->thingIdx, v8, v7, 0, param0, param1, param2, param3);
            if ( v13 != -9999.9873046875 )
            {
                v19 = v13;
                param0 = v13;
            }
        }
        else
        {
            v14 = sithCog_SendMessageEx(v12, message, SENDERTYPE_THING, sender->thingIdx, v8, v7, 0, param0, param1, param2, param3);
            if ( v14 != -9999.9873046875 )
                v19 = v14 + v19;
        }
    }
    for (int32_t i = 0; i < sithCog_numThingLinks; i++)
    {
        SithCogThingLink* v15 = &sithCog_aThingLinks[i];
        if ( v15->thing == sender && v15->signature == sender->signature && (receivera & v15->mask) != 0 )
        {
#ifdef DEBUG_QOL_CHEATS
            if (receiver == sithPlayer_g_pLocalPlayerThing &&message == SITH_MESSAGE_ACTIVATE && v15->cog) {
#ifdef SITH_DEBUG_STRUCT_NAMES
                jk_printf("OpenJKDF2: Debug thing cog link %s\n", v15->cog->cogscript_fpath);
#endif
            }
#endif
            if ( message == SITH_MESSAGE_DAMAGED )
            {
                v16 = sithCog_SendMessageEx(
                          v15->cog,
                          SITH_MESSAGE_DAMAGED,
                          SENDERTYPE_THING,
                          sender->thingIdx,
                          v8,
                          v7,
                          0,
                          param0,
                          param1,
                          param2,
                          param3);
                if ( v16 != -9999.9873046875 )
                {
                    v19 = v16;
                    param0 = v16;
                }
            }
            else
            {
                v17 = sithCog_SendMessageEx(
                          v15->cog,
                          message,
                          SENDERTYPE_THING,
                          sender->thingIdx,
                          v8,
                          v7,
                          v15->linkid,
                          param0,
                          param1,
                          param2,
                          param3);
                if ( v17 != -9999.9873046875 )
                    v19 = v17 + v19;
            }
        }
    }
    return v19;
}

void sithCog_SurfaceSendMessage(SithSurface *surface, SithThing *thing, int32_t msg)
{
    sithCog_SurfaceSendMessageEx(surface, thing, msg, 0.0, 0.0, 0.0, 0.0);
}

cog_flex_t sithCog_SurfaceSendMessageEx(SithSurface *sender, SithThing *thing, SITH_MESSAGE msg, cog_flex_t a4, cog_flex_t a5, cog_flex_t a6, cog_flex_t a7)
{
    int32_t v8; // ebp
    cog_flex_t v9; // ebx
    cog_flex_t v11; // st7
    cog_flex_t v12; // st7
    cog_flex_t v14; // [esp+10h] [ebp-Ch]
    int32_t v15; // [esp+14h] [ebp-8h]
    int32_t sourceType; // [esp+24h] [ebp+8h]

    v14 = 0.0;
    if ( thing )
    {
        v8 = thing->thingIdx;
        sourceType = SENDERTYPE_THING;
        v15 = 1 << thing->type;
    }
    else
    {
        v8 = -1;
        sourceType = 0;
        v15 = 1;
    }
    
    v9 = a4;
    for (int32_t i = 0; i < sithCog_numSurfaceLinks; i++)
    {
        SithCogSurfaceLink* surfaceLink = &sithCog_aSurfaceLinks[i];
        if ( surfaceLink->surface == sender && (surfaceLink->mask & v15) != 0 )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            if (thing == sithPlayer_g_pLocalPlayerThing && msg == SITH_MESSAGE_ACTIVATE) {
                printf("OpenJKDF2: Debug %s\n", surfaceLink->cog->cogscript_fpath);
            }
#endif
            if ( msg == SITH_MESSAGE_DAMAGED )
            {
                v11 = sithCog_SendMessageEx(
                          surfaceLink->cog,
                          SITH_MESSAGE_DAMAGED,
                          SENDERTYPE_SURFACE,
                          sender->index,
                          sourceType,
                          v8,
                          surfaceLink->linkid,
                          v9,
                          a5,
                          a6,
                          a7);
                if ( v11 == -9999.9873046875 )
                {
                    v14 = a4;
                }
                else
                {
                    v14 = v11;
                    a4 = v11;
                    v9 = a4;
                }
            }
            else
            {
                v12 = sithCog_SendMessageEx(surfaceLink->cog, msg, SENDERTYPE_SURFACE, sender->index, sourceType, v8, surfaceLink->linkid, v9, a5, a6, a7);
                if ( v12 != -9999.9873046875 )
                    v14 = v12 + v14;
            }
        }
    }
    return v14;
}

void sithCog_SectorSendMessage(SithSector *sector, SithThing *thing, int32_t message)
{
    sithCog_SectorSendMessageEx(sector, thing, message, 0.0, 0.0, 0.0, 0.0);
}

cog_flex_t sithCog_SectorSendMessageEx(SithSector *a1, SithThing *sourceType, SITH_MESSAGE message, cog_flex_t param0, cog_flex_t param1, cog_flex_t param2, cog_flex_t param3)
{
    int32_t v8; // ebp
    cog_flex_t v11; // st7
    cog_flex_t v12; // st7
    cog_flex_t v13; // [esp+10h] [ebp-Ch]
    int32_t v14; // [esp+14h] [ebp-8h]
    int32_t sourceTypea; // [esp+24h] [ebp+8h]

    v13 = 0.0;
    if ( sourceType )
    {
        v8 = sourceType->thingIdx;
        sourceTypea = SENDERTYPE_THING;
        v14 = 1 << sourceType->type;
    }
    else
    {
        v8 = -1;
        sourceTypea = 0;
        v14 = 1;
    }
    if ( &sithCog_aSectorLinks[sithCog_numSectorLinks] > sithCog_aSectorLinks )
    {
        for (int32_t i = 0; i < sithCog_numSectorLinks; i++)
        {
            SithCogSectorLink* link = &sithCog_aSectorLinks[i];
            if ( link->sector == a1 && (link->mask & v14) != 0 )
            {
                if ( message == SITH_MESSAGE_DAMAGED )
                {
                    v11 = sithCog_SendMessageEx(
                              link->cog,
                              SITH_MESSAGE_DAMAGED,
                              SENDERTYPE_SECTOR,
                              a1->id,
                              sourceTypea,
                              v8,
                              link->linkid,
                              param0,
                              param1,
                              param2,
                              param3);
                    if ( v11 == -9999.9873046875 )
                    {
                        v13 = param0;
                    }
                    else
                    {
                        v13 = v11;
                        param0 = v11;
                    }
                }
                else
                {
                    v12 = sithCog_SendMessageEx(link->cog, message, SENDERTYPE_SECTOR, a1->id, sourceTypea, v8, link->linkid, param0, param1, param2, param3);
                    if ( v12 != -9999.9873046875 )
                        v13 = v12 + v13;
                }
            }
        }
    }
    
    return v13;
}

void sithCog_BroadcastMessage(int32_t a1, int32_t a2, int32_t a3, int32_t a4, int32_t a5)
{
    sithCog_BroadcastMessageEx(a1, a2, a3, a4, a5, 0.0, 0.0, 0.0, 0.0);
}

void sithCog_BroadcastMessageEx(int32_t cmdid, int32_t senderType, int32_t senderIdx, int32_t sourceType, int32_t sourceIdx, cog_flex_t arg0, cog_flex_t arg1, cog_flex_t arg2, cog_flex_t arg3)
{
    sithCog *v9; // esi
    uint32_t i; // edi
    sithCog *v11; // esi
    uint32_t j; // edi

    if ( sithWorld_g_pStaticWorld )
    {
        v9 = sithWorld_g_pStaticWorld->cogs;
        for ( i = 0; i < sithWorld_g_pStaticWorld->numCogsLoaded; ++i )
            sithCog_SendMessageEx(v9++, cmdid, senderType, senderIdx, sourceType, sourceIdx, 0, arg0, arg1, arg2, arg3);
    }
    if ( sithWorld_g_pCurrentWorld )
    {
        v11 = sithWorld_g_pCurrentWorld->cogs;
        for ( j = 0; j < sithWorld_g_pCurrentWorld->numCogsLoaded; ++j )
            sithCog_SendMessageEx(v11++, cmdid, senderType, senderIdx, sourceType, sourceIdx, 0, arg0, arg1, arg2, arg3);
    }
}

void sithCog_SendMessage(sithCog *cog, int32_t msgid, int32_t senderType, int32_t senderIndex, int32_t sourceType, int32_t sourceIndex, int32_t linkId)
{
    SithCogScript *v7; // ebp
    uint32_t v10; // edi

    if (!cog)
        return;

    v7 = cog->cogscript;
    if (cog->flags & SITH_COG_DEBUG)
    {
#ifdef SITH_DEBUG_STRUCT_NAMES
        _sprintf(
            std_g_genBuffer,
            "Cog %s: Message %d delivered, senderType=%d, senderIndex=%d, sourceType=%d, sourceIndex=%d, linkId=%d.\n",
            cog->cogscript_fpath,
            msgid,
            senderType,
            senderIndex,
            sourceType,
            sourceIndex,
            linkId);
        sithConsole_PrintString(std_g_genBuffer);
#endif
    }

    if ( (cog->flags & SITH_COG_DISABLED) != 0 )
    {
        if ( (cog->flags & SITH_COG_DEBUG) != 0 )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_g_genBuffer, "Cog %s: Disabled, message ignored.\n", cog->cogscript_fpath);
            sithConsole_PrintString(std_g_genBuffer);
#endif
        }
        return;
    }

    for (v10 = 0; v10 < v7->num_triggers; v10++)
    {
        if ( msgid == v7->triggers[v10].trigId )
            break;
    }

    if ( v10 == v7->num_triggers )
    {
        if (cog->flags & SITH_COG_DEBUG)
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_g_genBuffer, "--Cog %s: Message %d received but ignored.  No handler.\n", cog->cogscript_fpath, msgid);
            sithConsole_PrintString(std_g_genBuffer);
#endif
        }
        return;
    }

    if ( (cog->flags & SITH_COG_PAUSED) != 0 )
    {
        if (cog->flags & SITH_COG_DEBUG)
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_g_genBuffer, "--Cog %s: Message %d received but COG is paused.\n", cog->cogscript_fpath, msgid);
            sithConsole_PrintString(std_g_genBuffer);
#endif
        }
        return;
    }

    // Added: Co-op
    if ((sithMulti_multiModeFlags & MULTIMODEFLAG_COOP) && msgid == SITH_MESSAGE_USER0 && sithCog_g_pMasterCog && cog->selfCog == sithCog_g_pMasterCog->selfCog && sithNet_isMulti)
    {
        // Send objectives to everyone
        //printf("Send objective to everyone\n");
        //if (param3 != 1234.0)
        sithDSSCog_SendMessage(
            cog,
            msgid,
            senderType,
            senderIndex,
            sourceType,
            sourceIndex,
            linkId,
            0.0,
            0.0,
            0.0,
            1234.0, // prevent infinite looping
            -1);

        goto execute;
    }

    // Added: Co-op, don't double-spawn drops
    if ((sithMulti_multiModeFlags & MULTIMODEFLAG_COOP) && msgid == SITH_MESSAGE_KILLED && sithNet_isMulti && !sithNet_isServer) {
        return;
    }
    
    if ( msgid == SITH_MESSAGE_STARTUP || msgid == SITH_MESSAGE_SHUTDOWN || !sithNet_isMulti || sithNet_isServer || (cog->flags & SITH_COG_LOCAL) != 0 )
    {
execute:
        cog->params[0] = 0.0;
        cog->senderId = linkId;
        cog->senderRef = senderIndex;
        cog->senderType = senderType;
        cog->sourceRef = sourceIndex;
        cog->sourceType = sourceType;
        cog->params[1] = 0.0;
        cog->params[2] = 0.0;
        cog->params[3] = 0.0;
        if ( (cog->flags & SITH_COG_DEBUG) != 0 )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_g_genBuffer, "--Cog %s: Message %d received and accepted for execution.\n", cog->cogscript_fpath, msgid);
            sithConsole_PrintString(std_g_genBuffer);
#endif
        }
        sithCogExec_ExecuteMessage(cog, v10);
    }
    else if ( msgid != SITH_MESSAGE_PULSE && msgid != SITH_MESSAGE_TIMER )
    {
        sithDSSCog_SendMessage(cog, msgid, senderType, senderIndex, sourceType, sourceIndex, linkId, 0.0, 0.0, 0.0, 0.0, sithNet_serverNetId);
    }
}

cog_flex_t sithCog_SendMessageEx(sithCog *cog, int32_t message, int32_t senderType, int32_t senderIndex, int32_t sourceType, int32_t sourceIndex, int32_t linkId, cog_flex_t param0, cog_flex_t param1, cog_flex_t param2, cog_flex_t param3)
{
    cog_flex_t result; // st7
    SithCogScript *v12; // ebp
    int32_t v13; // edx
    uint32_t trigIdxMax; // ecx
    uint32_t trigIdx; // edi
    sithCogTrigger *trig; // eax

    if ( !cog )
        return -9999.9873046875;
    v12 = cog->cogscript;
    if ( (cog->flags & SITH_COG_DEBUG) != 0 )
    {
#ifdef SITH_DEBUG_STRUCT_NAMES
        _sprintf(
            std_g_genBuffer,
            "Cog %s: MessageEx %d delivered, senderType=%d, senderIndex=%d, sourceType=%d, sourceIndex=%d, linkId=%d, param0=%g, param1=%g, param2=%g, param3=%g.\n",
            cog->cogscript_fpath,
            message,
            senderType,
            senderIndex,
            sourceType,
            sourceIndex,
            linkId,
            param0,
            param1,
            param2,
            param3);
        sithConsole_PrintString(std_g_genBuffer);
#endif
    }
    v13 = cog->flags;
    if ( (v13 & 2) != 0 )
    {
        if ( (v13 & 1) != 0 )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_g_genBuffer, "Cog %s: Disabled, MessageEx ignored.\n", cog->cogscript_fpath);
            sithConsole_PrintString(std_g_genBuffer);
#endif
            return -9999.9873046875;
        }
        return -9999.9873046875;
    }
    trigIdxMax = v12->num_triggers;
    trigIdx = 0;
    if ( trigIdxMax )
    {
        trig = v12->triggers;
        do
        {
            if ( message == trig->trigId )
                break;
            ++trigIdx;
            ++trig;
        }
        while ( trigIdx < trigIdxMax );
    }
    if ( trigIdx == trigIdxMax )
    {
        if ( (v13 & 1) != 0 )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_g_genBuffer, "--Cog %s: MessageEx %d received but ignored.  No handler.\n", cog->cogscript_fpath, message);
            sithConsole_PrintString(std_g_genBuffer);
#endif
        }
        return -9999.9873046875;
    }
    if ( (v13 & 0x10) != 0 )
    {
        if ( (v13 & 1) != 0 )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_g_genBuffer, "--Cog %s: MessageEx %d received but COG is paused.\n", cog->cogscript_fpath, message);
            sithConsole_PrintString(std_g_genBuffer);
#endif
        }
        return -9999.9873046875;
    }

    // Added: Co-op
    if ((sithMulti_multiModeFlags & MULTIMODEFLAG_COOP) && message == SITH_MESSAGE_USER0 && sithCog_g_pMasterCog && cog->selfCog == sithCog_g_pMasterCog->selfCog && sithNet_isMulti)
    {
        // Send objectives to everyone
        //printf("Send objective to everyone\n");
        if (param3 != 1234.0) {
            sithDSSCog_SendMessage(
                cog,
                message,
                senderType,
                senderIndex,
                sourceType,
                sourceIndex,
                linkId,
                param0,
                param1,
                param2,
                1234.0, // prevent infinite looping
                -1);
        }

        goto execute;
    }

    // Added: Co-op, don't double-spawn drops
    if ((sithMulti_multiModeFlags & MULTIMODEFLAG_COOP) && message == SITH_MESSAGE_KILLED && sithNet_isMulti && !sithNet_isServer) {
        return 0.0;
    }

    if ( message == SITH_MESSAGE_STARTUP || message == SITH_MESSAGE_SHUTDOWN || !sithNet_isMulti || sithNet_isServer || (v13 & 0x40) != 0 )
    {
execute:
        cog->senderId = linkId;
        cog->senderRef = senderIndex;
        cog->senderType = senderType;
        cog->sourceRef = sourceIndex;
        cog->sourceType = sourceType;
        cog->params[0] = param0;
        cog->params[1] = param1;
        cog->params[2] = param2;
        cog->params[3] = param3;
        cog->returnEx = -9999.9873046875;
        if ( (v13 & 1) != 0 )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_g_genBuffer, "--Cog %s: MessageEx %d received and accepted for execution.\n", cog->cogscript_fpath, message);
            sithConsole_PrintString(std_g_genBuffer);
#endif
        }
        sithCogExec_ExecuteMessage(cog, trigIdx);
        result = cog->returnEx;
    }
    else if ( message == SITH_MESSAGE_PULSE || message == SITH_MESSAGE_TIMER )
    {
        result = 0.0;
    }
    else
    {
        sithDSSCog_SendMessage(
            cog,
            message,
            senderType,
            senderIndex,
            sourceType,
            sourceIndex,
            linkId,
            param0,
            param1,
            param2,
            param3,
            sithNet_serverNetId);
        result = 0.0;
    }
    return result;
}

void sithCog_FreeWorldCogs(SithWorld *world)
{
    int32_t v2; // edi
    SithCogScript *v4; // esi
    uint32_t v5; // ebx
    uint32_t i; // ebx
    sithCog *v9; // esi

    if ( world->cogScripts )
    {
        for (int32_t i = 0; i < world->numCogScriptsLoaded; i++)
        {
            v4 = &world->cogScripts[i];
            sithCogParse_FreeSymbolTable(v4->pSymbolTable);
            for (v5 = 0; v5 < v4->numIdk; v5++)
            {
                if (v4->aIdk[v5].desc)
                {
                    SITH_FREE(v4->aIdk[v5].desc);
                    v4->aIdk[v5].desc = NULL;
                }
            }
#ifdef COG_DYNAMIC_IDK
            if (v4->aIdk)
                SITH_FREE(v4->aIdk);
            v4->aIdk = NULL;
#endif
#ifdef COG_DYNAMIC_TRIGGERS
            if (v4->triggers)
                SITH_FREE(v4->triggers);
            v4->triggers = NULL;
#endif
            if ( v4->script_program )
            {
                SITH_FREE(v4->script_program);
                v4->script_program = 0;
            }
#ifdef STDHASHTABLE_CRC32_KEYS
            stdHashtbl_FreeKeyCrc32(sithCog_g_pHashtable, v4->pathCrc);
#else
            stdHashtbl_Remove(sithCog_g_pHashtable, v4->cog_fpath);
#endif
        }
        SITH_FREE(world->cogScripts);
        world->cogScripts = 0;
        world->numCogScripts = 0;
        world->numCogScriptsLoaded = 0;
    }
    if ( world->cogs )
    {
        for (int32_t i = 0; i < world->numCogsLoaded; i++ )
        {
            v9 = &world->cogs[i];
            sithCogParse_FreeSymbolTable(v9->pSymbolTable);
#ifdef COG_HEAP_INIT_ARGS
            if ( v9->aInitArgs ) // Added: failed-load path can leave these live
            {
                SITH_FREE(v9->aInitArgs);
                v9->aInitArgs = NULL;
            }
#endif
            if ( v9->heap )
            {
                SITH_FREE(v9->heap);
                v9->numHeapVars = 0;
                v9->heap = NULL; // Added
            }
#ifdef COG_DYNAMIC_STACKS
            if (v9->stack) {
                SITH_FREE(v9->stack);
                v9->stack = NULL;
                v9->stackSize = 0;
            }
#endif
        }
        SITH_FREE(world->cogs);
        world->cogs = 0;
        world->numCogs = 0;
        world->numCogsLoaded = 0;
    }
}

void sithCog_UpdateThingTimer(SithThing *thing)
{
    if ( (thing->thingflags & SITH_TF_PULSE) != 0 && thing->pulse_end_ms <= sithTime_g_msecGameTime )
    {
        thing->pulse_end_ms = sithTime_g_msecGameTime + thing->pulse_ms;
        sithCog_ThingSendMessageEx(thing, 0, SITH_MESSAGE_PULSE, 0.0, 0.0, 0.0, 0.0);
    }
    if ( (thing->thingflags & SITH_TF_TIMER) != 0 && thing->timer <= sithTime_g_msecGameTime )
    {
        thing->thingflags &= ~SITH_TF_TIMER;
        sithCog_ThingSendMessageEx(thing, 0, SITH_MESSAGE_TIMER, 0.0, 0.0, 0.0, 0.0);
    }
}

// MOTS altered?
int sithCog_ReadCogScriptsListText(SithWorld *lvl, int a2)
{
    int32_t numCogScripts; // esi
    int32_t result; // eax
    SithCogScript *cogScripts; // edi
    char *v5; // esi
    SithWorld *v6; // edi
    uint32_t v7; // eax
    int32_t v8; // esi
    char cog_fpath[128]; // [esp+10h] [ebp-80h] BYREF

    // Added: ??
    v8 = 0;

    if ( a2 )
        return 0;
    stdConffile_ReadArgs();
    if ( _strcmp(stdConffile_g_entry.args[0].value, "world") || _strcmp(stdConffile_g_entry.args[1].value, "scripts") )
        return 0;
    numCogScripts = _atoi(stdConffile_g_entry.args[2].value);
    if ( !numCogScripts )
        return 1;
    cogScripts = (SithCogScript *)SITH_ALLOC(sizeof(SithCogScript) * numCogScripts);
    lvl->cogScripts = cogScripts;
    if ( cogScripts )
    {
        _memset(cogScripts, 0, sizeof(SithCogScript) * numCogScripts);
        lvl->numCogScripts = numCogScripts;
        lvl->numCogScriptsLoaded = 0;
        while ( stdConffile_ReadArgs() )
        {
            if ( !_strcmp(stdConffile_g_entry.args[0].value, "end") )
                break;
            if ( lvl->numCogScriptsLoaded < (unsigned int)lvl->numCogScripts )
            {
                if ( !stdConffile_g_entry.numArgs )
                    return 0;


                sithCog_LoadScript(stdConffile_g_entry.args[1].value, v8);
            }
        }
        result = 1;
    }
    else
    {
        stdPrintf(pSithHS->errorPrint, ".\\Cog\\sithCog.c", 843, "Memory alloc failure initializing COG scripts.\n", 0, 0, 0, 0);
        result = 0;
    }
    return result;
}

SithCogScript* sithCog_LoadScript(const char *pFpath, int32_t unk)
{
    SithCogScript *result; // eax
    uint32_t v4; // eax
    SithCogScript *v5; // edi
    char v6[128]; // [esp+8h] [ebp-80h] BYREF

    _sprintf(v6, "%s%c%s", "cog", '\\', pFpath);
    result = (SithCogScript *)stdHashtbl_Find(sithCog_g_pHashtable, pFpath);
    if ( !result )
    {
        v4 = sithWorld_g_pLastLoadedWorld->numCogScriptsLoaded;
        if ( v4 < sithWorld_g_pLastLoadedWorld->numCogScripts && (v5 = &sithWorld_g_pLastLoadedWorld->cogScripts[v4], sithCogParse_Load(v6, v5, unk)) )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            // The copies of names are load-bearing, SetKeyVal stores a reference
            stdHashtbl_Add(sithCog_g_pHashtable, v5->cog_fpath, v5);
#else
            stdHashtbl_Add(sithCog_g_pHashtable, pFpath, v5);
#endif
            ++sithWorld_g_pLastLoadedWorld->numCogScriptsLoaded;
            result = v5;
        }
        else
        {
            result = 0;
        }
    }
    return result;
}

void sithCog_RegisterFunction(SithCogSymbolTable *a1, cogSymbolFunc_t a2, const char *a3)
{
    SithCogSymbolValue a2a;

    SithCogSymbol* symbol = sithCogParse_AddSymbol(a1, a3);
    if ( symbol )
    {
        a2a.type = COG_TYPE_VERB;
        a2a.dataAsFunc = a2;
        sithCogParse_SetSymbolValue(symbol, &a2a);
    }
}

void sithCog_AddIntSymbol(SithCogSymbolTable *a1, int32_t a2, const char *a3)
{
    SithCogSymbolValue a2a; // [esp+0h] [ebp-10h] BYREF

    SithCogSymbol* v3 = sithCogParse_AddSymbol(a1, a3);
    if ( v3 )
    {
        a2a.type = COG_TYPE_INT;
        a2a.data[0] = a2;
        sithCogParse_SetSymbolValue(v3, &a2a);
    }
}

void sithCog_AddFloatSymbol(SithCogSymbolTable *a1, const char *a2, int32_t a3)
{
    SithCogSymbolValue a2a; // [esp+0h] [ebp-10h] BYREF

    SithCogSymbol* v3 = sithCogParse_AddSymbol(a1, a2);
    if ( v3 )
    {
        a2a.type = COG_TYPE_FLEX;
        a2a.data[0] = a3;
        sithCogParse_SetSymbolValue(v3, &a2a);
    }
}

void sithCog_ProcessCogs()
{
    if (g_sithMode == 2)
        return;

    for (uint32_t i = 0; i < sithWorld_g_pCurrentWorld->numCogsLoaded; i++)
    {
        sithCog_ProcessCog(&sithWorld_g_pCurrentWorld->cogs[i]);
    }

    if ( sithWorld_g_pStaticWorld )
    {
        for (uint32_t i = 0; i < sithWorld_g_pStaticWorld->numCogsLoaded; i++)
        {
            sithCog_ProcessCog(&sithWorld_g_pStaticWorld->cogs[i]);
        }
    }
}

void sithCog_ProcessCog(sithCog *cog)
{
    if (!(cog->flags & SITH_COG_DISABLED))
    {
        //printf("%x %x %x %s\n", cog->flags, sithTime_g_msecGameTime, cog->nextPulseMs, cog->cogscript_fpath);
        if ( (cog->flags & SITH_COG_PULSE_SET) && sithTime_g_msecGameTime >= cog->nextPulseMs )
        {
            cog->nextPulseMs = sithTime_g_msecGameTime + cog->pulsePeriodMs;
            sithCog_SendMessage(cog, SITH_MESSAGE_PULSE, 0, 0, 0, 0, 0);
        }

        if ( (cog->flags & SITH_COG_TIMER_SET) && sithTime_g_msecGameTime >= cog->field_20 )
        {
            cog->flags &= ~SITH_COG_TIMER_SET;
            cog->field_20 = 0;
            sithCog_SendMessage(cog, SITH_MESSAGE_TIMER, 0, 0, 0, 0, 0);
        }
        if ( cog->script_running == 2 )
        {
            if ( cog->wakeTimeMs >= sithTime_g_msecGameTime )
                return;
            if ((cog->flags & SITH_COG_DEBUG))
            {
#ifdef SITH_DEBUG_STRUCT_NAMES
                _sprintf(std_g_genBuffer, "Cog %s: Waking up due to timer elapse.\n", cog->cogscript_fpath);
                sithConsole_PrintString(std_g_genBuffer);
#endif
            }

            sithCogExec_Execute(cog);
            return;
        }
        if ( cog->script_running == 3 && (sithWorld_g_pCurrentWorld->things[cog->wakeTimeMs].trackParams.flags & 3) == 0 )
        {
            if ((cog->flags & SITH_COG_DEBUG))
            {
#ifdef SITH_DEBUG_STRUCT_NAMES
                _sprintf(std_g_genBuffer, "Cog %s: Waking up due to movement completion.\n", cog->cogscript_fpath);
                sithConsole_PrintString(std_g_genBuffer);
#endif
            }

            sithCogExec_Execute(cog);
            return;
        }
    }
}

int sithCog_TimerEventTask(int32_t deltaMs, SithEventParams *info)
{
    SithWorld *v2; // ecx
    int32_t v3; // eax
    sithCog *v4; // eax

    v2 = sithWorld_g_pCurrentWorld;
    v3 = info->cogIdx;
    if ( (v3 & 0x8000u) != 0 )
    {
        v2 = sithWorld_g_pStaticWorld;
        v3 &= ~0x8000u;
    }
    if ( v2 && v3 >= 0 && v3 < v2->numCogsLoaded )
        v4 = &v2->cogs[v3];
    else
        v4 = 0;
    if ( v4 )
        sithCog_SendMessageEx(v4, SITH_MESSAGE_TIMER, SENDERTYPE_COG, v4->selfCog, 0, 0, info->timerIdx, info->field_10, info->field_14, 0.0, 0.0);
    return 1;
}

// MOTS altered
int sithCog_CogStatus(stdDebugConsoleCmd *cmd, const char *extra)
{
    SithWorld *world; // esi
    sithCog *v3; // ebp
    SithCogSymbolTable *v4; // eax
    uint32_t v5; // ebx
    SithCogSymbol *v6; // esi
    const char *v7; // eax
    uint32_t tmp;

#ifdef SITH_DEBUG_STRUCT_NAMES
    world = sithWorld_g_pCurrentWorld;
    if ( sithWorld_g_pCurrentWorld
      && extra
      && _sscanf(extra, "%d", &tmp) == 1
      && tmp <= world->numCogsLoaded
      && (v3 = &world->cogs[tmp], v3->cogscript)
      && v3->pSymbolTable )
    {
        _sprintf(std_g_genBuffer, "Cog #%d: Name:%s  Script %s\n", tmp, v3->cogscript_fpath, v3->cogscript->cog_fpath);
        sithConsole_PrintString(std_g_genBuffer);
        v4 = v3->pSymbolTable;
        v5 = 0;
        v6 = v4->buckets;
        if ( v4->entry_cnt )
        {
            do
            {
#ifndef COG_CRC32_SYMBOL_NAMES
                v7 = v6->pName;
#else
                v7 = NULL;
#endif
                if ( !v7 )
                    v7 = "<null>";
                _sprintf(std_g_genBuffer, "  Symbol %d: '%s' ", v6->symbol_id, v7);
                if ( v6->val.type == 2 )
                    _sprintf(&std_g_genBuffer[_strlen(std_g_genBuffer)], " = %f\n", v6->val.dataAsFloat[0]);
                else
                    _sprintf(&std_g_genBuffer[_strlen(std_g_genBuffer)], " = %d\n", v6->val.data[0]);
                sithConsole_PrintString(std_g_genBuffer);
                ++v5;
                ++v6;
            }
            while ( v5 < v3->pSymbolTable->entry_cnt );
        }
    }
    else
    {
        sithConsole_PrintString("Error, bad parameters.\n");
    }
#endif
    return 1;
}

sithCog* sithCog_GetCogByIndex(int32_t idx)
{
    SithWorld *world; // ecx
    sithCog *result; // eax

    world = sithWorld_g_pCurrentWorld;
    if ( (idx & 0x8000) != 0 )
    {
        world = sithWorld_g_pStaticWorld;
        idx &= ~0x8000u;
    }

    if ( world && idx >= 0 && idx < world->numCogsLoaded )
        result = &world->cogs[idx];
    else
        result = NULL;

    return result;
}

void sithCog_FreeEntry(sithCog *cog)
{
    sithCogParse_FreeSymbolTable(cog->pSymbolTable);
    for (uint32_t i = 0; i < cog->cogscript->numIdk; i++)
    {
        if ( cog->cogscript->aIdk[i].desc )
        {
            SITH_FREE(cog->cogscript->aIdk[i].desc);
            cog->cogscript->aIdk[i].desc = NULL;
        }
    }
    if ( cog->heap )
    {
        SITH_FREE(cog->heap);
        cog->heap = NULL;
    }
}

void sithCog_FreeScriptEntry(SithCogScript *cogscript)
{
    sithCogParse_FreeSymbolTable(cogscript->pSymbolTable);
    if ( cogscript->script_program )
    {
        SITH_FREE(cogscript->script_program);
        cogscript->script_program = NULL;
    }
}

int sithCog_AllocWorldCogScripts(SithWorld *world, int num)
{
    SithCogScript *scripts = (SithCogScript *)SITH_ALLOC(num * sizeof(SithCogScript));
    world->cogScripts = scripts;
    if ( !scripts )
    {
        stdPrintf(pSithHS->errorPrint, ".\\Cog\\sithCog.c", 0x34B,
                  "Memory alloc failure initializing cog scripts.");
        return 0;
    }
    _memset(scripts, 0, num * sizeof(SithCogScript));
    world->numCogScripts = num;
    world->numCogScriptsLoaded = 0;
    return 1;
}

int sithCog_AllocWorldCogs(SithWorld *world, int num)
{
    sithCog *cogs;
    { TWL_EXTRAM_SUGGEST(pSithHS); // Added
    cogs = (sithCog *)SITH_ALLOC(num * sizeof(sithCog));
    TWL_EXTRAM_RESTORE(pSithHS); }
    world->cogs = cogs;
    if ( !cogs )
    {
        stdPrintf(pSithHS->errorPrint, ".\\Cog\\sithCog.c", 0x373,
                  "Memory alloc failure initializing cogs.");
        return 0;
    }
    stdPlatform_Memzero32(cogs, num * sizeof(sithCog)); // Added: word-safe
    world->numCogs = num;
    world->numCogsLoaded = 0;
    return 1;
}

int sithCog_LinkCogToThing(sithCog *cog, SithThing *thing, int linkId, int mask)
{
    int thingIdx = sithThing_ValidateThingPointer(thing);
    if ( !thingIdx || !thing->type )
        return 0;
    if ( linkId >= 0 )
    {
        thing->thingflags |= SITH_TF_CAPTURED;
        sithCog_aThingLinks[sithCog_numThingLinks].thing = thing;
        sithCog_aThingLinks[sithCog_numThingLinks].cog = cog;
        sithCog_aThingLinks[sithCog_numThingLinks].linkid = linkId;
        sithCog_aThingLinks[sithCog_numThingLinks].mask = mask;
        sithCog_aThingLinks[sithCog_numThingLinks].signature = thing->signature;
        sithCog_numThingLinks++;
    }
    return 1;
}

int sithCog_LinkCogToSurface(sithCog *cog, SithSurface *surface, int linkId, int mask)
{
    int surfIdx = sithSurface_ValidateSurfacePointer(surface);
    if ( !surfIdx )
        return 0;
    if ( linkId >= 0 )
    {
        surface->surfaceFlags |= SITH_SURFACE_COG_LINKED;
        sithCog_aSurfaceLinks[sithCog_numSurfaceLinks].surface = surface;
        sithCog_aSurfaceLinks[sithCog_numSurfaceLinks].cog = cog;
        sithCog_aSurfaceLinks[sithCog_numSurfaceLinks].linkid = linkId;
        sithCog_aSurfaceLinks[sithCog_numSurfaceLinks].mask = mask;
        sithCog_numSurfaceLinks++;
    }
    return 1;
}

int sithCog_LinkCogToSector(sithCog *cog, SithSector *sector, int linkId, int mask)
{
    int sectorIdx = sithSector_GetIdxFromPtr(sector);
    if ( !sectorIdx )
        return 0;
    if ( linkId >= 0 )
    {
        sector->flags |= SITH_SECTOR_COGLINKED;
        sithCog_aSectorLinks[sithCog_numSectorLinks].sector = sector;
        sithCog_aSectorLinks[sithCog_numSectorLinks].cog = cog;
        sithCog_aSectorLinks[sithCog_numSectorLinks].linkid = linkId;
        sithCog_aSectorLinks[sithCog_numSectorLinks].mask = mask;
        sithCog_numSectorLinks++;
    }
    return 1;
}
