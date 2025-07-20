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
#include "General/stdHashTable.h"
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

    sithCog_pSymbolTable = sithCogParse_NewSymboltable(SITHCOG_SYMBOL_LIMIT); // MOTS altered, DW altered, changed from 512 to 1024
    if (!sithCog_pSymbolTable )
    {
        stdPrintf(pSithHS->errorPrint, ".\\Cog\\sithCog.c", 118, "Could not allocate COG symboltable.");
        return 0;
    }
  
    sithCog_pScriptHashtable = stdHashTable_New(256);
    if (!sithCog_pScriptHashtable)
    {
        stdPrintf(pSithHS->errorPrint, ".\\Cog\\sithCog.c", 124, "Could not allocate COG hashtable.");
        return 0;
    }
    sithCog_pSymbolTable->bucket_idx = 0x100;
    sithCogFunction_Startup(sithCog_pSymbolTable);
    sithCogFunctionThing_Startup(sithCog_pSymbolTable);
    sithCogFunctionAI_Startup(sithCog_pSymbolTable);
    sithCogFunctionSurface_Startup(sithCog_pSymbolTable);
    sithCogFunctionSound_Startup(sithCog_pSymbolTable);
    sithCogFunctionSector_Startup(sithCog_pSymbolTable);
    sithCogFunctionPlayer_Startup(sithCog_pSymbolTable);
	sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 1, "activate");
	sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 1, "activated");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 3, "startup");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 4, "timer");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 5, "blocked");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 6, "entered");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 7, "exited");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 8, "crossed");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 9, "sighted");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 10, "damaged");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 11, "arrived");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 12, "killed");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 13, "pulse");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 14, "touched");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 15, "created");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 16, "loading");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 17, "selected");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 18, "deselected");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 20, "changed");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 21, "deactivated");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 22, "shutdown");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 23, "respawn");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 2, "removed");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 19, "autoselect");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 24, "aievent");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 25, "skill");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 26, "taken");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 27, "user0");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 28, "user1");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 29, "user2");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 30, "user3");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 31, "user4");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 32, "user5");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 33, "user6");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 34, "user7");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 35, "newplayer");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 36, "fire");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 37, "join");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 38, "leave");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 39, "splash");
    sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 40, "trigger");
    if (Main_bDwCompat) {
        sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 41, "laserhit");
        sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 42, "cut");
        sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 43, "injected");
        sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 44, "powerplug");
        sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 45, "welded");
        sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 46, "tugged");
        sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 48, "used");
        sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 47, "converse");
    }
    else if (Main_bMotsCompat) {
        sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 41, "preblock");
        sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 42, "escaped");
        sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 43, "attachkilled");
        sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 44, "playeraction");
    }
    sithCogScript_RegisterGlobalMessage(sithCog_pSymbolTable, "global0", 0);
    sithCogScript_RegisterGlobalMessage(sithCog_pSymbolTable, "global1", 0);
    sithCogScript_RegisterGlobalMessage(sithCog_pSymbolTable, "global2", 0);
    sithCogScript_RegisterGlobalMessage(sithCog_pSymbolTable, "global3", 0);
    sithCogScript_RegisterGlobalMessage(sithCog_pSymbolTable, "global4", 0);
    sithCogScript_RegisterGlobalMessage(sithCog_pSymbolTable, "global5", 0);
    sithCogScript_RegisterGlobalMessage(sithCog_pSymbolTable, "global6", 0);
    sithCogScript_RegisterGlobalMessage(sithCog_pSymbolTable, "global7", 0);
    sithCogScript_RegisterGlobalMessage(sithCog_pSymbolTable, "global8", 0);
    sithCogScript_RegisterGlobalMessage(sithCog_pSymbolTable, "global9", 0);
    sithCogScript_RegisterGlobalMessage(sithCog_pSymbolTable, "global10", 0);
    sithCogScript_RegisterGlobalMessage(sithCog_pSymbolTable, "global11", 0);
    sithCogScript_RegisterGlobalMessage(sithCog_pSymbolTable, "global12", 0);
    sithCogScript_RegisterGlobalMessage(sithCog_pSymbolTable, "global13", 0);
    sithCogScript_RegisterGlobalMessage(sithCog_pSymbolTable, "global14", 0);
    sithCogScript_RegisterGlobalMessage(sithCog_pSymbolTable, "global15", 0);
    sithEvent_RegisterFunc(4, sithCogScript_TimerTick, 0, 2);
    sithCog_bInitted = 1;
    return 1;
}

// Added: Register all new COG verbs last
int32_t sithCog_StartupEnhanced()
{
    if (!Main_bEnhancedCogVerbs) return 1;

    sithCogSymboltable* ctx = sithCog_pSymbolTable;

    // Generic
    if (!Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunction_Pow, "pow");
        sithCogScript_RegisterVerb(ctx, sithCogFunction_Wakeup, "wakeup");

        sithCogScript_RegisterVerb(ctx,sithCogFunction_VectorEqual,"vectorequal");

        sithCogScript_RegisterVerb(ctx,sithCogFunction_FireProjectileData,"fireprojectiledata");
        sithCogScript_RegisterVerb(ctx,sithCogFunction_FireProjectileLocal,"fireprojectilelocal");

        sithCogScript_RegisterVerb(ctx,sithCogFunction_GetWeaponBin,"getweaponbin");

        sithCogScript_RegisterVerb(ctx,sithCogFunction_SendMessageExRadius,"sendmessageexradius");

        sithCogScript_RegisterVerb(ctx,sithCogFunction_WorldFlash,"worldflash");

        sithCogScript_RegisterVerb(ctx,sithCogFunction_SetCameraZoom,"setcamerazoom");

        sithCogScript_RegisterVerb(ctx,sithCogFunction_GetActionCog,"getactioncog");
        sithCogScript_RegisterVerb(ctx,sithCogFunction_SetActionCog,"setactioncog");

        sithCogScript_RegisterVerb(ctx,sithCogFunction_Sin,"sin");
        sithCogScript_RegisterVerb(ctx,sithCogFunction_Cos,"cos");
        sithCogScript_RegisterVerb(ctx,sithCogFunction_Tan,"tan");
        sithCogScript_RegisterVerb(ctx,sithCogFunction_GetCogFlags,"getcogflags");
        sithCogScript_RegisterVerb(ctx,sithCogFunction_SetCogFlags,"setcogflags");
        sithCogScript_RegisterVerb(ctx,sithCogFunction_ClearCogFlags,"clearcogflags");
        sithCogScript_RegisterVerb(ctx,sithCogFunction_DebugBreak,"debugbreak");
        sithCogScript_RegisterVerb(ctx,sithCogFunction_GetSysDate,"getsysdate");
        sithCogScript_RegisterVerb(ctx,sithCogFunction_GetSysTime,"getsystime");
    }
    
    // Droidworks generic
    if (!Main_bDwCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunction_SetCameraFocii, "setcamerafocii");
    }

    // AI
    if (!Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_FirstThingInCone,"firstthingincone");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_NextThingInCone,"nextthingincone");
    }
    
#ifdef JKM_AI
    if (!Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_AIGetAlignment, "aigetalignment");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_AISetAlignment, "aisetalignment");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_AISetInterest, "aisetinterest");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_AIGetInterest, "aigetinterest");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_AISetDistractor, "aisetdistractor");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_AIAddAlignmentPriority, "aiaddalignmentpriority");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionAI_AIRemoveAlignmentPriority, "airemovealignmentpriority");
    
        //TODO: actor_rc.cog references a "AISetMoveTarget"?
    }
#endif

    // Player
    if (!Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionPlayer_KillPlayerQuietly, "killplayerquietly");
    }

    // Sector
    if (!Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx,sithCogFunctionSector_ChangeAllSectorsLight,"changeallsectorslight");
        sithCogScript_RegisterVerb(ctx,sithCogFunctionSector_FindSectorAtPos,"findsectoratpos");
        sithCogScript_RegisterVerb(ctx,sithCogFunctionSector_IsSphereInSector,"issphereinsector");
        sithCogScript_RegisterVerb(ctx,sithCogFunctionSector_GetSectorAmbientLight,"getsectorambientlight");
        sithCogScript_RegisterVerb(ctx,sithCogFunctionSector_SetSectorAmbientLight,"setsectorambientlight");
    }

    // Sound
    if (!Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionSound_PlaySoundThingLocal, "playsoundthinglocal");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionSound_PlaySoundPosLocal, "playsoundposlocal");
        
        sithCogScript_RegisterVerb(ctx,sithCogFunctionSound_PlaySoundThing,"playvoicething");
        sithCogScript_RegisterVerb(ctx,sithCogFunctionSound_PlaySoundPos,"playvoicepos");
        sithCogScript_RegisterVerb(ctx,sithCogFunctionSound_PlaySoundLocal,"playvoicelocal");
        sithCogScript_RegisterVerb(ctx,sithCogFunctionSound_PlaySoundGlobal,"playvoiceglobal");
    }

    // Surface
    if (!Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetSurfaceVertexLight, "getsurfacevertexlight");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SetSurfaceVertexLight, "setsurfacevertexlight");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_GetSurfaceVertexLightRGB, "getsurfacevertexlightrgb");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionSurface_SetSurfaceVertexLightRGB, "setsurfacevertexlightrgb");
    }

    // Thing
    
    if (!Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_CreateThingLocal, "createthinglocal");

        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_CreateThingAtPosOwner, "createthingatposowner");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_CreateThingAtPos, "createthingatposold");

        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingParent, "setthingparent");

        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingPosEx, "setthingposex");

        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingLvecPYR, "getthinglvecpyr");

        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetCurInvWeapon, "getcurinvweapon2");

        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetActorWeapon, "getactorweapon2");

        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingLookPYR, "setthinglookpyr");

        sithCogScript_RegisterVerb(ctx,sithCogFunctionThing_GetThingGUID,"getthingguid");
        sithCogScript_RegisterVerb(ctx,sithCogFunctionThing_GetGUIDThing,"getguidthing");

        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingMaxVelocity, "getthingmaxvelocity");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingMaxVelocity, "setthingmaxvelocity");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingMaxAngularVelocity, "getthingmaxangularvelocity");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingMaxAngularVelocity, "setthingmaxangularvelocity");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetActorHeadPYR, "getactorheadpyr");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetActorHeadPYR, "setactorheadpyr");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingJointAngle, "setthingjointangle");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetThingJointAngle, "getthingjointangle");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingMaxHeadPitch, "setthingmaxheadpitch");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetThingMinHeadPitch, "setthingminheadpitch");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_InterpolatePYR, "interpolatepyr");
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_SetWeaponTarget, "setweapontarget");

        // TODO: weap_eweb_m.cog references a "SetThingCollide" verb? Superceded by "SetThingCollideSize"?
        // TODO: exp_hrail.cog references a "GetUserData" verb? Superceded by "GetThingUserData"?
    }

    // Present in files, but registered?
    if (Main_bMotsCompat) {
        sithCogScript_RegisterVerb(ctx, sithCogFunctionThing_GetCurInvWeaponMots, "getcurinvweapon");
    }


    // JK
    if (!Main_bMotsCompat && !Main_bDwCompat) {
        sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 45, "enterbubble");
        sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 46, "exitbubble");
    }
    
    if (!Main_bMotsCompat) {
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_PrintUniVoice, "jkprintunivoice");

        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetSaberSideMat, "jkgetsabersidemat");

        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SyncForcePowers, "jksyncforcepowers");

        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_BeginCutscene,"jkbegincutscene");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_EndCutscene,"jkendcutscene");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_StartupCutscene,"jkstartupcutscene");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetMultiParam,"jkgetmultiparam");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_InsideLeia,"insideleia");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_CreateBubble,"jkcreatebubble");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_DestroyBubble,"jkdestroybubble");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetBubbleDistance,"jkgetbubbledistance");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_ThingInBubble,"jkthinginbubble");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetFirstBubble,"jkgetfirstbubble");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetNextBubble,"jkgetnextbubble");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetBubbleType,"jkgetbubbletype");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetBubbleRadius,"jkgetbubbleradius");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetBubbleType,"jksetbubbletype");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_SetBubbleRadius,"jksetbubbleradius");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_Screenshot,"jkscreenshot");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_GetOpenFrames,"jkgetopenframes");
    }
    
    if (!Main_bDwCompat) {
        // Added for droidwork tests
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_dwGetActivateBin, "dwGetActivateBin");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_stub1Args, "dwsetreftopic");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_addBeam, "addbeam");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_addLaser, "addlaser");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_removeLaser, "removelaser");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_getLaserId, "getlaserid");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_stub0Args, "dwFlashInventory");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_dwPlayCammySpeech, "dwplaycammyspeech");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_stub0Args, "dwfreezeplayer");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_stub0Args, "dwunfreezeplayer");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_stub2Args, "dwplaycharacterspeech");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCog_stub0Args, "dwcleardialog");
    }

    // JK13
    if (!Main_bMotsCompat && !Main_bDwCompat)
    {
        //sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 40, "trigger");
        sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 44, "playeraction");
        sithCogScript_RegisterMessageSymbol(sithCog_pSymbolTable, 47, "hotkey");

        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_GetThingAttachSurface, "getthingattachsurface");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_GetThingAttachThing, "getthingattachthing");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_GetCameraFov, "getcamerafov");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_GetCameraOffset, "getcameraoffset");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_SetCameraFov, "setcamerafov");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_SetCameraOffset, "setcameraoffset");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_Absolute, "absolute");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_Arccosine, "arccosine");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_Arcsine, "arcsine");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_Arctangent, "arctangent");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_Ceiling, "ceiling");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_Cosine, "cosine");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_Floor, "floor");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_Power, "power");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_Randomflex, "randomflex");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_Randomint, "randomint");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_Sine, "sine");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_Squareroot, "squareroot");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_GetHotkeyCog, "gethotkeycog");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_SetHotkeyCog, "sethotkeycog");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_IsAdjoin, "isadjoin");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_SetGameSpeed, "setgamespeed");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_GetThingHeadLvec, "getthingheadlvec");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_GetThingHeadPitch, "getthingheadpitch");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_GetThingHeadPYR, "getthingheadpyr");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_GetThingPYR, "getthingpyr");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_SetThingHeadPYR, "setthingheadpyr");
        //sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_SetThingPosEx, "setthingposex");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_SetThingPYR, "setthingpyr");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_SetThingLRUVecs, "setthingrluvecs");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_SetThingSector, "setthingsector");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_RestoreJoint, "restorejoint");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_GetThingAirDrag, "getthingairdrag");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_GetThingEyeOffset, "getthingeyeoffset");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_GetThingHeadPitchMax, "getthingheadpitchmax");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_GetThingHeadPitchMin, "getthingheadpitchmin");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_GetThingJumpSpeed, "getthingjumpspeed");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_SetThingAirDrag, "setthingairdrag");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_SetThingEyeOffset, "setthingeyeoffset");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_SetThingHeadPitchMinMax, "setthingheadpitchminmax");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_SetThingJumpSpeed, "setthingjumpspeed");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_SetThingMesh, "setthingmesh");
        //sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_SetThingParent, "setthingparent");
        sithCogScript_RegisterVerb(sithCog_pSymbolTable, jkCogExt_SetSaberFaceFlags, "jksetsaberfaceflags");
    }

    return 1;
}

void sithCog_Shutdown()
{
    sithCogParse_FreeSymboltable(sithCog_pSymbolTable);
    if ( sithCog_pScriptHashtable )
    {
        stdHashTable_Free(sithCog_pScriptHashtable);
        sithCog_pScriptHashtable = 0;
    }
    sithCogParse_Reset();
    sithCog_bInitted = 0;

    // Added: sithCogExec var clean reset
    sithCogExec_009d39b0 = 0;
    sithCogExec_pIdkMotsCtx = NULL;
    sithCog_pActionCog = NULL;
    sithCog_actionCogIdk = 0;
}

int32_t sithCog_Open()
{
    sithWorld *world; // ecx
    int32_t result; // eax
    sithCog *v2; // ebx
    sithCogReference *v3; // ebp
    sithCog *v5; // ebp
    sithCogReference *v6; // ebx
    char *v7; // esi
    sithCogSymbol *v8; // edx
    uint32_t v10; // [esp+4h] [ebp-14h]
    uint32_t v12; // [esp+8h] [ebp-10h]
    char *v13; // [esp+Ch] [ebp-Ch]
    sithCogSymbol *v14; // [esp+10h] [ebp-8h]
    sithWorld *world_; // [esp+14h] [ebp-4h]

    world = sithWorld_pCurrentWorld;
    world_ = sithWorld_pCurrentWorld;
    if ( sithCog_bOpened )
        return 0;
    if ( sithWorld_pStatic )
    {
        v2 = sithWorld_pStatic->cogs;
        for (int32_t i = 0; i < sithWorld_pStatic->numCogsLoaded; i++)
        {
            for (int32_t j = 0; j < v2->cogscript->numIdk; j++)
            {
                v3 = &v2->cogscript->aIdk[j];
                if ( _strlen(v3->value) )
                    sithCog_LoadEntry(&v2->pSymbolTable->buckets[v3->hash], v3, v3->value);
            }
            sithCog_SendMessage(v2++, SITH_MESSAGE_LOADING, 0, 0, 0, 0, 0);
            world = world_;
        }
    }
    sithCog* cogs = world->cogs;
    v12 = 0;
    if ( world->numCogsLoaded )
    {
        sithCogReference* idk = NULL;
        while ( 1 )
        {
            v10 = 0;
            v6 = cogs->cogscript->aIdk;
            if ( cogs->cogscript->numIdk )
                break;
LABEL_25:
            sithCog_SendMessage(cogs++, SITH_MESSAGE_LOADING, 0, 0, 0, 0, 0);
            if (++v12 >= world_->numCogsLoaded )
                goto LABEL_26;
        }

        v13 = cogs->field_4BC;
        while ( 1 )
        {
            idk = &cogs->cogscript->aIdk[v10];
            v8 = &cogs->pSymbolTable->buckets[idk->hash];
            v14 = v8;
            if ( (idk->flags & 1) != 0 )
            {
                if ( _strlen(idk->value) )
                    sithCog_LoadEntry(v8, v6, idk->value);
                goto LABEL_24;
            }
            else if ( _strlen(v13) ) {
                sithCog_LoadEntry(v8, v6, v13);
                v8 = v14;
            }
            else if ( _strlen(idk->value) )
            {
                sithCog_LoadEntry(v8, v6, idk->value);
                v8 = v14;
            }
            v13 += 32;
            sithCog_ThingsSectorsRegSymbolIdk(cogs, v6, v8);


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
        sithCog_SendMessageToAll(SITH_MESSAGE_SHUTDOWN, 0, 0, 0, 0, 0.0, 0.0, 0.0, 0.0);
        sithCog_numSectorLinks = 0;
        sithCog_numSurfaceLinks = 0;
        sithCog_numThingLinks = 0;
        sithCog_masterCog = 0;
        sithCog_pActionCog = NULL; // MOTS added
        sithCog_actionCogIdk = -1; // MOTS added
        sithCog_bOpened = 0;
    }
}

// MOTS altered?
int sithCog_Load(sithWorld *world, int a2)
{
    int32_t num_cogs; // esi
    int32_t result; // eax
    sithCog *cogs; // eax
    uint32_t v7; // eax
    int32_t *v8; // ebx
    sithCog *v9; // eax
    uint32_t v15; // eax
    sithCogSymboltable *cogscript_symboltable; // edx
    int32_t v17; // ecx
    sithCogScript *v18; // ebp
    char **v19; // edi
    char *v21; // esi
    uint32_t v22; // [esp+10h] [ebp-88h]
    uint32_t v23; // [esp+14h] [ebp-84h]
    char cog_fpath[32]; // [esp+18h] [ebp-80h] BYREF

    if ( a2 )
        return 0;
    stdConffile_ReadArgs();
    if ( _strcmp(stdConffile_entry.args[0].value, "world") || _strcmp(stdConffile_entry.args[1].value, "cogs") )
        return 0;
    num_cogs = _atoi(stdConffile_entry.args[2].value);
    if ( !num_cogs )
        return 1;
    cogs = (sithCog *)pSithHS->alloc(sizeof(sithCog) * num_cogs);
    world->cogs = cogs;
    if ( cogs )
    {
        _memset(cogs, 0, sizeof(sithCog) * num_cogs);
        world->numCogs = num_cogs;
        world->numCogsLoaded = 0;
        while ( stdConffile_ReadArgs() )
        {
            if ( !_strcmp(stdConffile_entry.args[0].value, "end") )
                break;
            if ( stdConffile_entry.numArgs < 2u )
                return 0;
            v9 = sithCog_LoadCogscript(stdConffile_entry.args[1].value);

            //printf("%s\n", stdConffile_entry.args[1].value);

            if ( v9 )
            {
                v18 = v9->cogscript;
                v23 = 0;
                v21 = &v9->field_4BC[0];
                v22 = 2;
                for (v23 = 0; v23 < v9->cogscript->numIdk; v23++)
                {
                    //printf("%s\n", stdConffile_entry.args[v22].value);
                    if ( (v18->aIdk[v23].flags & 1) == 0 && stdConffile_entry.numArgs > v22 )
                    {
                        stdString_SafeStrCopy(v21, stdConffile_entry.args[v22].value, 32);
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

sithCog* sithCog_LoadCogscript(const char *fpath)
{
    uint32_t cogIdx; // eax
    sithCogSymboltable *result; // eax
    sithCog *cog; // ebx
    sithCogScript *v7; // eax
    sithCogScript *v8; // esi
    uint32_t v9; // eax
    char cog_fpath[128]; // [esp+10h] [ebp-80h] BYREF

    cogIdx = sithWorld_pLoading->numCogsLoaded;
    if ( cogIdx >= sithWorld_pLoading->numCogs )
        return 0;

    cog = &sithWorld_pLoading->cogs[cogIdx];
    cog->selfCog = cogIdx;
    if (sithWorld_pLoading->level_type_maybe & 1)
    {
        cog->selfCog |= 0x8000;
    }
    _sprintf(cog_fpath, "%s%c%s", "cog", '\\', fpath);
    v7 = (sithCogScript *)stdHashTable_GetKeyVal(sithCog_pScriptHashtable, fpath);
    if ( v7 )
    {
        v8 = v7;
    }
    else
    {
        v9 = sithWorld_pLoading->numCogScriptsLoaded;
        if ( v9 < sithWorld_pLoading->numCogScripts && (v8 = &sithWorld_pLoading->cogScripts[v9], sithCogParse_Load(cog_fpath, v8, 0)) )
        {
            stdHashTable_SetKeyVal(sithCog_pScriptHashtable, cog_fpath, v8); // Added: v8 -> no v8 for cog_fpath
            ++sithWorld_pLoading->numCogScriptsLoaded;
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
    cog->pSymbolTable = sithCogParse_CopySymboltable(v8->pSymbolTable);
    if ( cog->pSymbolTable )
    {
        sithWorld_pLoading->numCogsLoaded++;
        return cog;
    }
    return NULL;
}

int32_t sithCog_LoadEntry(sithCogSymbol *cogSymbol, sithCogReference *cogIdk, char *val)
{
    sithCogSymbol *v5; // esi
    sithCogSymbol *v7; // ecx
    sithCogSymbol *v9; // esi
    rdMaterial *v10; // eax
    sithSound *v12; // eax
    sithThing *v14; // eax
    rdModel3 *v15; // eax
    rdKeyframe *v17; // eax
    sithAIClass *v19; // eax

    switch ( cogIdk->type )
    {
        case COG_TYPE_FLEX:
            cogSymbol->val.type = COG_VARTYPE_FLEX;
            cogSymbol->val.dataAsFloat[0] = _atof(val); // FLEXTODO
            return 1;

        case COG_TYPE_TEMPLATE:
            cogSymbol->val.type = COG_VARTYPE_INT;
            v14 = sithTemplate_GetEntryByName(val);
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
                v17->id = (v17 - sithWorld_pCurrentWorld->keyframes) & 0xFFFF;
                if (v17->id >= 0x8000)
                {
                    v17->id = (v17 - sithWorld_pStatic->keyframes) | 0x8000;
                }
            }

            cogSymbol->val.data[0] = v17->id;
            return 1;
        case COG_TYPE_SOUND:
            cogSymbol->val.type = COG_VARTYPE_INT;
            v12 = sithSound_LoadEntry(val, 0);
            if ( !v12 )
            {
                cogSymbol->val.data[0] = -1;
                return 0;
            }
            cogSymbol->val.data[0] = v12->id;
            return 1;
        case COG_TYPE_MATERIAL:
            cogSymbol->val.type = COG_VARTYPE_INT;
            v10 = sithMaterial_LoadEntry(val, 0, 0);
            if ( !v10 )
            {
                cogSymbol->val.data[0] = -1;
                return 0;
            }
            cogSymbol->val.data[0] = v10->id;
            return 1;
        case COG_TYPE_VECTOR:
            cogSymbol->val.type = COG_VARTYPE_VECTOR;
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
            break;

        case COG_TYPE_MODEL:
            cogSymbol->val.type = COG_VARTYPE_INT;
            v15 = sithModel_LoadEntry(val, 1);
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

int32_t sithCog_ThingsSectorsRegSymbolIdk(sithCog *cog, sithCogReference *idk, sithCogSymbol *symbol)
{
    cog_int_t v3; // eax
    int32_t v5; // ebx
    int32_t v6; // edi
    sithSurface *v7; // esi
    int32_t v8; // eax
    int32_t v10; // eax
    int32_t v11; // ebx
    int32_t v12; // edi
    sithSector *v13; // esi
    int32_t v17; // ebx
    int32_t v18; // edi
    sithThing *v19; // esi

    v3 = symbol->val.data[0];
    if ( v3 < 0 )
        return 0;
    switch ( idk->type )
    {
        case 3:
            if ( v3 >= sithWorld_pCurrentWorld->numThingsLoaded )
                return 0;
            v17 = idk->mask;
            v18 = idk->linkid;
            v19 = &sithWorld_pCurrentWorld->things[v3];
            //printf("OpenJKDF2: Linking thing %x to cog `%s`? %x %x %x\n", v3, cog->cogscript_fpath, sithThing_GetIdxFromThing(v19), v19->type, idk->linkid);
            if ( sithThing_GetIdxFromThing(v19) && v19->type && v18 >= 0 )
            {
                //printf("OpenJKDF2: Linked thing `%s` to cog `%s`\n", v19->template_name, cog->cogscript_fpath);
                v19->thingflags |= SITH_TF_CAPTURED;
                sithCog_aThingLinks[sithCog_numThingLinks].thing = v19;
                sithCog_aThingLinks[sithCog_numThingLinks].cog = cog;
                sithCog_aThingLinks[sithCog_numThingLinks].linkid = v18;
                sithCog_aThingLinks[sithCog_numThingLinks].mask = v17;
                sithCog_aThingLinks[sithCog_numThingLinks].signature = v19->signature;
                sithCog_numThingLinks++;
            }
            break;
        case 5:
            if ( v3 >= sithWorld_pCurrentWorld->numSectors )
                return 0;
            v11 = idk->mask;
            v12 = idk->linkid;
            v13 = &sithWorld_pCurrentWorld->sectors[v3];
            if ( sithSector_GetIdxFromPtr(v13) && v12 >= 0 )
            {
                v13->flags |= SITH_SECTOR_COGLINKED;
                sithCog_aSectorLinks[sithCog_numSectorLinks].sector = v13;
                sithCog_aSectorLinks[sithCog_numSectorLinks].cog = cog;
                sithCog_aSectorLinks[sithCog_numSectorLinks].linkid = v12;
                sithCog_aSectorLinks[sithCog_numSectorLinks].mask = v11;
                sithCog_numSectorLinks++;
                return 1;
            }
            break;
        case 6:
            if ( v3 >= sithWorld_pCurrentWorld->numSurfaces )
                return 0;
            v5 = idk->mask;
            v6 = idk->linkid;
            v7 = &sithWorld_pCurrentWorld->surfaces[v3];
            if ( sithSurface_GetIdxFromPtr(v7) )
            {
                if ( v6 >= 0 )
                {
                    v7->surfaceFlags |= SITH_SURFACE_COG_LINKED;
                    v10 = sithCog_numSurfaceLinks;
                    sithCog_aSurfaceLinks[v10].surface = v7;
                    sithCog_aSurfaceLinks[v10].cog = cog;
                    sithCog_aSurfaceLinks[v10].linkid = v6;
                    sithCog_aSurfaceLinks[v10].mask = v5;
                    sithCog_numSurfaceLinks++;
                    return 1;
                }
            }
            break;
    }
    return 1;
}

void sithCog_SendMessageFromThing(sithThing *a1, sithThing *a2, int32_t msg)
{
    sithCog_SendMessageFromThingEx(a1, a2, msg, 0.0, 0.0, 0.0, 0.0);
}

cog_flex_t sithCog_SendMessageFromThingEx(sithThing *sender, sithThing *receiver, SITH_MESSAGE message, cog_flex_t param0, cog_flex_t param1, cog_flex_t param2, cog_flex_t param3)
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
        if (receiver == sithPlayer_pLocalPlayerThing && message == SITH_MESSAGE_ACTIVATE) {
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
        if (receiver == sithPlayer_pLocalPlayerThing && message == SITH_MESSAGE_ACTIVATE) {
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
        sithCogThingLink* v15 = &sithCog_aThingLinks[i];
        if ( v15->thing == sender && v15->signature == sender->signature && (receivera & v15->mask) != 0 )
        {
#ifdef DEBUG_QOL_CHEATS
            if (receiver == sithPlayer_pLocalPlayerThing &&message == SITH_MESSAGE_ACTIVATE && v15->cog) {
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

void sithCog_SendMessageFromSurface(sithSurface *surface, sithThing *thing, int32_t msg)
{
    sithCog_SendMessageFromSurfaceEx(surface, thing, msg, 0.0, 0.0, 0.0, 0.0);
}

cog_flex_t sithCog_SendMessageFromSurfaceEx(sithSurface *sender, sithThing *thing, SITH_MESSAGE msg, cog_flex_t a4, cog_flex_t a5, cog_flex_t a6, cog_flex_t a7)
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
        sithCogSurfaceLink* surfaceLink = &sithCog_aSurfaceLinks[i];
        if ( surfaceLink->surface == sender && (surfaceLink->mask & v15) != 0 )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            if (thing == sithPlayer_pLocalPlayerThing && msg == SITH_MESSAGE_ACTIVATE) {
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

void sithCog_SendMessageFromSector(sithSector *sector, sithThing *thing, int32_t message)
{
    sithCog_SendMessageFromSectorEx(sector, thing, message, 0.0, 0.0, 0.0, 0.0);
}

cog_flex_t sithCog_SendMessageFromSectorEx(sithSector *a1, sithThing *sourceType, SITH_MESSAGE message, cog_flex_t param0, cog_flex_t param1, cog_flex_t param2, cog_flex_t param3)
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
            sithCogSectorLink* link = &sithCog_aSectorLinks[i];
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

void sithCog_SendSimpleMessageToAll(int32_t a1, int32_t a2, int32_t a3, int32_t a4, int32_t a5)
{
    sithCog_SendMessageToAll(a1, a2, a3, a4, a5, 0.0, 0.0, 0.0, 0.0);
}

void sithCog_SendMessageToAll(int32_t cmdid, int32_t senderType, int32_t senderIdx, int32_t sourceType, int32_t sourceIdx, cog_flex_t arg0, cog_flex_t arg1, cog_flex_t arg2, cog_flex_t arg3)
{
    sithCog *v9; // esi
    uint32_t i; // edi
    sithCog *v11; // esi
    uint32_t j; // edi

    if ( sithWorld_pStatic )
    {
        v9 = sithWorld_pStatic->cogs;
        for ( i = 0; i < sithWorld_pStatic->numCogsLoaded; ++i )
            sithCog_SendMessageEx(v9++, cmdid, senderType, senderIdx, sourceType, sourceIdx, 0, arg0, arg1, arg2, arg3);
    }
    if ( sithWorld_pCurrentWorld )
    {
        v11 = sithWorld_pCurrentWorld->cogs;
        for ( j = 0; j < sithWorld_pCurrentWorld->numCogsLoaded; ++j )
            sithCog_SendMessageEx(v11++, cmdid, senderType, senderIdx, sourceType, sourceIdx, 0, arg0, arg1, arg2, arg3);
    }
}

void sithCog_SendMessage(sithCog *cog, int32_t msgid, int32_t senderType, int32_t senderIndex, int32_t sourceType, int32_t sourceIndex, int32_t linkId)
{
    sithCogScript *v7; // ebp
    uint32_t v10; // edi

    if (!cog)
        return;

    v7 = cog->cogscript;
    if (cog->flags & SITH_COG_DEBUG)
    {
#ifdef SITH_DEBUG_STRUCT_NAMES
        _sprintf(
            std_genBuffer,
            "Cog %s: Message %d delivered, senderType=%d, senderIndex=%d, sourceType=%d, sourceIndex=%d, linkId=%d.\n",
            cog->cogscript_fpath,
            msgid,
            senderType,
            senderIndex,
            sourceType,
            sourceIndex,
            linkId);
        sithConsole_Print(std_genBuffer);
#endif
    }

    if ( (cog->flags & SITH_COG_DISABLED) != 0 )
    {
        if ( (cog->flags & SITH_COG_DEBUG) != 0 )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_genBuffer, "Cog %s: Disabled, message ignored.\n", cog->cogscript_fpath);
            sithConsole_Print(std_genBuffer);
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
            _sprintf(std_genBuffer, "--Cog %s: Message %d received but ignored.  No handler.\n", cog->cogscript_fpath, msgid);
            sithConsole_Print(std_genBuffer);
#endif
        }
        return;
    }

    if ( (cog->flags & SITH_COG_PAUSED) != 0 )
    {
        if (cog->flags & SITH_COG_DEBUG)
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_genBuffer, "--Cog %s: Message %d received but COG is paused.\n", cog->cogscript_fpath, msgid);
            sithConsole_Print(std_genBuffer);
#endif
        }
        return;
    }

    // Added: Co-op
    if ((sithMulti_multiModeFlags & MULTIMODEFLAG_COOP) && msgid == SITH_MESSAGE_USER0 && sithCog_masterCog && cog->selfCog == sithCog_masterCog->selfCog && sithNet_isMulti)
    {
        // Send objectives to everyone
        //printf("Send objective to everyone\n");
        //if (param3 != 1234.0)
        sithDSSCog_SendSendTrigger(
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
            _sprintf(std_genBuffer, "--Cog %s: Message %d received and accepted for execution.\n", cog->cogscript_fpath, msgid);
            sithConsole_Print(std_genBuffer);
#endif
        }
        sithCogExec_ExecCog(cog, v10);
    }
    else if ( msgid != SITH_MESSAGE_PULSE && msgid != SITH_MESSAGE_TIMER )
    {
        sithDSSCog_SendSendTrigger(cog, msgid, senderType, senderIndex, sourceType, sourceIndex, linkId, 0.0, 0.0, 0.0, 0.0, sithNet_serverNetId);
    }
}

cog_flex_t sithCog_SendMessageEx(sithCog *cog, int32_t message, int32_t senderType, int32_t senderIndex, int32_t sourceType, int32_t sourceIndex, int32_t linkId, cog_flex_t param0, cog_flex_t param1, cog_flex_t param2, cog_flex_t param3)
{
    cog_flex_t result; // st7
    sithCogScript *v12; // ebp
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
            std_genBuffer,
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
        sithConsole_Print(std_genBuffer);
#endif
    }
    v13 = cog->flags;
    if ( (v13 & 2) != 0 )
    {
        if ( (v13 & 1) != 0 )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_genBuffer, "Cog %s: Disabled, MessageEx ignored.\n", cog->cogscript_fpath);
            sithConsole_Print(std_genBuffer);
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
            _sprintf(std_genBuffer, "--Cog %s: MessageEx %d received but ignored.  No handler.\n", cog->cogscript_fpath, message);
            sithConsole_Print(std_genBuffer);
#endif
        }
        return -9999.9873046875;
    }
    if ( (v13 & 0x10) != 0 )
    {
        if ( (v13 & 1) != 0 )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            _sprintf(std_genBuffer, "--Cog %s: MessageEx %d received but COG is paused.\n", cog->cogscript_fpath, message);
            sithConsole_Print(std_genBuffer);
#endif
        }
        return -9999.9873046875;
    }

    // Added: Co-op
    if ((sithMulti_multiModeFlags & MULTIMODEFLAG_COOP) && message == SITH_MESSAGE_USER0 && sithCog_masterCog && cog->selfCog == sithCog_masterCog->selfCog && sithNet_isMulti)
    {
        // Send objectives to everyone
        //printf("Send objective to everyone\n");
        if (param3 != 1234.0) {
            sithDSSCog_SendSendTrigger(
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
            _sprintf(std_genBuffer, "--Cog %s: MessageEx %d received and accepted for execution.\n", cog->cogscript_fpath, message);
            sithConsole_Print(std_genBuffer);
#endif
        }
        sithCogExec_ExecCog(cog, trigIdx);
        result = cog->returnEx;
    }
    else if ( message == SITH_MESSAGE_PULSE || message == SITH_MESSAGE_TIMER )
    {
        result = 0.0;
    }
    else
    {
        sithDSSCog_SendSendTrigger(
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

void sithCog_Free(sithWorld *world)
{
    int32_t v2; // edi
    sithCogScript *v4; // esi
    uint32_t v5; // ebx
    uint32_t i; // ebx
    sithCog *v9; // esi

    if ( world->cogScripts )
    {
        for (int32_t i = 0; i < world->numCogScriptsLoaded; i++)
        {
            v4 = &world->cogScripts[i];
            sithCogParse_FreeSymboltable(v4->pSymbolTable);
            for (v5 = 0; v5 < v4->numIdk; v5++)
            {
                if (v4->aIdk[v5].desc)
                {
                    pSithHS->free(v4->aIdk[v5].desc);
                    v4->aIdk[v5].desc = NULL;
                }
            }
#ifdef COG_DYNAMIC_IDK
            if (v4->aIdk)
                pSithHS->free(v4->aIdk);
            v4->aIdk = NULL;
#endif
#ifdef COG_DYNAMIC_TRIGGERS
            if (v4->triggers)
                pSithHS->free(v4->triggers);
            v4->triggers = NULL;
#endif
            if ( v4->script_program )
            {
                pSithHS->free(v4->script_program);
                v4->script_program = 0;
            }
#ifdef STDHASHTABLE_CRC32_KEYS
            stdHashTable_FreeKeyCrc32(sithCog_pScriptHashtable, v4->pathCrc);
#else
            stdHashTable_FreeKey(sithCog_pScriptHashtable, v4->cog_fpath);
#endif
        }
        pSithHS->free(world->cogScripts);
        world->cogScripts = 0;
        world->numCogScripts = 0;
        world->numCogScriptsLoaded = 0;
    }
    if ( world->cogs )
    {
        for (int32_t i = 0; i < world->numCogsLoaded; i++ )
        {
            v9 = &world->cogs[i];
            sithCogParse_FreeSymboltable(v9->pSymbolTable);
            if ( v9->heap )
            {
                pSithHS->free(v9->heap);
                v9->numHeapVars = 0;
                v9->heap = NULL; // Added
            }
#ifdef COG_DYNAMIC_STACKS
            if (v9->stack) {
                pSithHS->free(v9->stack);
                v9->stack = NULL;
                v9->stackSize = 0;
            }
#endif
        }
        pSithHS->free(world->cogs);
        world->cogs = 0;
        world->numCogs = 0;
        world->numCogsLoaded = 0;
    }
}

void sithCog_HandleThingTimerPulse(sithThing *thing)
{
    if ( (thing->thingflags & SITH_TF_PULSE) != 0 && thing->pulse_end_ms <= sithTime_curMs )
    {
        thing->pulse_end_ms = sithTime_curMs + thing->pulse_ms;
        sithCog_SendMessageFromThingEx(thing, 0, SITH_MESSAGE_PULSE, 0.0, 0.0, 0.0, 0.0);
    }
    if ( (thing->thingflags & SITH_TF_TIMER) != 0 && thing->timer <= sithTime_curMs )
    {
        thing->thingflags &= ~SITH_TF_TIMER;
        sithCog_SendMessageFromThingEx(thing, 0, SITH_MESSAGE_TIMER, 0.0, 0.0, 0.0, 0.0);
    }
}

// MOTS altered?
int sithCogScript_Load(sithWorld *lvl, int a2)
{
    int32_t numCogScripts; // esi
    int32_t result; // eax
    sithCogScript *cogScripts; // edi
    char *v5; // esi
    sithWorld *v6; // edi
    uint32_t v7; // eax
    int32_t v8; // esi
    char cog_fpath[128]; // [esp+10h] [ebp-80h] BYREF

    // Added: ??
    v8 = 0;

    if ( a2 )
        return 0;
    stdConffile_ReadArgs();
    if ( _strcmp(stdConffile_entry.args[0].value, "world") || _strcmp(stdConffile_entry.args[1].value, "scripts") )
        return 0;
    numCogScripts = _atoi(stdConffile_entry.args[2].value);
    if ( !numCogScripts )
        return 1;
    cogScripts = (sithCogScript *)pSithHS->alloc(sizeof(sithCogScript) * numCogScripts);
    lvl->cogScripts = cogScripts;
    if ( cogScripts )
    {
        _memset(cogScripts, 0, sizeof(sithCogScript) * numCogScripts);
        lvl->numCogScripts = numCogScripts;
        lvl->numCogScriptsLoaded = 0;
        while ( stdConffile_ReadArgs() )
        {
            if ( !_strcmp(stdConffile_entry.args[0].value, "end") )
                break;
            if ( lvl->numCogScriptsLoaded < (unsigned int)lvl->numCogScripts )
            {
                if ( !stdConffile_entry.numArgs )
                    return 0;


                sithCogScript_LoadEntry(stdConffile_entry.args[1].value, v8);
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

sithCogScript* sithCogScript_LoadEntry(const char *pFpath, int32_t unk)
{
    sithCogScript *result; // eax
    uint32_t v4; // eax
    sithCogScript *v5; // edi
    char v6[128]; // [esp+8h] [ebp-80h] BYREF

    _sprintf(v6, "%s%c%s", "cog", '\\', pFpath);
    result = (sithCogScript *)stdHashTable_GetKeyVal(sithCog_pScriptHashtable, pFpath);
    if ( !result )
    {
        v4 = sithWorld_pLoading->numCogScriptsLoaded;
        if ( v4 < sithWorld_pLoading->numCogScripts && (v5 = &sithWorld_pLoading->cogScripts[v4], sithCogParse_Load(v6, v5, unk)) )
        {
#ifdef SITH_DEBUG_STRUCT_NAMES
            // The copies of names are load-bearing, SetKeyVal stores a reference
            stdHashTable_SetKeyVal(sithCog_pScriptHashtable, v5->cog_fpath, v5);
#else
            stdHashTable_SetKeyVal(sithCog_pScriptHashtable, pFpath, v5);
#endif
            ++sithWorld_pLoading->numCogScriptsLoaded;
            result = v5;
        }
        else
        {
            result = 0;
        }
    }
    return result;
}

void sithCogScript_RegisterVerb(sithCogSymboltable *a1, cogSymbolFunc_t a2, const char *a3)
{
    sithCogStackvar a2a;

    sithCogSymbol* symbol = sithCogParse_AddSymbol(a1, a3);
    if ( symbol )
    {
        a2a.type = COG_TYPE_VERB;
        a2a.dataAsFunc = a2;
        sithCogParse_SetSymbolVal(symbol, &a2a);
    }
}

void sithCogScript_RegisterMessageSymbol(sithCogSymboltable *a1, int32_t a2, const char *a3)
{
    sithCogStackvar a2a; // [esp+0h] [ebp-10h] BYREF

    sithCogSymbol* v3 = sithCogParse_AddSymbol(a1, a3);
    if ( v3 )
    {
        a2a.type = COG_TYPE_INT;
        a2a.data[0] = a2;
        sithCogParse_SetSymbolVal(v3, &a2a);
    }
}

void sithCogScript_RegisterGlobalMessage(sithCogSymboltable *a1, const char *a2, int32_t a3)
{
    sithCogStackvar a2a; // [esp+0h] [ebp-10h] BYREF

    sithCogSymbol* v3 = sithCogParse_AddSymbol(a1, a2);
    if ( v3 )
    {
        a2a.type = COG_TYPE_FLEX;
        a2a.data[0] = a3;
        sithCogParse_SetSymbolVal(v3, &a2a);
    }
}

void sithCogScript_TickAll()
{
    if (g_sithMode == 2)
        return;

    for (uint32_t i = 0; i < sithWorld_pCurrentWorld->numCogsLoaded; i++)
    {
        sithCogScript_Tick(&sithWorld_pCurrentWorld->cogs[i]);
    }

    if ( sithWorld_pStatic )
    {
        for (uint32_t i = 0; i < sithWorld_pStatic->numCogsLoaded; i++)
        {
            sithCogScript_Tick(&sithWorld_pStatic->cogs[i]);
        }
    }
}

void sithCogScript_Tick(sithCog *cog)
{
    if (!(cog->flags & SITH_COG_DISABLED))
    {
        //printf("%x %x %x %s\n", cog->flags, sithTime_curMs, cog->nextPulseMs, cog->cogscript_fpath);
        if ( (cog->flags & SITH_COG_PULSE_SET) && sithTime_curMs >= cog->nextPulseMs )
        {
            cog->nextPulseMs = sithTime_curMs + cog->pulsePeriodMs;
            sithCog_SendMessage(cog, SITH_MESSAGE_PULSE, 0, 0, 0, 0, 0);
        }

        if ( (cog->flags & SITH_COG_TIMER_SET) && sithTime_curMs >= cog->field_20 )
        {
            cog->flags &= ~SITH_COG_TIMER_SET;
            cog->field_20 = 0;
            sithCog_SendMessage(cog, SITH_MESSAGE_TIMER, 0, 0, 0, 0, 0);
        }
        if ( cog->script_running == 2 )
        {
            if ( cog->wakeTimeMs >= sithTime_curMs )
                return;
            if ((cog->flags & SITH_COG_DEBUG))
            {
#ifdef SITH_DEBUG_STRUCT_NAMES
                _sprintf(std_genBuffer, "Cog %s: Waking up due to timer elapse.\n", cog->cogscript_fpath);
                sithConsole_Print(std_genBuffer);
#endif
            }

            sithCogExec_Exec(cog);
            return;
        }
        if ( cog->script_running == 3 && (sithWorld_pCurrentWorld->things[cog->wakeTimeMs].trackParams.flags & 3) == 0 )
        {
            if ((cog->flags & SITH_COG_DEBUG))
            {
#ifdef SITH_DEBUG_STRUCT_NAMES
                _sprintf(std_genBuffer, "Cog %s: Waking up due to movement completion.\n", cog->cogscript_fpath);
                sithConsole_Print(std_genBuffer);
#endif
            }

            sithCogExec_Exec(cog);
            return;
        }
    }
}

int sithCogScript_TimerTick(int32_t deltaMs, sithEventInfo *info)
{
    sithWorld *v2; // ecx
    int32_t v3; // eax
    sithCog *v4; // eax

    v2 = sithWorld_pCurrentWorld;
    v3 = info->cogIdx;
    if ( (v3 & 0x8000u) != 0 )
    {
        v2 = sithWorld_pStatic;
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
int sithCogScript_DevCmdCogStatus(stdDebugConsoleCmd *cmd, const char *extra)
{
    sithWorld *world; // esi
    sithCog *v3; // ebp
    sithCogSymboltable *v4; // eax
    uint32_t v5; // ebx
    sithCogSymbol *v6; // esi
    const char *v7; // eax
    uint32_t tmp;

#ifdef SITH_DEBUG_STRUCT_NAMES
    world = sithWorld_pCurrentWorld;
    if ( sithWorld_pCurrentWorld
      && extra
      && _sscanf(extra, "%d", &tmp) == 1
      && tmp <= world->numCogsLoaded
      && (v3 = &world->cogs[tmp], v3->cogscript)
      && v3->pSymbolTable )
    {
        _sprintf(std_genBuffer, "Cog #%d: Name:%s  Script %s\n", tmp, v3->cogscript_fpath, v3->cogscript->cog_fpath);
        sithConsole_Print(std_genBuffer);
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
                _sprintf(std_genBuffer, "  Symbol %d: '%s' ", v6->symbol_id, v7);
                if ( v6->val.type == 2 )
                    _sprintf(&std_genBuffer[_strlen(std_genBuffer)], " = %f\n", v6->val.dataAsFloat[0]);
                else
                    _sprintf(&std_genBuffer[_strlen(std_genBuffer)], " = %d\n", v6->val.data[0]);
                sithConsole_Print(std_genBuffer);
                ++v5;
                ++v6;
            }
            while ( v5 < v3->pSymbolTable->entry_cnt );
        }
    }
    else
    {
        sithConsole_Print("Error, bad parameters.\n");
    }
#endif
    return 1;
}

sithCog* sithCog_GetByIdx(int32_t idx)
{
    sithWorld *world; // ecx
    sithCog *result; // eax

    world = sithWorld_pCurrentWorld;
    if ( (idx & 0x8000) != 0 )
    {
        world = sithWorld_pStatic;
        idx &= ~0x8000u;
    }

    if ( world && idx >= 0 && idx < world->numCogsLoaded )
        result = &world->cogs[idx];
    else
        result = NULL;

    return result;
}
