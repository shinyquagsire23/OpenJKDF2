#include "sithGamesave.h"

#ifdef TARGET_DREAMCAST
#include "Platform/Dreamcast/dcStorage.h" // Added: single-autosave slot on VMU/RAM
#endif

#include "AI/sithAI.h"
#include "World/sithWorld.h"
#include "World/jkPlayer.h"
#include "World/sithThing.h"
#include "World/sithSector.h"
#include "Main/jkGame.h"
#include "Main/sithMain.h"
#include "Engine/sithCamera.h"
#include "Devices/sithSoundMixer.h"
#include "World/sithSurface.h"
#include "Gameplay/sithEvent.h"
#include "Gameplay/sithTime.h"
#include "Engine/sithAnimClass.h"
#include "General/sithStrTable.h"
#include "General/stdPalEffects.h"
#include "General/stdString.h"
#include "General/stdFnames.h"
#include "General/stdConffile.h"
#include "General/stdFileUtil.h"
#include "Devices/sithConsole.h"
#include "Cog/sithCogExec.h"
#include "Dss/sithDSSThing.h"
#include "Dss/sithDSS.h"
#include "Dss/sithDSSCog.h"
#include "Devices/sithComm.h"
#include "Dss/sithMulti.h"
#include "Gui/jkGUIDialog.h"
#include "Main/jkStrings.h"
#include "Main/jkMain.h"
#include "Main/jkEpisode.h"
#include "General/stdString.h"
#include "stdPlatform.h"
#include "jk.h"

#ifdef TARGET_DREAMCAST
// Added: set while a load re-runs sithMain_AutoSave() so its re-save doesn't push
// a redundant write to the VMU -- the card already holds what we just loaded.
static int sithGamesave_bSuppressVmuFlush = 0;
// Added: forces a slim (inventory-only) save even when an SD card is present, so
// the extra copy destined for the VMU stays tiny.
int sithGamesave_bForceSlim = 0;
#endif

// Added: the autosave slot is normally named per-map (_JKAUTO_<map>.jks). On a
// Dreamcast without an SD card the writable store (VMU/RAM) can't hold one per
// level, so every autosave collapses onto a single fixed name -- the real map is
// still recovered from the save's header on load. Elsewhere (and on SD) this is
// just the current map name, preserving the per-map autosaves.
const char* sithGamesave_AutosaveMapName(void)
{
#ifdef TARGET_DREAMCAST
    if (!dcStorage_HasFilesystem())
        return "dcauto.jkl";
#endif
    return sithWorld_pCurrentWorld->map_jkl_fname;
}

#ifdef TARGET_DREAMCAST
// Added: with no SD, the level-start autosave (the death/restart buffer) is kept
// as a single FULL save file in volatile KOS /ram. That flat ramdisk holds one
// file fine (no subdirs), and living outside the writable tree means it's never
// packed into the VMU snapshot and never triggers a slow VMU write on level load.
// Returns 1 (and fills pOut with the /ram path) when saveFname is that autosave.
static int sithGamesave_DcRamAutosavePath(const char* saveFname, char* pOut, int outSz)
{
    if (dcStorage_HasFilesystem() || !saveFname || _strncmp(saveFname, "_JKAUTO_", 8) != 0)
        return 0;
    stdString_snprintf(pOut, outSz, "/ram/%s", saveFname);
    return 1;
}

// Added: alongside a full autosave on SD, also drop a slim inventory-only copy on
// the VMU (named _JKAUTO_dcauto.jks) so the card always carries a resume point.
// No-op with no SD (the primary autosave is already the slim VMU save) or no VMU.
void sithGamesave_DcFlushSlimToVmu(void)
{
    if (!dcStorage_HasFilesystem() || !dcStorage_VmuPresent())
        return;
    char name[128];
    char savedFname[128];
    // Preserve the primary autosave name -- death should still reload the full SD
    // save, not this slim VMU copy.
    _strncpy(savedFname, sithGamesave_autosave_fname, sizeof(savedFname) - 1);
    savedFname[sizeof(savedFname) - 1] = 0;

    stdString_snprintf(name, sizeof(name), "_JKAUTO_dcauto.jks");
    sithGamesave_bForceSlim = 1;
    sithGamesave_Save(name, 1, 0, 0);
    sithGamesave_bForceSlim = 0;

    _strncpy(sithGamesave_autosave_fname, savedFname, 0x7Fu);
    sithGamesave_autosave_fname[127] = 0;
}
#endif

void sithGamesave_Setidk(sithSaveHandler_t a1, sithSaveHandler_t a2, sithSaveHandler_t a3, sithSaveHandler_t a4, sithSaveHandler_t a5)
{
    sithGamesave_func1 = a1;
    sithGamesave_func2 = a2;
    sithGamesave_func3 = a3;
    sithGamesave_funcWrite = a4;
    sithGamesave_funcRead = a5;
}

int sithGamesave_GetProfilePath(char *out, int outSize, char *a3)
{
    char a1[32]; // [esp+0h] [ebp-20h] BYREF

    stdString_WcharToChar(a1, jkPlayer_playerShortName, 31);
    a1[31] = 0;
    return stdString_snprintf(
        out, outSize, "player%c%s%c%s",
        LEC_PATH_SEPARATOR_CHR, a1, LEC_PATH_SEPARATOR_CHR, a3
    );
}

// write

int sithGamesave_Restore(char *saveFname, int debugNextCheckpoint, int a3)
{
    char playerName[32]; // [esp+0h] [ebp-A0h] BYREF
    char fpath[128]; // [esp+20h] [ebp-80h] BYREF

    stdString_WcharToChar(playerName, jkPlayer_playerShortName, 31);
    playerName[31] = 0;
#ifdef TARGET_DREAMCAST
    // The death/restart autosave lives in flat /ram with no SD (see helper above).
    if (!sithGamesave_DcRamAutosavePath(saveFname, fpath, 128))
#endif
    stdString_snprintf(
        fpath, 128, "player%c%s%c%s",
        LEC_PATH_SEPARATOR_CHR, playerName, LEC_PATH_SEPARATOR_CHR, saveFname
    );

    if (stdConffile_OpenReadBytesBypass(fpath))
    {
        stdConffile_Close();
        sithGamesave_dword_835914 = a3;
        if (sithWorld_pCurrentWorld)
        {
            sithGamesave_currentState = debugNextCheckpoint != 0 ? SITH_GS_LOAD_DEBUG_NEXTCHECKPOINT : SITH_GS_LOAD;
            _strncpy(sithGamesave_fpath, fpath, 0x7Fu);
            sithGamesave_fpath[127] = 0;
            return 1;
        }
        else
        {
            return sithGamesave_RestoreFile(fpath);
        }
    }
    return 0;
}

// MOTS altered
int sithGamesave_RestoreFile(char *fpath)
{
    uint32_t curMs; // [esp+Ch] [ebp-650h] BYREF
    char SrcStr[32]; // [esp+10h] [ebp-64Ch] BYREF
    sithGamesave_Header header; // [esp+30h] [ebp-62Ch] BYREF
#ifdef QOL_IMPROVEMENTS
    int32_t backup_episodeIdx = 0;
#endif

    int bIsOutdatedSave = 0;
    int bIsBinOnly = 0; // Added
#ifdef TARGET_DREAMCAST
    // Added: slim saves omit per-thing state, so they load like an outdated save
    // -- restore inventory and restart the level. Detected by the fixed slim
    // filename (_JKAUTO_dcauto.jks) rather than platform state, since a full SD
    // save and the slim VMU copy coexist. It's the intended format, so suppress
    // the "outdated" warning further down.
    // The flat /ram death/restart autosave shares the "dcauto" name but is a FULL
    // save, so exclude it here -- only the slim VMU copy loads inventory-only.
    if (fpath && _strstr(fpath, "dcauto") && _strncmp(fpath, "/ram/", 5) != 0) {
        bIsBinOnly = 1;
        bIsOutdatedSave = 1;
    }
#endif

    if ( !stdConffile_OpenReadBytesBypass(fpath) )
        goto load_fail;
    stdConffile_Read(&header, sizeof(sithGamesave_Header));

    if (!Main_bMotsCompat) {
        if ( header.version != 6 )
        goto load_fail;
    }
    else {
        if ( header.version != 6 && header.version != 0x7D6)
            goto load_fail;
         
        if ( header.version == 6) {
            bIsOutdatedSave = 1;
        }
    }

    // Added: multiple versions
    sithComm_version = header.version;
    
    if ( sithGamesave_funcRead )
        sithGamesave_funcRead();
    stdConffile_Read(SrcStr, 32);
    _strtolower(SrcStr);

    // Added: Fix soundtrack on levels that use disk 2
#ifdef QOL_IMPROVEMENTS
    backup_episodeIdx = jkEpisode_mLoad.currentEpisodeEntryIdx;
    if ( jkEpisode_Load(&jkGui_episodeLoad) )
    {
        if (jkEpisode_mLoad.paEntries) {
            JK_FREE(jkEpisode_mLoad.paEntries);
            jkEpisode_mLoad.paEntries = NULL;
        }
        jkEpisode_mLoad = jkGui_episodeLoad;
        size_t aEnts_size = (jkEpisode_mLoad.numSeq + 1) * sizeof(jkEpisodeEntry);
        jkEpisode_mLoad.paEntries = (jkEpisodeEntry *)JK_ALLOC(aEnts_size);
        memcpy(jkEpisode_mLoad.paEntries, jkGui_episodeLoad.paEntries, aEnts_size);

        jkEpisode_mLoad.currentEpisodeEntryIdx = backup_episodeIdx;
        //printf("asdfasdfasdf %u\n", jkEpisode_mLoad.currentEpisodeEntryIdx);
        if (jkEpisode_mLoad.currentEpisodeEntryIdx > jkEpisode_mLoad.numSeq) {
            jkEpisode_mLoad.currentEpisodeEntryIdx = 0;
        }

        if (!jkEpisode_mLoad.currentEpisodeEntryIdx)
        {
            for (int j = 0; j < jkEpisode_mLoad.numSeq; j++)
            {
                //printf("%s %s\n", jkEpisode_mLoad.paEntries[j].fileName, v25);
                if (!__strcmpi(jkEpisode_mLoad.paEntries[j].fileName, SrcStr)) {
                    jkEpisode_mLoad.currentEpisodeEntryIdx = j;
                    break;
                }
            }
        }

        jkMain_pEpisodeEnt = &jkEpisode_mLoad.paEntries[jkEpisode_mLoad.currentEpisodeEntryIdx];
        jkMain_pEpisodeEnt2 = &jkEpisode_mLoad.paEntries[jkEpisode_mLoad.currentEpisodeEntryIdx];
        //printf("asdfasdfasdf %u %s\n", jkEpisode_mLoad.currentEpisodeEntryIdx, jkEpisode_mLoad.paEntries[jkEpisode_mLoad.currentEpisodeEntryIdx].fileName);
    }
#endif

    if ( sithWorld_pCurrentWorld )
    {
        if ( !_strcmp(SrcStr, sithWorld_pCurrentWorld->map_jkl_fname) )
        {
            sithWorld_ResetSectorRuntimeAlteredVars(sithWorld_pCurrentWorld);
            goto LABEL_11;
        }
        sithMain_Close();
    }
    if ( !sithMain_OpenNormal(SrcStr) )
    {
        goto load_fail;
    }
LABEL_11:
    sithSoundMixer_Reset();
    sithSurface_Startup3();
    sithEvent_Reset();
    stdPalEffects_FlushAllEffects();
    stdPalEffects_ResetEffectsState(&stdPalEffects_state);
    if ( sithGamesave_func2 )
        sithGamesave_func2();
    if ( !stdConffile_Read(&curMs, sizeof(uint32_t)) )
        goto load_fail; // TODO: is this a memleak?
    sithTime_SetGameTime(curMs);
    
    // Added: split this apart, g_sithMode is a struct...
    stdConffile_Read((char*)&g_sithMode, sizeof(int32_t));
    stdConffile_Read((char*)&g_submodeFlags, sizeof(int32_t));
    stdConffile_Read((char*)&sithSurface_byte_8EE668, sizeof(int32_t));
    stdConffile_Read((char*)&g_debugmodeFlags, sizeof(int32_t));
    stdConffile_Read((char*)&jkPlayer_setDiff, sizeof(int32_t));
    stdConffile_Read((char*)&g_mapModeFlags, sizeof(int32_t));

    if (bIsOutdatedSave) {
        //stdConffile_Close();
        
        // TODO add message
        //sithGamesave_currentState = SITH_GS_LOAD_DEBUG_NEXTCHECKPOINT;
        curMs = 0;
        sithCamera_ResetAllCameras();
        goto skip_free_things;
    }

    sithThing_freestuff(sithWorld_pCurrentWorld);

skip_free_things:
    // Apparently this works by interpreting a bunch of netMsg packets from the
    // savefile? Funky.
//#ifndef LINUX_TMP
    while (1)
    {
        // Added: Determinism
        memset(&sithComm_netMsgTmp, 0, sizeof(sithComm_netMsgTmp));

        // TODO
        if (sithComm_version == 0x7D6) {
            int32_t tmp = 0;
            if ( !stdConffile_Read(&tmp, sizeof(tmp)) )
            {
                break;
            }
        }

        if ( !stdConffile_Read(&sithComm_netMsgTmp.netMsg.cogMsgId, sizeof(int32_t)) )
        {
            break;
        }
        
        if (!stdConffile_Read(&sithComm_netMsgTmp.netMsg.msg_size, sizeof(int32_t)))
        {
            stdPlatform_Printf("OpenJKDF2: Save load failed to read msg_size\n");
            goto load_fail;
        }

        //printf("%x %x\n", sithComm_netMsgTmp.netMsg.cogMsgId, sithComm_netMsgTmp.netMsg.msg_size);

        if (sithComm_netMsgTmp.netMsg.msg_size > sizeof(sithComm_netMsgTmp.pktData)) {
            stdPlatform_Printf("OpenJKDF2: Save load failed to read msg, size 0x%x is too large.\n", sithComm_netMsgTmp.netMsg.msg_size);
            goto load_fail;
        }
        
        if (!(!sithComm_netMsgTmp.netMsg.msg_size || stdConffile_Read(sithComm_netMsgTmp.pktData, sithComm_netMsgTmp.netMsg.msg_size)))
        {
            stdPlatform_Printf("OpenJKDF2: Save load failed to read msg sized %x\n", sithComm_netMsgTmp.netMsg.msg_size);
            goto load_fail;
        }

        // If the save is outdated, only try to load inventory data
        if (bIsOutdatedSave && sithComm_netMsgTmp.netMsg.cogMsgId != DSS_INVENTORY) {
            continue;
        }
        
        if (!sithMessage_Process(&sithComm_netMsgTmp))
        {
            stdPlatform_Printf("OpenJKDF2: Save load failed to invoke msg %u\n", sithComm_netMsgTmp.netMsg.cogMsgId);
#ifndef SDL2_RENDER
            // Linux fails on SyncSound only
            goto load_fail;
#endif
        }
    }
//#endif

    if (bIsOutdatedSave)
    {
        jkPlayer_Startup();
        jkPlayer_InitForceBins();
        jkPlayer_InitSaber();
#ifdef TARGET_DREAMCAST
        // Added: this AutoSave just re-materialises what we loaded; let it rebuild
        // the RAM-disk save but skip the (slow, flash-wearing) VMU write.
        sithGamesave_bSuppressVmuFlush = 1;
        sithMain_AutoSave();
        sithGamesave_bSuppressVmuFlush = 0;
#else
        sithMain_AutoSave();
#endif

        // Added: bin-only is the intended VMU save format, not a version error --
        // don't scare the player with the "outdated save" dialog.
        if (!bIsBinOnly)
            jkGuiDialog_ErrorDialog(jkStrings_GetUniStringWithFallback("ERROR"), L"This save is outdated and cannot be loaded fully. The level will be restarted with your existing inventory and progress.");

        goto skip_dss;
    }

    sithThing_sub_4CCE60();
    sithPlayer_idk(0);
    if ( sithGamesave_func3 )
        sithGamesave_func3();

    stdConffile_Close();
    _memcpy(&sithGamesave_headerTmp, &header, sizeof(sithGamesave_headerTmp));
    stdString_SafeStrCopy(sithGamesave_autosave_fname, stdFnames_FindMedName(fpath), 128);
    if ( sithGamesave_dword_835914 )
    {
        stdString_SafeStrCopy(sithGamesave_saveName, stdFnames_FindMedName(fpath), 128);
        _wcsncpy(sithGamesave_wsaveName, sithGamesave_headerTmp.saveName, 0xFFu);
        sithGamesave_wsaveName[255] = 0;
    }
skip_dss:
    sithTime_SetGameTime(curMs);
    sithCamera_SetCurrentCamera(sithCamera_currentCamera);
    return 1;

load_fail:
    stdConffile_Close();
    sithThing_sub_4CCE60();
    sithMain_Close();
    return 0;
}

// MOTS altered
// Added: minimal serializer for Dreamcast VMU (bin-only) saves. Emits just the
// DSS_INVENTORY messages -- the only thing the restart-with-inventory load path
// consumes -- so the save stays a few KB and fits the memory card.
int sithGamesave_SerializeInventoryOnly(int mpFlags)
{
    if ( (sithComm_multiplayerFlags & mpFlags) == 0 )
        return 0;
    for (int v19 = 0; v19 < SITHBIN_NUMBINS; v19++)
    {
        if ( (sithInventory_aDescriptors[v19].flags & ITEMINFO_VALID) != 0 )
            sithDSS_SendInventory(sithPlayer_pLocalPlayerThing, v19, 0, mpFlags);
    }
    return 1;
}

int sithGamesave_SaveCurrentWorld(int mpFlags)
{
    uint32_t v15; // ebx
    int v16; // ebp
    uint32_t v17; // ebx
    int v18; // ebp
    int v19; // ebx
    sithItemDescriptor *v20; // esi

    if ( (sithComm_multiplayerFlags & mpFlags) == 0 )
        return 0;
    for (uint32_t i = 0; i < sithWorld_pCurrentWorld->numThingsLoaded; i++)
    {
        sithThing* v4 = &sithWorld_pCurrentWorld->things[i];
        if ( sithThing_ShouldSync(v4) )
        {
            sithDSSThing_SendFullDesc(v4, 0, mpFlags);
            if ( v4->rdthing.puppet )
                sithDSS_SendSyncPuppet(v4, 0, mpFlags);
        }
    }

    for (uint32_t i = 0; i < sithWorld_pCurrentWorld->numThingsLoaded; i++)
    {
        sithThing* v7 = &sithWorld_pCurrentWorld->things[i];
        if (sithThing_ShouldSync(v7))
        {
            if ( v7->attach_flags )
            {
                // MOTS altered: Jail Key
                if (!Main_bMotsCompat && (v7->attach_flags & SITH_ATTACH_NO_MOVE) != 0 || v7->moveType != SITH_MT_PHYSICS )
                    sithDSSThing_SendSyncThingAttachment(v7, 0, mpFlags, 1);
                else if (Main_bMotsCompat && v7->attach_flags && (v7->attach_flags & (SITH_ATTACH_NO_MOVE|SITH_ATTACH_FORCE_SERIALIZE)) != 0 || v7->moveType != SITH_MT_PHYSICS )
                    sithDSSThing_SendSyncThingAttachment(v7, 0, mpFlags, 1);
            }
        }
    }

    for (uint32_t i = 0; i < SITHAI_MAX_ACTORS; i++) // TODO define this maximum
    {
        if ( sithAI_actors[i].pAIClass ) {
            sithDSS_SendAIStatus(&sithAI_actors[i], 0, mpFlags);
        }
    }

    for (uint32_t i = 0; i < sithWorld_pCurrentWorld->numCogsLoaded; i++)
    {
        sithDSSCog_SyncCogState(&sithWorld_pCurrentWorld->cogs[i], 0, mpFlags);
    }

    if ( sithWorld_pStatic )
    {
        for (uint32_t i = 0; i < sithWorld_pStatic->numCogsLoaded; i++)
        {
            sithDSSCog_SyncCogState(&sithWorld_pStatic->cogs[i], 0, mpFlags);
        }
    }

    for (uint32_t i = 0; i < sithWorld_pCurrentWorld->numSurfaces; i++)
    {
        sithDSS_SendSurfaceStatus(&sithWorld_pCurrentWorld->surfaces[i], 0, mpFlags);
    }

    for (uint32_t i = 0; i < sithWorld_pCurrentWorld->numSectors; i++)
    {
        sithDSS_SendSectorStatus(&sithWorld_pCurrentWorld->sectors[i], 0, mpFlags);
    }

    for (v19 = 0; v19 < SITHBIN_NUMBINS; v19++) // TODO define this maximum
    {
        if ( (sithInventory_aDescriptors[v19].flags & ITEMINFO_VALID) != 0 )
            sithDSS_SendInventory(sithPlayer_pLocalPlayerThing, v19, 0, mpFlags);
    }

    sithSurface_SyncFull(mpFlags);

    for (sithEvent* timerIter = sithEvent_list; timerIter; timerIter = timerIter->nextTimer )
        sithDSS_SendSyncEvents(timerIter, 0, mpFlags);

    sithDSS_SendSyncPalEffects(0, mpFlags);
    sithDSS_SendSyncCameras(0, mpFlags);
    sithSoundMixer_SyncSounds();
    sithDSS_SendMisc(0, mpFlags);

    return 1;
}

int sithGamesave_Save(char *saveFname, int a2, int a3, wchar_t *saveName)
{
    wchar_t *v5; // esi
    flex32_t *v7; // eax
    sithItemInfo *v8; // ecx
    char tmp_playerName[32]; // [esp+Ch] [ebp-2A0h] BYREF
    char PathName[128]; // [esp+2Ch] [ebp-280h] BYREF
    wchar_t v13[256]; // [esp+ACh] [ebp-200h] BYREF

    if ( (g_submodeFlags & 1) != 0 )
        return 0;
    if ( (sithPlayer_pLocalPlayerThing->thingflags & SITH_TF_DEAD) != 0 )
        return 0;

    // Added: multiple versions
    sithComm_version = COMPAT_SAVE_VERSION;

    v5 = saveName;
    if ( !saveName )
    {
        v5 = v13;
        stdString_CharToWchar(v13, saveFname, 255);
        v13[255] = 0;
    }
    sithGamesave_dword_835914 = a3;
    stdString_WcharToChar(tmp_playerName, jkPlayer_playerShortName, 31);
    tmp_playerName[31] = 0;
    stdString_snprintf(
        PathName, 128, "player%c%s%c%s",
        LEC_PATH_SEPARATOR_CHR, tmp_playerName, LEC_PATH_SEPARATOR_CHR,
        &sithGamesave_fpath[128]
    );
    stdFileUtil_MkDir(PathName);
    stdString_WcharToChar(tmp_playerName, jkPlayer_playerShortName, 31);
    tmp_playerName[31] = 0;
    stdString_snprintf(
        PathName, 128, "player%c%s%c%s",
        LEC_PATH_SEPARATOR_CHR, tmp_playerName, LEC_PATH_SEPARATOR_CHR,
        saveFname
    );
#ifdef TARGET_DREAMCAST
    // Redirect the death/restart autosave to a flat /ram file: full, volatile, and
    // off the VMU (see sithGamesave_DcRamAutosavePath). No-op for other saves; the
    // resulting path drives the full-serialize / no-VMU-flush choices in _Flush().
    sithGamesave_DcRamAutosavePath(saveFname, PathName, 128);
#endif
    if ( a2 || !stdConffile_OpenReadBypass(PathName) )
    {
        _memset(&sithGamesave_headerTmp, 0, sizeof(sithGamesave_headerTmp));
        sithGamesave_headerTmp.version = COMPAT_SAVE_VERSION;
        _strncpy(sithGamesave_headerTmp.episodeName, sithWorld_pCurrentWorld->episodeName, 0x7Fu);
        sithGamesave_headerTmp.episodeName[127] = 0;
        _strncpy(sithGamesave_headerTmp.jklName, sithWorld_pCurrentWorld->map_jkl_fname, 0x7Fu);
        sithGamesave_headerTmp.jklName[127] = 0;
        _wcsncpy(sithGamesave_headerTmp.saveName, v5, 0xFFu);
        sithGamesave_headerTmp.saveName[255] = 0;
        sithGamesave_headerTmp.playerHealth = sithPlayer_pLocalPlayerThing->actorParams.health;
        sithGamesave_headerTmp.playerMaxHealth = sithPlayer_pLocalPlayerThing->actorParams.maxHealth;
        v7 = sithGamesave_headerTmp.binAmts;
        v8 = sithPlayer_pLocalPlayer->iteminfo;
        do
        {
            *v7++ = v8->ammoAmt;
            ++v8;
        }
        while ( (intptr_t)v7 < (intptr_t)sithGamesave_headerTmp.saveName );
        sithGamesave_currentState = SITH_GS_SAVE;
        _strncpy(sithGamesave_fpath, PathName, 0x7Fu);
        sithGamesave_fpath[127] = 0;
        return 1;
    }
    else
    {
        stdConffile_Close();
        return 0;
    }
}

int sithGamesave_Process()
{
    if ( sithGamesave_currentState == SITH_GS_LOAD )
    {
        if ( sithGamesave_RestoreFile(sithGamesave_fpath) )
        {
            sithGamesave_currentState = SITH_GS_NONE;
            return 1;
        }
        // TODO inlined?
        sithMain_set_sithmode_5();
        sithGamesave_currentState = SITH_GS_NONE;
        return 1;
    }
    if ( sithGamesave_currentState != SITH_GS_SAVE )
    {
        if ( sithGamesave_currentState != SITH_GS_LOAD_DEBUG_NEXTCHECKPOINT)
            return sithGamesave_currentState - SITH_GS_LOAD_DEBUG_NEXTCHECKPOINT;
        if ( sithGamesave_RestoreFile(sithGamesave_fpath) )
        {
            sithPlayer_debug_ToNextCheckpoint(sithPlayer_pLocalPlayerThing);
            sithGamesave_currentState = SITH_GS_NONE;
            return 1;
        }
        // TODO inlined?
        sithMain_set_sithmode_5();
        sithGamesave_currentState = SITH_GS_NONE;
        return 1;
    }
    if ( (sithPlayer_pLocalPlayerThing->thingflags & SITH_TF_DEAD) == 0 && stdConffile_OpenWriteBypass(sithGamesave_fpath) )
    {
        int multiplayerFlagsSave = sithComm_multiplayerFlags;
        sithComm_multiplayerFlags = 4;
        stdConffile_Write((const char*)&sithGamesave_headerTmp, sizeof(sithGamesave_Header));
        if ( sithGamesave_funcWrite )
            sithGamesave_funcWrite();
        stdConffile_Write((const char*)sithWorld_pCurrentWorld->map_jkl_fname, 32);
        stdConffile_Write((const char*)&sithTime_curMs, sizeof(uint32_t));
        
        // Added: split this apart, g_sithMode is a struct...
        stdConffile_Write((const char*)&g_sithMode, sizeof(int32_t));
        stdConffile_Write((const char*)&g_submodeFlags, sizeof(int32_t));
        stdConffile_Write((const char*)&sithSurface_byte_8EE668, sizeof(int32_t));
        stdConffile_Write((const char*)&g_debugmodeFlags, sizeof(int32_t));
        stdConffile_Write((const char*)&jkPlayer_setDiff, sizeof(int32_t));
        stdConffile_Write((const char*)&g_mapModeFlags, sizeof(int32_t));
        
#ifdef TARGET_DREAMCAST
        // The flat /ram autosave (redirected in _Write) is identified by its path.
        int bRamAutosave = (_strncmp(sithGamesave_fpath, "/ram/", 5) == 0);
        // Added: a slim save serializes only the inventory bins, not the full
        // per-thing state -- the restart-with-inventory load consumes just
        // DSS_INVENTORY, and the tiny VMU can't hold the rest. Slim when there's
        // no SD (the only store) or when explicitly forced (the extra VMU copy
        // written alongside a full SD save). The /ram death/restart autosave is
        // always full -- the flat ramdisk holds it and restart needs it.
        if ((dcStorage_HasFilesystem() || bRamAutosave) && !sithGamesave_bForceSlim)
            sithGamesave_SaveCurrentWorld(4);
        else
            sithGamesave_SerializeInventoryOnly(4);
#else
        sithGamesave_SaveCurrentWorld(4);
#endif
        if ( sithGamesave_func1 )
            sithGamesave_func1();
        stdConffile_CloseWrite();
        _strncpy(sithGamesave_autosave_fname, stdFnames_FindMedName(sithGamesave_fpath), 0x7Fu);
        sithGamesave_autosave_fname[127] = 0;
        if ( sithGamesave_dword_835914 )
        {
            _strncpy(sithGamesave_saveName, stdFnames_FindMedName(sithGamesave_fpath), 0x7Fu);
            sithGamesave_saveName[127] = 0;
            _wcsncpy(sithGamesave_wsaveName, sithGamesave_headerTmp.saveName, 0xFFu);
            sithGamesave_wsaveName[255] = 0;
            sithConsole_PrintWString(sithStrTable_GetUniStringWithFallback("GAME_SAVED"));
        }
        sithComm_multiplayerFlags = multiplayerFlagsSave;
#ifdef TARGET_DREAMCAST
        // Added: flush to the VMU only for slim saves (the card carries just the
        // slim copy) -- and not when re-materialising a save the card already
        // holds. Full SD writes don't touch the VMU, and neither does the flat
        // /ram death/restart autosave (it lives outside the writable tree).
        {
            int bWroteSlim = (!dcStorage_HasFilesystem() || sithGamesave_bForceSlim) && !bRamAutosave;
            if (bWroteSlim && !sithGamesave_bSuppressVmuFlush)
                dcStorage_Flush();
        }
#endif
    }
    sithGamesave_currentState = SITH_GS_NONE;
    return 0;
}
