#include "jkRes.h"

#include "../jk.h"
#include "Win95/stdGob.h"
#include "Main/Main.h"
#include "General/stdFileUtil.h"
#include "General/stdFnames.h"
#include "stdPlatform.h"
#include "Win95/Windows.h"
#include "Main/sithMain.h"
#include "General/util.h"
#include "Gui/jkGUIDialog.h"
#include "Main/jkStrings.h"
#include "General/stdString.h"
#include "General/stdHashTable.h"

static int jkRes_bInit;

int jkRes_Startup(HostServices *a1)
{
    stdPlatform_Printf("OpenJKDF2: %s\n", __func__);
    
    if ( jkRes_bInit )
        return 0;

    _memcpy(&lowLevelHS, a1, sizeof(HostServices));
    pLowLevelHS = (HostServices *)&lowLevelHS;
    _memset(&jkRes_gCtx, 0, sizeof(jkRes_gCtx));
    jkRes_pHS = a1;

    jkRes_HookHS();
    if ( Main_path[0] )
    {
        jkRes_New(Main_path);
    }
    jkRes_LoadNew(&jkRes_gCtx.aGobDirectories[3], "resource", 1);
    _memset(jkRes_aFiles, 0, sizeof(jkRes_aFiles));
    stdPlatform_Printf("OpenJKDF2: %s - jkRes_bInit = 1\n", __func__);
    // Log out whats all now initted 
    stdPlatform_Printf("OpenJKDF2: %s - jkRes_gCtx.aGobDirectories[0].name = %s\n", __func__, jkRes_gCtx.aGobDirectories[0].name);
    stdPlatform_Printf("OpenJKDF2: %s - jkRes_gCtx.aGobDirectories[0].name = %s\n", __func__, jkRes_gCtx.aGobDirectories[1].name);
    stdPlatform_Printf("OpenJKDF2: %s - jkRes_gCtx.aGobDirectories[0].name = %s\n", __func__, jkRes_gCtx.aGobDirectories[2].name);
    stdPlatform_Printf("OpenJKDF2: %s - jkRes_gCtx.aGobDirectories[0].name = %s\n", __func__, jkRes_gCtx.aGobDirectories[3].name);

    jkRes_bInit = 1;
    return 1;
}

int jkRes_Shutdown()
{
    stdPlatform_Printf("OpenJKDF2: %s\n", __func__);

    if (!jkRes_bInit)
        return 0;

    jkRes_UnhookHS();
    
    for (int i = 0; i < 5; i++)
    {
        jkRes_FreeGobs(i);
    }
    // MOTS added: close fail log
    //if (Main_failLogFp) {
    //    fclose(Main_failLogFp);
    //}
    jkRes_bInit = 0;
    return 1;
}

void jkRes_New(char *path)
{
    jkRes_FreeGobs(0);

    if ( *path )
        jkRes_LoadNew(&jkRes_gCtx.aGobDirectories[0], path, 1);
}

// Added: This seems to be inlined everywhere
void jkRes_FreeGobs(int idx)
{
    for (int i = 0; i < jkRes_gCtx.aGobDirectories[idx].numGobs; i++)
    {
        stdGob_Free(jkRes_gCtx.aGobDirectories[idx].gobs[i]);
    }
    jkRes_gCtx.aGobDirectories[idx].numGobs = 0;
}

void jkRes_LoadGob(char *a1)
{
    unsigned int v1; // esi
    unsigned int v3; // esi
    int v12; // ecx
    int v13; // edx
    int v15; // edx
    int v24; // ecx
    int v25; // edx
    int v27; // edx
    char v30[128]; // [esp+10h] [ebp-80h] BYREF

    sithMain_SetEpisodeName(a1);
    
    jkRes_FreeGobs(1);
    jkRes_FreeGobs(2);

    stdString_SafeStrCopy(jkRes_episodeGobName, a1, 0x20);
    if (a1[0] == 0)
        return;

    stdString_snprintf(v30, 0x80u, "%s.%s", jkRes_episodeGobName, JKRES_GOB_EXT);
    stdString_snprintf(jkRes_gCtx.aGobDirectories[1].name, 0x80u, "episode\\%s", jkRes_episodeGobName);
    
    jkRes_NewGob(&jkRes_gCtx.aGobDirectories[1], "episode", v30);
    strcpy(jkRes_curDir, "sdmc:/jk");
    if ( jkRes_curDir[0] && Windows_installType < 1 )
    {
        stdString_snprintf(std_genBuffer, 0x80u, "%s\\episode", jkRes_curDir);
        stdString_snprintf(jkRes_gCtx.aGobDirectories[2].name, 0x80u, "%s\\episode\\%s", jkRes_curDir, jkRes_episodeGobName);
        
        jkRes_NewGob(&jkRes_gCtx.aGobDirectories[2], std_genBuffer, v30);
    }
}

int jkRes_LoadCd(char *a1)
{
    char v4[128]; // [esp+Ch] [ebp-80h] BYREF

    // Added: prevent overlap
    if (jkRes_curDir != a1) {
        stdString_SafeStrCopy(jkRes_curDir, a1, 128);
    }

    jkRes_FreeGobs(4);

    if ( *a1 )
    {
        stdString_snprintf(v4, 0x80u, "%s%cgamedata%cresource", jkRes_curDir, LEC_PATH_SEPARATOR_CHR, LEC_PATH_SEPARATOR_CHR);
        return jkRes_LoadNew(&jkRes_gCtx.aGobDirectories[4], v4, Windows_installType != 9);
    }
    return 0;
}

void jkRes_HookHS()
{
    if (!jkRes_bHookedHS)
    {
        jkRes_pHS->fileOpen = jkRes_FileOpen;
        jkRes_pHS->fileClose = jkRes_FileClose;
        jkRes_pHS->fileRead = jkRes_FileRead;
        jkRes_pHS->fileGets = jkRes_FileGets;
        jkRes_pHS->fileGetws = jkRes_FileGetws;
        jkRes_pHS->fileWrite = jkRes_FileWrite;
        jkRes_pHS->fileEof = jkRes_FEof;
        jkRes_pHS->ftell = jkRes_FTell;
        jkRes_pHS->fseek = jkRes_FSeek;
        jkRes_pHS->fileSize = jkRes_FileSize;
        jkRes_pHS->filePrintf = jkRes_FilePrintf;
    }
    ++jkRes_bHookedHS;
}

void jkRes_UnhookHS()
{
    if (jkRes_bHookedHS)
    {
        jkRes_pHS->fileOpen = lowLevelHS.fileOpen;
        jkRes_pHS->fileClose = lowLevelHS.fileClose;
        jkRes_pHS->fileRead = lowLevelHS.fileRead;
        jkRes_pHS->fileGets = lowLevelHS.fileGets;
        jkRes_pHS->fileGetws = lowLevelHS.fileGetws;
        jkRes_pHS->fileWrite = lowLevelHS.fileWrite;
        jkRes_pHS->fileEof = lowLevelHS.fileEof;
        jkRes_pHS->ftell = lowLevelHS.ftell;
        jkRes_pHS->fseek = lowLevelHS.fseek;
        jkRes_pHS->fileSize = lowLevelHS.fileSize;
        jkRes_pHS->filePrintf = lowLevelHS.filePrintf;
        --jkRes_bHookedHS;
    }
}

int jkRes_FileExists(const char *fpath, char *a2, int len)
{
    jkResFile *resFile;

    stdFile_t fd = jkRes_FileOpen(fpath, "r");

    if (!fd)
        return 0;

    resFile = &jkRes_aFiles[fd-1];
    stdString_SafeStrCopy(a2, resFile->fpath, len);

    if ( resFile->useLowLevel )
        pLowLevelHS->fileClose(resFile->fsHandle);
    else
        stdGob_FileClose(resFile->gobHandle);

    resFile->bOpened = 0;
    return 1;
}

// Added
int jkRes_ReadKeyFromFile(const char* fpath)
{
    int keyval;
    stdPlatform_Printf("OpenJKDF2: %s - Reading key from file: %s\n", __func__, fpath);

    stdFile_t fd = pHS->fileOpen(fpath, "rb");
    if (!fd)
        return 0;

    keyval = 0;
    pHS->fileRead(fd, &keyval, 4);
    pHS->fileClose(fd);
    return keyval;
}

// Added
int jkRes_ReadKeyRaw()
{
        stdPlatform_Printf("OpenJKDF2: %s - Reading key raw: %s\n", __func__);

    return jkRes_ReadKeyFromFile("jk_.cd");
}

// Added
int jkRes_ReadKeyRawEarly()
{
            stdPlatform_Printf("OpenJKDF2: %s - Reading key raw early: %s\n", __func__);

    return jkRes_ReadKeyFromFile("resource/jk_.cd");
}

int jkRes_ReadKey()
{
    int keyval = jkRes_ReadKeyRaw();

    if (keyval == JKRES_MAGIC_0)
    {
        return 0;
    }
    else if (keyval == JKRES_MAGIC_1)
    {
        return 1;
    }
    else if (keyval == JKRES_MAGIC_2)
    {
        return 2;
    }
    return 0;
}

int jkRes_LoadNew(jkResGobDirectory *resGob, char *name, int a3)
{


    #ifdef TARGET_SWITCH
   char  path[255] = {0};
    getcwd(path, 255);
    chdir("sdmc:/jk/");
        stdPlatform_Printf("Openjkdf2 loadNew:  Current working directory: %s\n", path);
    #endif
    stdFileSearch *v15; // ebp
    stdFileSearchResult v18; // [esp+8h] [ebp-10Ch] BYREF

    stdString_SafeStrCopy(resGob->name, name, 128);
    resGob->numGobs = 0;
    if (!a3)
        return 0;

    jkRes_UnhookHS();

    // Added: Add a mods dir which always overrides resource/
    if (!_strcmp(name, "resource"))
    {
        v15 = stdFileUtil_NewFind("mods", 3, JKRES_GOB_EXT);
        while (stdFileUtil_FindNext(v15, &v18))
        {
            if ( resGob->numGobs >= STDGOB_MAX_GOBS )
                break;
            if ( v18.fpath[0] != '.' )
            {
                stdString_snprintf(jkRes_idkGobPath, 0x80u, "%s%c%s", "mods", LEC_PATH_SEPARATOR_CHR, v18.fpath);
                resGob->gobs[resGob->numGobs] = stdGob_Load(jkRes_idkGobPath, 16, 0);

                if ( resGob->gobs[resGob->numGobs] )
                    resGob->numGobs++;
            }
        }
        stdFileUtil_DisposeFind(v15);
    }

    v15 = stdFileUtil_NewFind(name, 3, JKRES_GOB_EXT);
    stdPlatform_Printf("OpenJKDF2: %s - Searching for gobs in %s\n", __func__, name);
    while (stdFileUtil_FindNext(v15, &v18))
    {
        stdPlatform_Printf("OpenJKDF2: %s - Found gob: %s\n", __func__, v18.fpath);
        if ( resGob->numGobs >= STDGOB_MAX_GOBS )
            break;
        if ( v18.fpath[0] != '.' )
        {
            stdString_snprintf(jkRes_idkGobPath, 0x80u, "%s%c%s", name, LEC_PATH_SEPARATOR_CHR, v18.fpath);
            resGob->gobs[resGob->numGobs] = stdGob_Load(jkRes_idkGobPath, 16, 0);

            stdPlatform_Printf("OpenJKDF2: %s - Loading gob: %s\n", __func__, jkRes_idkGobPath);

            if ( resGob->gobs[resGob->numGobs] )
                resGob->numGobs++;
        }
    }

    stdFileUtil_DisposeFind(v15);

    jkRes_HookHS();
    
    return jkRes_bHookedHS;
}

int jkRes_NewGob(jkResGobDirectory *gobFullpath, char *gobFolder, char *gobFname)
{
    jkRes_UnhookHS();
    
    gobFullpath->numGobs = 0;
    stdString_snprintf(jkRes_idkGobPath, 0x80u, "%s%c%s", gobFolder, LEC_PATH_SEPARATOR_CHR, gobFname);
    if ( util_FileExists(jkRes_idkGobPath) )
    {
        if ( gobFullpath->numGobs < STDGOB_MAX_GOBS )
        {
            gobFullpath->gobs[gobFullpath->numGobs] = stdGob_Load(jkRes_idkGobPath, 16, 0);
            if ( gobFullpath->gobs[gobFullpath->numGobs] )
                gobFullpath->numGobs++;
        }
    }

    jkRes_HookHS();    
    
    return jkRes_bHookedHS;
}

int jkRes_LoadCD(int cdNumberNeeded)
{
        stdPlatform_Printf("OpenJKDF2 - read cd: %s\n", __func__); // Added
    int v1; // eax
    unsigned int v3; // edi
    stdGob **v4; // esi
    unsigned int v5; // edi
    stdGob **v6; // esi
    wchar_t *v7; // eax
    wchar_t *v8; // eax
    wchar_t *v9; // eax
    unsigned int v10; // esi
    stdGob **v11; // edi
    unsigned int v12; // esi
    stdGob **v13; // edi
    unsigned int v14; // edi
    stdGob **v15; // esi
    unsigned int v16; // esi
    unsigned int v18; // esi
    unsigned int v20; // edi
    stdGob **v21; // esi
    int v23; // [esp+10h] [ebp-18Ch]
    int v24; // [esp+14h] [ebp-188h]
    int keyval; // [esp+18h] [ebp-184h] BYREF
    char v26[128]; // [esp+1Ch] [ebp-180h] BYREF
    char a2[128]; // [esp+9Ch] [ebp-100h] BYREF
    wchar_t v28[64]; // [esp+11Ch] [ebp-80h] BYREF

    v23 = 0;
    v24 = 0;
    while ( 1 )
    {
        v1 = pHS->fileOpen("jk_.cd", "rb");
        stdPlatform_Printf("OpenJKDF2: %s - Opening jk_.cd\n", __func__);

        if ( v1 )
        {

        stdPlatform_Printf("OpenJKDF2: %s - Opening jk_.cd good \n", __func__);
            pHS->fileRead(v1, &keyval, 4);
            if ( keyval == JKRES_MAGIC_0 ) {
                v23 = 1;
            }
            else if ( !cdNumberNeeded )
            {
                if ( keyval == JKRES_MAGIC_1 || keyval == JKRES_MAGIC_2 )
                    v23 = 1;
            }
            else if ( keyval == ((cdNumberNeeded << (cdNumberNeeded + 5)) | JKRES_MAGIC_3) ) {
                v23 = 1;
            }

            pHS->fileClose(v1);
        }

#if defined(TARGET_TWL) || defined(TARGET_SWITCH)
        v23 = 1;
#endif
        
        if ( v23 )
        {
            if ( v24 )
            {
                //stdString_SafeStrCopy(jkRes_curDir, jkRes_curDir, 128); //TODO ??
                //jkRes_curDir[0] = 0; // Added

                jkRes_curDir[127] = 0;

                jkRes_FreeGobs(4);
                if ( jkRes_curDir[0] )
                {
                    stdString_snprintf(a2, 0x80u, "%s%cgamedata%cresource", jkRes_curDir, LEC_PATH_SEPARATOR_CHR, LEC_PATH_SEPARATOR_CHR);
                    jkRes_LoadNew(&jkRes_gCtx.aGobDirectories[4], a2, Windows_installType != 9);
                }
                sithMain_SetEpisodeName(jkRes_episodeGobName);
                jkRes_FreeGobs(1);
                jkRes_FreeGobs(2);
                //stdString_SafeStrCopy(jkRes_episodeGobName, jkRes_episodeGobName, 32);  // TODO ???
                if ( jkRes_episodeGobName[0] )
                {
                    stdString_snprintf(v26, 0x80u, "%s.%s", jkRes_episodeGobName, JKRES_GOB_EXT);
                    stdString_snprintf(jkRes_gCtx.aGobDirectories[1].name, 0x80u, "episode%c%s", LEC_PATH_SEPARATOR_CHR, jkRes_episodeGobName);
                    jkRes_NewGob(&jkRes_gCtx.aGobDirectories[1], "episode", v26);
                    if ( jkRes_curDir[0] )
                    {
                        if ( Windows_installType < 1 )
                        {
                            stdString_snprintf(std_genBuffer, 0x80u, "%s%cgamedata%cepisode", jkRes_curDir, LEC_PATH_SEPARATOR_CHR, LEC_PATH_SEPARATOR_CHR);
                            stdString_snprintf(jkRes_gCtx.aGobDirectories[2].name, 0x80u, "%s%cgamedata%cepisode%c%s", jkRes_curDir, LEC_PATH_SEPARATOR_CHR, LEC_PATH_SEPARATOR_CHR, LEC_PATH_SEPARATOR_CHR, jkRes_episodeGobName);
                            jkRes_NewGob(&jkRes_gCtx.aGobDirectories[2], std_genBuffer, v26);
                        }
                    }
                }
            }
            goto LABEL_39;
        }
        jkRes_FreeGobs(2);
        jkRes_FreeGobs(4);

        v24 = 1;
        if ( cdNumberNeeded )
        {
            v8 = jkStrings_GetUniStringWithFallback("GUI_INSERTCD");
            jk_snwprintf(v28, 0x40u, v8, cdNumberNeeded);
        }
        else
        {
            v7 = jkStrings_GetUniStringWithFallback("GUI_INSERTANYCD");
            jk_snwprintf(v28, 0x40u, v7);
        }
        v9 = jkStrings_GetUniStringWithFallback("GUI_INSERTCDTITLE");
        if ( !jkGuiDialog_OkCancelDialog(v9, v28) )
            break;
LABEL_39:
        if ( v23 )
            return 1;
    }
    //stdString_SafeStrCopy(jkRes_curDir, jkRes_curDir, 128); // TODO ???
    //jkRes_curDir[0] = 0; // Added
    jkRes_curDir[127] = 0;
    jkRes_FreeGobs(4);

    if ( jkRes_curDir[0] )
    {
        stdString_snprintf(a2, 0x80u, "%s%cgamedata%cresource", jkRes_curDir, LEC_PATH_SEPARATOR_CHR, LEC_PATH_SEPARATOR_CHR);
        jkRes_LoadNew(&jkRes_gCtx.aGobDirectories[4], a2, Windows_installType != 9);
    }
    sithMain_SetEpisodeName(jkRes_episodeGobName);
    jkRes_FreeGobs(1);
    jkRes_FreeGobs(2);
    //stdString_SafeStrCopy(jkRes_episodeGobName, jkRes_episodeGobName, 32); // TODO ???

    if ( jkRes_episodeGobName[0] )
    {
        stdString_snprintf(v26, 0x80u, "%s.%s", jkRes_episodeGobName, JKRES_GOB_EXT);
        stdString_snprintf(jkRes_gCtx.aGobDirectories[1].name, 0x80u, "episode%c%s", LEC_PATH_SEPARATOR_CHR, jkRes_episodeGobName);
        jkRes_NewGob(&jkRes_gCtx.aGobDirectories[1], "episode", v26);
        if ( jkRes_curDir[0] )
        {
            if ( Windows_installType < 1 )
            {
                stdString_snprintf(std_genBuffer, 0x80u, "%s%cgamedata%cepisode", jkRes_curDir, LEC_PATH_SEPARATOR_CHR, LEC_PATH_SEPARATOR_CHR);
                stdString_snprintf(jkRes_gCtx.aGobDirectories[2].name, 0x80u, "%s%cgamedata%cepisode%c%s", jkRes_curDir, LEC_PATH_SEPARATOR_CHR, LEC_PATH_SEPARATOR_CHR, LEC_PATH_SEPARATOR_CHR, jkRes_episodeGobName);
                jkRes_NewGob(&jkRes_gCtx.aGobDirectories[2], std_genBuffer, v26);
            }
        }
    }
    return 0;
}

stdFile_t jkRes_FileOpen(const char *fpath, const char *mode)
{

    unsigned int resIdx; // edi
    int success; // esi
    stdFile_t fhand; // eax
    unsigned int v8; // esi
    const char *gobDirectoryName; // eax
    stdFile_t fileHandle; // eax
    unsigned int v13; // esi
    stdGobFile *v14; // eax
    unsigned int v15; // esi
    bool v16; // cf
    stdGob **gobFile; // [esp+10h] [ebp-Ch]
    unsigned int gobIdx; // [esp+14h] [ebp-8h]
    int gobDirectoryIdx; // [esp+18h] [ebp-4h]
    stdPlatform_Printf("Openjkdf2: %s - Opening file: %s with mode: %s\n", __func__, fpath, mode);
    resIdx = 0;
    for (resIdx = 0; resIdx < 32; resIdx++)
    {
        if ( !jkRes_aFiles[resIdx].bOpened )
            break;
    }
    if ( resIdx >= 0x20 )
        return (stdFile_t)0;
    success = 0;

    // Try in the EXE root (not in resource/), ex "3do\key\kysabrf2.key"
    fhand = pLowLevelHS->fileOpen(fpath, mode);
    if ( fhand )
    {
        stdPlatform_Printf("Openjkdf2: %s - Opened file successfully in EXE root: %s\n", __func__, fpath);
        v8 = resIdx;
        jkRes_aFiles[v8].useLowLevel = 1;
        jkRes_aFiles[v8].fsHandle = fhand;
        stdString_SafeStrCopy(jkRes_aFiles[resIdx].fpath, fpath, 128);
        jkRes_aFiles[resIdx].bOpened = 1;
        success = 1;
    }
    else
    {
        for (gobDirectoryIdx = 0; gobDirectoryIdx < 5; gobDirectoryIdx++)
        {
            gobDirectoryName = jkRes_gCtx.aGobDirectories[gobDirectoryIdx].name;
            if (!gobDirectoryName || !gobDirectoryName[0]) continue;

            // Try in episode/[episode name], resource/, etc
            // ex: "episode\JK1\3do\key\kysabrf2.key", "resource/3do\key\kysabrf2.key"
     stdString_snprintf(jkRes_idkGobPath, 0x80u, "%s%c%s", gobDirectoryName, LEC_PATH_SEPARATOR_CHR, fpath);
            fileHandle = pLowLevelHS->fileOpen(jkRes_idkGobPath, mode);
            if ( fileHandle )
            {
                v13 = resIdx;
                jkRes_aFiles[v13].useLowLevel = 1;
                jkRes_aFiles[v13].fsHandle = fileHandle;
                stdString_SafeStrCopy(jkRes_aFiles[resIdx].fpath, jkRes_idkGobPath, 128);
                jkRes_aFiles[resIdx].bOpened = 1;
                success = 1;
            }

            // Try in the GOB itself
            if ( !success )
            {
                for (gobIdx = 0; gobIdx < jkRes_gCtx.aGobDirectories[gobDirectoryIdx].numGobs; gobIdx++)
                {
                    gobFile = &jkRes_gCtx.aGobDirectories[gobDirectoryIdx].gobs[gobIdx];
                    stdPlatform_Printf("Openjkdf2: %s - Trying to open gob: %s\n", __func__, (*gobFile)->fpath);
                    if ( success )
                        break;
                    v14 = stdGob_FileOpen(*gobFile, fpath);
                    if ( v14 )
                    {
                        v15 = resIdx;
                        jkRes_aFiles[v15].useLowLevel = 0;
                        jkRes_aFiles[v15].gobHandle = v14;
                        stdString_SafeStrCopy(jkRes_aFiles[resIdx].fpath, fpath, 128);
                        jkRes_aFiles[resIdx].bOpened = 1;
                        success = 1;
                    }
                }
            }
        }
    }

    if ( !success ) {
        // MOTS added: fail log
        //if (Main_failLogFp) {
        //    fputs(Main_failLogFp, "%s", fpath);
        //}
            stdPlatform_Printf("Openjkdf2: %s - FAILED OPENING FILE: %s\n", __func__, fpath);
        return (stdFile_t)0;
    }
    // Print out if opening was successful based on v6
    //stdPlatform_Printf("Openjkdf2: %s - Opened file successfully in gob %s: %s\n", __func__, (*gobFile)->fpath ,  jkRes_aFiles[resIdx].fpath);
    //stdPlatform_Printf("Openjkdf2: %s - Opened file successfully: %s\n", __func__, jkRes_aFiles[resIdx].fpath);
    return (stdFile_t)(resIdx + 1);
}

int jkRes_FileClose(stdFile_t fd)
{
    jkResFile *resFile = &jkRes_aFiles[fd - 1];

    if (resFile->useLowLevel)
        pLowLevelHS->fileClose(resFile->fsHandle);
    else
        stdGob_FileClose(resFile->gobHandle);

    resFile->bOpened = 0;
    return 0;
}

size_t jkRes_FileRead(stdFile_t fd, void* out, size_t len)
{
    jkResFile *resFile = &jkRes_aFiles[fd - 1];
    //stdPlatform_Printf("Openjkdf2: %s fd: %d len: %zu\n", __func__, fd, len);
    //stdPlatform_Printf("Openjkdf2: %s - use low level: %d\n", __func__, resFile->useLowLevel);


    if ( resFile->useLowLevel )
        return pLowLevelHS->fileRead(resFile->fsHandle, out, len);
    else
        return stdGob_FileRead(resFile->gobHandle, out, len);
}

size_t jkRes_FileWrite(stdFile_t fd, void* out, size_t len)
{
    jkResFile *resFile = &jkRes_aFiles[fd - 1];

    if ( resFile->useLowLevel )
        return pLowLevelHS->fileWrite(resFile->fsHandle, out, len);
    else
        return 0; // GOB has no write function
}

const char* jkRes_FileGets(stdFile_t fd, char* str, size_t n)
{
    jkResFile* resFile = &jkRes_aFiles[fd - 1];
    if (resFile->useLowLevel)
        return pLowLevelHS->fileGets(resFile->fsHandle, str, n);
    else
        return stdGob_FileGets(resFile->gobHandle, str, n);
}

const wchar_t* jkRes_FileGetws(stdFile_t fd, wchar_t* wstr, size_t n)
{
    jkResFile* resFile = &jkRes_aFiles[fd - 1];
    if (resFile->useLowLevel)
        return pLowLevelHS->fileGetws(resFile->fsHandle, wstr, n);
    else
        return stdGob_FileGetws(resFile->gobHandle, wstr, n);
}

int jkRes_FEof(stdFile_t fd)
{
    jkResFile* resFile = &jkRes_aFiles[fd - 1];
    if ( resFile->useLowLevel )
        return pLowLevelHS->fileEof(resFile->fsHandle);
    else
        return stdGob_FEof(resFile->gobHandle);
}

int jkRes_FTell(stdFile_t fd)
{
    jkResFile* resFile = &jkRes_aFiles[fd - 1];
    if ( resFile->useLowLevel )
        return pLowLevelHS->ftell(resFile->fsHandle);
    else
        return stdGob_FTell(resFile->gobHandle);
}

int jkRes_FSeek(stdFile_t fd, int offs, int whence)
{
    jkResFile* resFile = &jkRes_aFiles[fd - 1];
    if ( resFile->useLowLevel )
        return pLowLevelHS->fseek(resFile->fsHandle, offs, whence);
    else
        return stdGob_FSeek(resFile->gobHandle, offs, whence);
}

int jkRes_FileSize(stdFile_t fd)
{
    // This is implemented wonky in the original? 
    // It assumes GOB just doesn't exist and goes straight to pLowLevelHS...
    // I'm just going to fix the impl for now.

    jkResFile* resFile = &jkRes_aFiles[fd - 1];
    if ( resFile->useLowLevel )
        return pLowLevelHS->fileSize(resFile->fsHandle);
    else
        return stdGob_FileSize(resFile->gobHandle);
}

int jkRes_FilePrintf(stdFile_t fd, const char* fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    
    jkResFile* resFile = &jkRes_aFiles[fd - 1];
    
    int v3 = __vsnprintf(std_genBuffer, 0x400u, fmt, va);
    va_end(va);
    
    // No GOB impl
    if ( resFile->useLowLevel )
        return pLowLevelHS->filePrintf(resFile->fsHandle, std_genBuffer, v3);

    return 0;
}
