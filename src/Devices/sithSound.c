#include "sithSound.h"

#include "Win95/stdSound.h"
#include "General/stdHashtbl.h"
#include "General/stdString.h"
#include "General/stdFnames.h"
#include "World/sithWorld.h"
#include "stdPlatform.h" // Added: word-safe read bounce for VRAM-resident PCM
#include "jk.h"

#ifdef NO_JK_MMAP
// Published sound pointers are retained by classes, mixer voices and sectors.
// Overflow pages never move; the legacy world layout and initial array remain.
typedef struct sithSoundPage {
    struct sithSoundPage *next;
    SithWorld *world;
    int first;
    int count;
    sithSound records[];
} sithSoundPage;

static sithSoundPage *sithSound_pages;

static sithSoundPage *sithSound_NewPage(SithWorld *world)
{
    if (world->numSounds < 1 || world->numSounds >= SITHSOUND_MAX_RECORDS)
        return NULL;
    int count = SITHSOUND_MAX_RECORDS - world->numSounds;
    if (count > SITHSOUND_PAGE_RECORDS)
        count = SITHSOUND_PAGE_RECORDS;
    sithSoundPage *page = SITH_ALLOC(sizeof(*page) + sizeof(sithSound) * count);
    if (!page)
        return NULL;
    _memset(page, 0, sizeof(*page) + sizeof(sithSound) * count);
    page->world = world;
    page->first = world->numSounds;
    page->count = count;
    return page;
}

static int sithSound_ParseCount(const char *text, int *count)
{
    int value = 0;
    if (!text || !*text)
        return 0;
    for (; *text; ++text) {
        if (*text < '0' || *text > '9'
            || value > (SITHSOUND_MAX_RECORDS - (*text - '0')) / 10)
            return 0;
        value = value * 10 + (*text - '0');
    }
    *count = value;
    return 1;
}
#endif

static sithSound *sithSound_GetAllocatedSound(SithWorld *world, int idx)
{
    if (!world || !world->sounds || idx < 0 || idx >= world->numSounds)
        return NULL;
#ifdef NO_JK_MMAP
    int baseCount = world->numSounds;
    for (sithSoundPage *page = sithSound_pages; page; page = page->next) {
        if (page->world != world)
            continue;
        if (idx >= page->first && idx - page->first < page->count)
            return &page->records[idx - page->first];
        if (page->first < baseCount)
            baseCount = page->first;
    }
    if (idx >= baseCount)
        return NULL;
#endif
    return &world->sounds[idx];
}

sithSound *sithSound_GetWorldSoundByIndex(SithWorld *world, int idx)
{
    if (!world || idx < 0 || idx >= world->numSoundsLoaded)
        return NULL;
    return sithSound_GetAllocatedSound(world, idx);
}

// Un-inlined: searches semicolon-delimited directory list for a sound file.
// Returns file handle on success, 0 on failure. outPath receives the full path found.
static stdFile_t sithSound_FindInSearchPaths(const char *filename, char *outPath, int outPathSize)
{
    char dirBuf[128];
    char *searchPaths = "sound;voice";
    while ( 1 )
    {
        searchPaths = stdString_CopyBetweenDelimiter(searchPaths, dirBuf, 128, ";");
        if ( dirBuf[0] )
        {
            stdString_snprintf(outPath, outPathSize, "%s%c%s", dirBuf, '\\', filename);
            stdFile_t fd = pSithHS->fileOpen(outPath, "rb");
            if ( fd )
                return fd;
        }
        if ( !searchPaths )
            return 0;
    }
}

int sithSound_Startup()
{
#ifdef TARGET_RETRO_HOMEBREW
    if (openjkdf2_bIsExtraLowMemoryPlatform)
        sithSound_maxDataLoaded = 0x60000;
    else
        sithSound_maxDataLoaded = 0x200000;
#elif defined(QOL_IMPROVEMENTS)
    sithSound_maxDataLoaded = 0x4000000; // 64MiB
#endif

    if ( stdSound_Startup() )
    {
        sithSound_hashtable = stdHashtbl_New(256);
        if ( sithSound_hashtable )
        {
            sithSound_bInit = 1;
            return 1;
        }
    }
    return 0;
}

int sithSound_Shutdown()
{
    if ( !sithSound_bInit )
        return 0;

    stdSound_Shutdown();
    if ( sithSound_hashtable )
    {
        stdHashtbl_Free(sithSound_hashtable);
        sithSound_hashtable = 0;
    }

    sithSound_bInit = 0;
    return 1;
}

int sithSound_ReadSoundsListText(SithWorld *pWorld, int bSkip)
{
    int numSounds; // eax

    SITH_ASSERTREL(pWorld); // Added: from OpenJones3D

    if ( bSkip )
        return 0;

    sithWorld_UpdateLoadProgress(0.0);
    if (!stdConffile_ReadArgs() 
        || _strcmp(stdConffile_g_entry.aArgs[0].value, "world") 
        || _strcmp(stdConffile_g_entry.aArgs[1].value, "sounds") )
    {
        sithSound_FreeWorldSounds(pWorld);
        return 0;
    }
#ifdef NO_JK_MMAP
    if (stdConffile_g_entry.numArgs < 3
        || !sithSound_ParseCount(stdConffile_g_entry.aArgs[2].value, &numSounds))
        return 0;
#else
    numSounds = _atoi(stdConffile_g_entry.aArgs[2].value);
#endif
    if ( !numSounds )
        return 1;

#ifdef NO_JK_MMAP
    if (!sithSound_New(pWorld, numSounds))
        return 0;
#else
    sithSound_New(pWorld, numSounds);
#endif
    
    while ( stdConffile_ReadArgs() )
    {
        if ( !_strcmp(stdConffile_g_entry.aArgs[0].value, "end") )
            break;
        if ( sithSound_bInit )
            sithSound_Load(stdConffile_g_entry.aArgs[0].value, stdConffile_g_entry.numArgs > 1u);
    }
    return 1;
}

void sithSound_FreeWorldSounds(SithWorld *pWorld)
{
    SITH_ASSERTREL(pWorld != NULL); // Added: from OpenJones3D

    if (pWorld->sounds)
    {
        for (int i = 0; i < pWorld->numSoundsLoaded; i++)
        {
            sithSound *sound = sithSound_GetWorldSoundByIndex(pWorld, i);
            if (sound) {
                sithSound_UnloadData(sound);
                stdHashtbl_Remove(sithSound_hashtable, sound->sound_fname);
            }
        }
#ifdef NO_JK_MMAP
        sithSoundPage **link = &sithSound_pages;
        while (*link) {
            sithSoundPage *page = *link;
            if (page->world == pWorld) {
                *link = page->next;
                SITH_FREE(page);
            }
            else {
                link = &page->next;
            }
        }
#endif
        SITH_FREE(pWorld->sounds);
        pWorld->numSoundsLoaded = 0;
        pWorld->numSounds = 0;
        pWorld->sounds = 0;
    }
}

// MOTS altered
int sithSound_New(SithWorld *world, int num)
{
#ifdef NO_JK_MMAP
    if (!world || world->sounds || world->numSounds || world->numSoundsLoaded
        || num < 0 || num > SITHSOUND_MAX_RECORDS - (Main_bMotsCompat != 0))
        return 0;
#endif
    // MOTS added: reserve sound 0?
    if (Main_bMotsCompat) {
        num++;
    }

#ifdef NO_JK_MMAP
    if (!num)
        num = 1; // A lazily populated empty world must remain visible to cleanup.
#endif

    sithSound* sounds  = (sithSound *)SITH_ALLOC(sizeof(sithSound) * num);
#ifndef NO_JK_MMAP
    world->sounds = sounds;
#endif
    if ( sounds )
    {
        _memset(sounds, 0, sizeof(sithSound) * num);
        world->sounds = sounds;
        world->numSounds = num;
        world->numSoundsLoaded = 0;

        //  MOTS added TODO: wat?
        if (Main_bMotsCompat) {
            //world->numSoundsLoaded = 1;
        }
        return 1;
    }
    return 0;
}

sithSound* sithSound_Load(char *sound_fname, int a2)
{
    stdFile_t sound_file; // ebp
    sithSound *sound = NULL; // esi
#ifdef NO_JK_MMAP
    sithSoundPage *pendingPage = NULL;
#endif
    uint32_t v7; // eax
    uint32_t v10; // eax
    uint32_t frequencyKHz; // eax
    struct HostServices *v12; // ecx
    char tmp2[128];

    sound_file = 0;

    SITH_ASSERTREL(sound_fname != NULL); // Added: from OpenJones3D (filename)

    if ( !sithSound_bInit )
        return 0;

    if ( !_strcmp(sound_fname, "none") )
        return 0;

    //printf("sithSound_Load %s\n", sound_fname);
    sound = (sithSound *)stdHashtbl_Find(sithSound_hashtable, sound_fname);
    if ( sound )
    {
        if ( a2 && (sound->isLoaded & 1) == 0 )
        {
            sithSound_LoadFileData(sound);
            return sound;
        }
        return sound;
    }

    sound_file = sithSound_FindInSearchPaths(sound_fname, tmp2, 128);
    if ( !sound_file )
        return 0;

#ifdef NO_JK_MMAP
    if (!sithWorld_g_pLastLoadedWorld)
        goto fail;
    if (!sithWorld_g_pLastLoadedWorld->sounds
        && !sithSound_New(sithWorld_g_pLastLoadedWorld, 0))
        goto fail;
    if (sithWorld_g_pLastLoadedWorld->numSoundsLoaded == sithWorld_g_pLastLoadedWorld->numSounds) {
        pendingPage = sithSound_NewPage(sithWorld_g_pLastLoadedWorld);
        if (!pendingPage)
            goto fail;
    }
    if (pendingPage || sithWorld_g_pLastLoadedWorld->numSoundsLoaded < sithWorld_g_pLastLoadedWorld->numSounds)
#else
    if ( sithWorld_g_pLastLoadedWorld->numSoundsLoaded < sithWorld_g_pLastLoadedWorld->numSounds )
#endif
    {
#ifdef NO_JK_MMAP
        sound = pendingPage ? &pendingPage->records[0] :
            sithSound_GetAllocatedSound(sithWorld_g_pLastLoadedWorld, sithWorld_g_pLastLoadedWorld->numSoundsLoaded);
        if (!sound)
            goto fail;
#else
        sound = &sithWorld_g_pLastLoadedWorld->sounds[sithWorld_g_pLastLoadedWorld->numSoundsLoaded];
#endif
        sound->id = sithWorld_g_pLastLoadedWorld->numSoundsLoaded;
        if ((sithWorld_g_pLastLoadedWorld->level_type_maybe & 1))
        {
            sound->id |= 0x8000;
        }
        stdString_SafeStrCopy(sound->sound_fname, sound_fname, 32);
        sound->bufferBytes = stdSound_ParseWav(sound_file, &sound->sampleRate, &sound->bitsPerSample, &sound->bStereo, &sound->seekOffset);
        if ( sound->bufferBytes )
        {
            frequencyKHz = sound->bufferBytes / (sound->sampleRate / 1000u);

            sound->sound_len = frequencyKHz;
            if ( sound->bitsPerSample == 16 )
                sound->sound_len = frequencyKHz / 2;
            if ( sound->bitsPerSample == 24 ) // Added
                sound->sound_len = frequencyKHz / 3;
            if ( sound->bStereo )
                sound->sound_len = sound->sound_len >> 1;
            sound->isLoaded = 0;
            sound->infoLoaded = 1;
#ifdef NO_JK_MMAP
            if (!stdHashtbl_Add(sithSound_hashtable, sound->sound_fname, sound))
                goto fail;
            if (pendingPage) {
                pendingPage->next = sithSound_pages;
                sithSound_pages = pendingPage;
                sithWorld_g_pLastLoadedWorld->numSounds += pendingPage->count;
                pendingPage = NULL;
            }
#else
            stdHashtbl_Add(sithSound_hashtable, sound->sound_fname, sound);
#endif
            v12 = pSithHS;
            ++sithWorld_g_pLastLoadedWorld->numSoundsLoaded;
            v12->fileClose(sound_file);
            return sound;
        }
    }
#ifdef NO_JK_MMAP
fail:
    if (sound)
        _memset(sound, 0, sizeof(*sound));
    if (pendingPage)
        SITH_FREE(pendingPage);
#endif
    if ( sound_file )
        pSithHS->fileClose(sound_file);
    return 0;
}

sithSound* sithSound_GetFromIdx(int idx)
{
    SithWorld* world = sithWorld_g_pCurrentWorld;

    if (idx & 0x8000)
    {
        world = sithWorld_g_pStaticWorld;
        idx &= ~0x8000;
    }

    return sithSound_GetWorldSoundByIndex(world, idx);
}


#ifdef TARGET_RETRO_HOMEBREW
// Added: fileRead byte-writes into the destination, but long-sound PCM may live
// in word-addressable-only memory (DC VRAM arena). Bounce those through a chunk
// buffer with word-safe copies; everything else reads direct.
static int sithSound_ReadIntoBuffer(int fd, void* pDst, int len)
{
    if (!stdPlatform_IsWordAddressableOnly(pDst))
        return pSithHS->fileRead(fd, pDst, len);

    static char aBounce[16384]; // sound loads are main-thread only
    char* pOut = (char*)pDst;
    int total = 0;
    while (total < len) {
        int chunk = len - total;
        if (chunk > (int)sizeof(aBounce)) chunk = (int)sizeof(aBounce);
        int got = pSithHS->fileRead(fd, aBounce, chunk);
        if (got <= 0) break;
        stdPlatform_Memcpy32(pOut + total, aBounce, got);
        total += got;
        if (got < chunk) break;
    }
    return total;
}
#else
#define sithSound_ReadIntoBuffer(fd, pDst, len) pSithHS->fileRead((fd), (pDst), (len))
#endif

int sithSound_LoadFileData(sithSound *sound)
{
    void *buf; // ebp
    int32_t bufferMaxSize; // [esp+10h] [ebp-84h] BYREF
    char outstr2[128];

    stdFile_t fd = 0;
    if (sound->isLoaded & 1)
        return 0;

    if ( sound->bufferBytes + sithSound_curDataLoaded > sithSound_maxDataLoaded )
        sithSound_FreeUpMemory(sound->bufferBytes + 0x19000);
    stdSound_buffer_t* dsoundBuf = stdSound_BufferCreate(sound->bStereo, sound->sampleRate, sound->bitsPerSample, sound->bufferBytes);
    if ( dsoundBuf )
    {
        sound->dsoundBuffer2 = dsoundBuf;
        sithSound_curDataLoaded += sound->bufferBytes;
        
        fd = sithSound_FindInSearchPaths(sound->sound_fname, outstr2, 128);
        if ( fd )
        {
            pSithHS->fseek(fd, sound->seekOffset, 0);
            // Added: on TWL the ARM9 mixes from source PCM, so it can live in
            // extram (the fill below goes through the word-safe read bounce);
            // only the ARM7-visible mix output buffer needs HEAP_AUDIO.
            { TWL_EXTRAM_SUGGEST(pSithHS);
            buf = stdSound_BufferSetData(sound->dsoundBuffer2, sound->bufferBytes, &bufferMaxSize);
            TWL_EXTRAM_RESTORE(pSithHS); }
            if ( buf )
            {
                int numRead = sithSound_ReadIntoBuffer(fd, buf, bufferMaxSize); // Added: word-safe for VRAM-resident PCM
                if ( stdSound_BufferUnlock(sound->dsoundBuffer2, buf, numRead) )
                {
                    sound->isLoaded |= 1u;
                    pSithHS->fileClose(fd);
                    return 1;
                }
            }
        }
    }
    if ( fd )
        pSithHS->fileClose(fd);
    if ( sound->dsoundBuffer2 )
    {
        stdSound_BufferRelease(sound->dsoundBuffer2);
        // Added: the counterpart of the += above -- a failed load must not leak
        // accounting, or curDataLoaded inflates until no sound can ever load again.
        sithSound_curDataLoaded -= sound->bufferBytes;
    }
    sound->dsoundBuffer2 = 0;
    return 0;
}

int sithSound_UnloadData(sithSound *sound)
{
    if (!(sound->isLoaded & 1)) {
        return 0;
    }

    stdSound_BufferRelease(sound->dsoundBuffer2);
    sound->isLoaded &= ~1u;
    sound->dsoundBuffer2 = 0;
    sithSound_curDataLoaded -= sound->bufferBytes;
    return 1;
}

stdSound_buffer_t* sithSound_LoadData(sithSound *sound)
{
    if (!(sound->isLoaded & 1))
    {
        //printf("sithSound_LoadData %s\n", sound->sound_fname);
        sithSound_LoadFileData(sound);
        if (!(sound->isLoaded & 1))
            return 0;
    }

    sound->infoLoaded = 1;
    return stdSound_BufferDuplicate(sound->dsoundBuffer2);
}

int sithSound_ReadDataFromFd(int fd, sithSound *sound)
{
    void *data;

    int32_t bufferBytes;
    { TWL_EXTRAM_SUGGEST(pSithHS); // Added: see sithSound_LoadFileData
    data = stdSound_BufferSetData(sound->dsoundBuffer2, sound->bufferBytes, &bufferBytes);
    TWL_EXTRAM_RESTORE(pSithHS); }
    if ( data )
    {
        int amt = sithSound_ReadIntoBuffer(fd, data, bufferBytes); // Added: word-safe for VRAM-resident PCM
        return stdSound_BufferUnlock(sound->dsoundBuffer2, data, amt);
    }
    return 0;
}

int sithSound_FreeUpMemory(uint32_t numBytesNeeded)
{
    SithWorld *world; // edi
    int result; // eax
    int v8; // [esp+10h] [ebp-Ch]
    int v9; // [esp+14h] [ebp-8h]
    unsigned int v10; // [esp+18h] [ebp-4h]

    v8 = sithSound_var5;
    v10 = 0;
    v9 = 0;
    while ( 1 )
    {
        world = sithWorld_g_pCurrentWorld;
        if ( v8 )
        {
            world = sithWorld_g_pStaticWorld;
            if (!world)
                world = sithWorld_g_pCurrentWorld;
            else if(!world) // Added: allow freeing sounds during loading
                world = sithWorld_g_pLastLoadedWorld;
            else
                v8 = 0;
        }

        // Added: Prevent nullptr deref
        if (!world) {
            return 0;
        }

        for (uint32_t v3 = sithSound_var4; v3 < world->numSoundsLoaded; v3++)
        {
            sithSound *sound = sithSound_GetWorldSoundByIndex(world, v3);
            if (sound && (sound->isLoaded & 1)
                && !sound->field_40
                && !stdSound_IsPlaying(sound->dsoundBuffer2, 0))
            {
                if (sound->infoLoaded)
                {
                    sound->infoLoaded = 0;
                }
                else
                {
                    result = sound->bufferBytes + v9;
                    v9 = result;
                    if ((sound->isLoaded & 1))
                    {
                        stdSound_BufferRelease(sound->dsoundBuffer2);
                        sound->isLoaded &= ~1u;
                        sound->dsoundBuffer2 = 0;
                        sithSound_curDataLoaded -= sound->bufferBytes;
                        result = v9;
                    }
                    if ( result >= numBytesNeeded )
                    {
                        sithSound_var5 = v8;
                        sithSound_var4 = v3 + 1;
                        return result;
                    }
                }
            }
        }
        if ( v10 >= 2 )
            return 0;
        ++v10;
        sithSound_var4 = 0;
        v8 = v8 == 0;
        sithSound_var4 = 0;
    }
}

stdSound_buffer_t* sithSound_InitFromPath(char *path)
{
    stdFile_t fd; // ebx
    int bufferLen; // edi
    stdSound_buffer_t *createdBuf; // eax
    stdSound_buffer_t *dsoundBuf; // esi
    int32_t bStereo; // [esp+Ch] [ebp-94h] BYREF
    int32_t bufferMaxSize; // [esp+10h] [ebp-90h] BYREF
    uint32_t nSamplesPerSec; // [esp+14h] [ebp-8Ch] BYREF
    int32_t offset; // [esp+18h] [ebp-88h] BYREF
    int32_t bitsPerSample; // [esp+1Ch] [ebp-84h] BYREF
    char tmp[128]; // [esp+20h] [ebp-80h] BYREF

    if (!path)
        return NULL;

    _sprintf(tmp, "sound%c%s", LEC_PATH_SEPARATOR_CHR, path);
    fd = pSithHS->fileOpen(tmp, "rb");
    if ( fd )
    {
        bufferLen = stdSound_ParseWav(fd, &nSamplesPerSec, &bitsPerSample, &bStereo, &offset);
        if ( bufferLen )
        {
            createdBuf = stdSound_BufferCreate(bStereo, nSamplesPerSec, bitsPerSample, bufferLen);
            dsoundBuf = createdBuf;
            if ( createdBuf )
            {
                void* data = stdSound_BufferSetData(createdBuf, bufferLen, &bufferMaxSize);
                if ( !data )
                    return NULL;
                size_t amtRead = pSithHS->fileRead(fd, (void *)data, bufferMaxSize);
                if ( stdSound_BufferUnlock(dsoundBuf, data, amtRead) )
                {
                    pSithHS->fileClose(fd);
                    return dsoundBuf;
                }
            }
        }
        else
        {
            //dsoundBuf = (stdSound_buffer_t *)offset;
            // Added: fix undefined behavior?
            dsoundBuf = NULL;
        }
        pSithHS->fileClose(fd);
        if ( dsoundBuf )
            stdSound_BufferRelease(dsoundBuf);
    }
    return NULL;
}
