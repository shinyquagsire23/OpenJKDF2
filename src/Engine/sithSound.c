#include "sithSound.h"

#include "Win95/stdSound.h"
#include "General/stdHashTable.h"
#include "General/stdString.h"
#include "World/sithWorld.h"
#include "jk.h"

int sithSound_Startup()
{
    if ( stdSound_Initialize() )
    {
        sithSound_hashtable = stdHashTable_New(256);
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
        stdHashTable_Free(sithSound_hashtable);
        sithSound_hashtable = 0;
    }

    sithSound_bInit = 0;
    return 1;
}

int sithSound_Load(sithWorld *world, int a2)
{
    int numSounds; // eax

    if ( a2 )
        return 0;

    sithWorld_UpdateLoadPercent(0.0);
    if (!stdConffile_ReadArgs() 
        || _strcmp(stdConffile_entry.args[0].value, "world") 
        || _strcmp(stdConffile_entry.args[1].value, "sounds") )
    {
        sithSound_Free(world);
        return 0;
    }
    numSounds = _atoi(stdConffile_entry.args[2].value);
    if ( !numSounds )
        return 1;

    sithSound_New(world, numSounds);
    
    while ( stdConffile_ReadArgs() )
    {
        if ( !_strcmp(stdConffile_entry.args[0].value, "end") )
            break;
        if ( sithSound_bInit )
            sithSound_LoadEntry(stdConffile_entry.args[0].value, stdConffile_entry.numArgs > 1u);
    }
    return 1;
}

void sithSound_Free(sithWorld *world)
{
    if (world->sounds)
    {
        for (int i = 0; i < world->numSoundsLoaded; i++)
        {
            sithSound_UnloadData(&world->sounds[i]);
            stdHashTable_FreeKey(sithSound_hashtable, world->sounds[i].sound_fname);
        }
        pSithHS->free(world->sounds);
        world->numSoundsLoaded = 0;
        world->numSounds = 0;
        world->sounds = 0;
    }
}

int sithSound_New(sithWorld *world, int num)
{
    sithSound* sounds  = (sithSound *)pSithHS->alloc(sizeof(sithSound) * num);
    world->sounds = sounds;
    if ( sounds )
    {
        _memset(sounds, 0, sizeof(sithSound) * num);
        world->numSounds = num;
        world->numSoundsLoaded = 0;
        return 1;
    }
    return 0;
}

sithSound* sithSound_LoadEntry(char *sound_fname, int a2)
{
    int sound_file; // ebp
    sithSound *sound; // esi
    int v5; // edi
    char *v6; // esi
    unsigned int v7; // eax
    unsigned int v10; // eax
    unsigned int frequencyKHz; // eax
    struct common_functions *v12; // ecx
    char tmp[128]; // [esp+14h] [ebp-80h] BYREF

    sound_file = 0;

    if ( !sithSound_bInit )
        return 0;

    if ( !_strcmp(sound_fname, "none") )
        return 0;

    sound = (sithSound *)stdHashTable_GetKeyVal(sithSound_hashtable, sound_fname);
    if ( sound )
    {
        if ( a2 && (sound->isLoaded & 1) == 0 )
        {
            sithSound_LoadFileData(sound);
            return sound;
        }
        return sound;
    }

    // inlined
    v5 = 0;
    v6 = "sound;voice";
    while ( 1 )
    {
        v6 = stdString_CopyBetweenDelimiter(v6, tmp, 128, ";");
        if ( tmp[0] )
        {
            _sprintf(tmp, "%s%c%s", tmp, '\\', sound_fname);
            sound_file = pSithHS->fileOpen(tmp, "rb");
            if ( sound_file )
                break;
        }
        if ( !v6 )
            return 0;
    }
    v5 = 1;
    // end inlined

    if ( !v5 )
        return 0;

    if ( sithWorld_pLoading->numSoundsLoaded < sithWorld_pLoading->numSounds )
    {
        sound = &sithWorld_pLoading->sounds[sithWorld_pLoading->numSoundsLoaded];
        sound->id = sithWorld_pLoading->numSoundsLoaded;
        if ((sithWorld_pLoading->level_type_maybe & 1))
        {
            sound->id |= 0x8000;
        }
        _strncpy(sound->sound_fname, sound_fname, 0x1Fu);
        sound->sound_fname[31] = 0;
        sound->bufferBytes = stdSound_ParseWav(sound_file, &sound->sampleRateHz, &sound->bitsPerSample, &sound->bStereo, &sound->seekOffset);
        if ( sound->bufferBytes )
        {
            frequencyKHz = sound->bufferBytes / (sound->sampleRateHz / 1000u);

            sound->sound_len = frequencyKHz;
            if ( sound->bitsPerSample == 16 )
                sound->sound_len = frequencyKHz >> 1;
            if ( sound->bStereo )
                sound->sound_len = sound->sound_len >> 1;
            sound->isLoaded = 0;
            sound->infoLoaded = 1;
            stdHashTable_SetKeyVal(sithSound_hashtable, sound->sound_fname, sound);
            v12 = pSithHS;
            ++sithWorld_pLoading->numSoundsLoaded;
            v12->fileClose(sound_file);
            return sound;
        }
    }
    if ( sound_file )
        pSithHS->fileClose(sound_file);
    return 0;
}

sithSound* sithSound_GetFromIdx(int idx)
{
    sithWorld* world = sithWorld_pCurWorld;

    if (idx & 0x8000)
    {
        world = sithWorld_pStatic;
        idx &= ~0x8000;
    }

    if ( idx < 0 || idx >= world->numSoundsLoaded )
        return 0;


    return &world->sounds[idx];
}

int sithSound_LoadFileData(sithSound *sound)
{
    void *buf; // ebp
    int32_t bufferMaxSize; // [esp+10h] [ebp-84h] BYREF
    char outstr[128]; // [esp+14h] [ebp-80h] BYREF

    int fd = 0;
    if (sound->isLoaded & 1)
        return 0;

    if ( sound->bufferBytes + sithSound_curDataLoaded > sithSound_maxDataLoaded )
        sithSound_StopAll(sound->bufferBytes + 0x19000);
    stdSound_buffer_t* dsoundBuf = stdSound_BufferCreate(sound->bStereo, sound->sampleRateHz, sound->bitsPerSample, sound->bufferBytes);
    if ( dsoundBuf )
    {
        sound->dsoundBuffer2 = dsoundBuf;
        sithSound_curDataLoaded += sound->bufferBytes;
        
        // inlined
        int v5 = 0;
        char* v6 = "sound;voice";
        while ( 1 )
        {
            v6 = stdString_CopyBetweenDelimiter(v6, outstr, 128, ";");
            if ( outstr[0] )
            {
                _sprintf(outstr, "%s%c%s", outstr, '\\', sound->sound_fname);
                fd = pSithHS->fileOpen(outstr, "rb");
                if ( fd )
                    break;
            }
            if ( !v6 )
                goto LABEL_11;
        }
        v5 = 1;
        // end inlined

LABEL_11:
        if ( v5 )
        {
            pSithHS->fseek(fd, sound->seekOffset, 0);
            buf = stdSound_BufferSetData(sound->dsoundBuffer2, sound->bufferBytes, &bufferMaxSize);
            if ( buf )
            {
                int numRead = pSithHS->fileRead(fd, buf, bufferMaxSize);
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
        stdSound_BufferRelease(sound->dsoundBuffer2);
    sound->dsoundBuffer2 = 0;
    return 0;
}

int sithSound_UnloadData(sithSound *sound)
{
    if (!(sound->isLoaded & 1))
        return 0;

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
    data = stdSound_BufferSetData(sound->dsoundBuffer2, sound->bufferBytes, &bufferBytes);
    if ( data )
    {
        int amt = pSithHS->fileRead(fd, data, bufferBytes);
        return stdSound_BufferUnlock(sound->dsoundBuffer2, data, amt);
    }
    return 0;
}

int sithSound_StopAll(uint32_t idk)
{
    sithWorld *world; // edi
    int result; // eax
    int v8; // [esp+10h] [ebp-Ch]
    int v9; // [esp+14h] [ebp-8h]
    unsigned int v10; // [esp+18h] [ebp-4h]

    v8 = sithSound_var5;
    v10 = 0;
    v9 = 0;
    while ( 1 )
    {
        world = sithWorld_pCurWorld;
        if ( v8 )
        {
            world = sithWorld_pStatic;
            if (!world)
                world = sithWorld_pCurWorld;
            else
                v8 = 0;
        }

        for (uint32_t v3 = sithSound_var4; v3 < world->numSoundsLoaded; v3++)
        {
            if ((world->sounds[v3].isLoaded & 1) 
                && !world->sounds[v3].field_40
                && !stdSound_IsPlaying(world->sounds[v3].dsoundBuffer2, 0))
            {
                if (world->sounds[v3].infoLoaded)
                {
                    world->sounds[v3].infoLoaded = 0;
                }
                else
                {
                    result = world->sounds[v3].bufferBytes + v9;
                    v9 = result;
                    if ((world->sounds[v3].isLoaded & 1))
                    {
                        stdSound_BufferRelease(world->sounds[v3].dsoundBuffer2);
                        world->sounds[v3].isLoaded &= ~1u;
                        world->sounds[v3].dsoundBuffer2 = 0;
                        sithSound_curDataLoaded -= world->sounds[v3].bufferBytes;
                        result = v9;
                    }
                    if ( result >= idk )
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
    int fd; // ebx
    int bufferLen; // edi
    stdSound_buffer_t *createdBuf; // eax
    stdSound_buffer_t *dsoundBuf; // esi
    int bStereo; // [esp+Ch] [ebp-94h] BYREF
    int32_t bufferMaxSize; // [esp+10h] [ebp-90h] BYREF
    int nSamplesPerSec; // [esp+14h] [ebp-8Ch] BYREF
    int seekOffs; // [esp+18h] [ebp-88h] BYREF
    int bitsPerSample; // [esp+1Ch] [ebp-84h] BYREF
    char tmp[128]; // [esp+20h] [ebp-80h] BYREF

    if (!path)
        return NULL;

    _sprintf(tmp, "sound%c%s", 92, path);
    fd = pSithHS->fileOpen(tmp, "rb");
    if ( fd )
    {
        bufferLen = stdSound_ParseWav(fd, &nSamplesPerSec, &bitsPerSample, &bStereo, &seekOffs);
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
            //dsoundBuf = (stdSound_buffer_t *)seekOffs;
            // Added: fix undefined behavior?
            dsoundBuf = NULL;
        }
        pSithHS->fileClose(fd);
        if ( dsoundBuf )
            stdSound_BufferRelease(dsoundBuf);
    }
    return NULL;
}

