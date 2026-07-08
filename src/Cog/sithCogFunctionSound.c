#include "sithCogFunctionSound.h"

#include "Devices/sithSoundMixer.h"
#include "World/sithSoundClass.h"
#include "Devices/sithSound.h"
#include "World/sithSector.h"
#include "Dss/sithDSSThing.h"
#include "Main/Main.h"

void sithCogFunctionSound_PlaySong(sithCog *pCog)
{
    int trackFrom = sithCogExec_PopInt(pCog);
    int trackTo = sithCogExec_PopInt(pCog);
    int trackNum = sithCogExec_PopInt(pCog);

    if ( trackNum <= 0 )
        sithSoundMixer_StopSong();
    else
        sithSoundMixer_PlaySong(trackFrom, trackTo, trackNum, 1);
}

void sithCogFunctionSound_PlaySoundThing(sithCog *pCog)
{
    flex_d_t maxDist_act; // st7
    __int32 flagsTmp; // ebx
    sithPlayingSound *playingSound; // eax
    sithPlayingSound *playingSound_; // ebp
    int refid_; // eax
    int refid; // eax
    cog_flex_t minDist_act; // [esp+10h] [ebp-Ch]
    cog_flex_t maxDist_act_; // [esp+14h] [ebp-8h]

    int flags = sithCogExec_PopInt(pCog);
    cog_flex_t maxDist = sithCogExec_PopFlex(pCog);
    cog_flex_t minDist = sithCogExec_PopFlex(pCog);
    cog_flex_t volume = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    sithSound* pSound = sithCogExec_PopSound(pCog);

    //printf("sithCogFunctionSound_PlaySoundThing %s\n", ctx->aName);

    if ( !pSound )
    {
        sithCogExec_PushInt(pCog, -1);
        return;
    }

    if ( minDist >= 0.0 )
        minDist_act = minDist * 0.1;
    else
        minDist_act = 0.5;
    if ( maxDist >= 0.0 )
        maxDist_act = maxDist * 0.1;
    else
        maxDist_act = 2.5;
    maxDist_act_ = maxDist_act;
    if ( maxDist_act <= minDist_act )
        maxDist_act_ = minDist_act;
    if ( volume < 0.0 )
    {
        volume = 0.0;
    }
    else if ( volume > 1.5 )
    {
        volume = 1.5;
    }
    if ( pThing )
    {
        if (!(flags & SITHSOUNDFLAG_FOLLOWSTHING))
        {
            flagsTmp = flags | SITHSOUNDFLAG_ABSOLUTE;
            playingSound = sithSoundMixer_PlaySoundPos(pSound, &pThing->position, pThing->sector, volume, minDist_act, maxDist_act_, flagsTmp);
        }
        else
        {
            flagsTmp = flags & ~SITHSOUNDFLAG_ABSOLUTE;
            playingSound = sithSoundMixer_PlaySoundThing(pSound, pThing, volume, minDist_act, maxDist_act_, flagsTmp);
        }
        if (COG_SHOULD_SYNC(pCog))
        {
            if ( playingSound )
                refid_ = playingSound->refid;
            else
                refid_ = -1;
            sithDSSThing_PlaySound(pThing, &pThing->position, pSound, minDist_act, maxDist_act_, flagsTmp, refid_, -1, 255);
        }
    }
    else
    {
        flags &= ~(SITHSOUNDFLAG_FOLLOWSTHING|SITHSOUNDFLAG_ABSOLUTE);
        playingSound = sithSoundMixer_PlaySound(pSound, volume, 0.0, flags);
        if (COG_SHOULD_SYNC(pCog))
        {
            if ( playingSound )
                refid = playingSound->refid;
            else
                refid = -1;
            sithDSSThing_PlaySound(0, 0, pSound, volume, 0.0, flags, refid, -1, 255);
        }
    }
    if ( playingSound )
        sithCogExec_PushInt(pCog, playingSound->refid);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSound_PlaySoundPos(sithCog *pCog)
{
    int flagsTmp; // edi
    sithPlayingSound *playingSound; // eax
    int v7; // ecx
    int refId; // eax
    cog_flex_t maxDist_act; // [esp+10h] [ebp-14h]
    cog_flex_t minDist_act; // [esp+28h] [ebp+4h]

    rdVector3 pos;

    int flags = sithCogExec_PopInt(pCog);
    cog_flex_t maxDist = sithCogExec_PopFlex(pCog);
    cog_flex_t minDist = sithCogExec_PopFlex(pCog);
    cog_flex_t volume = sithCogExec_PopFlex(pCog);
    int posVal = sithCogExec_PopVector(pCog, &pos);
    sithSound* pSound = sithCogExec_PopSound(pCog);

    if ( !pSound || !posVal )
    {
        sithCogExec_PushInt(pCog, -1);
        return;
    }

    minDist_act = minDist >= 0.0 ? (cog_flex_t)(minDist * (cog_flex_t)0.1) : (cog_flex_t)0.5; // FLEXTODO
    maxDist_act = maxDist >= 0.0 ? (cog_flex_t)(maxDist * (cog_flex_t)0.1) : (cog_flex_t)2.5; // FLEXTODO
    if ( volume < 0.0 )
    {
        volume = 0.0;
    }
    else if ( volume > 1.5 )
    {
        volume = 1.5;
    }
    if ( minDist_act > (flex_d_t)maxDist_act )
        maxDist_act = minDist_act;
    flagsTmp = flags | SITHSOUNDFLAG_ABSOLUTE;
    playingSound = sithSoundMixer_PlaySoundPos(pSound, &pos, 0, volume, minDist_act, maxDist_act, flagsTmp);
    if (COG_SHOULD_SYNC(pCog))
    {
        if ( playingSound )
            refId = playingSound->refid;
        else
            refId = -1;

        sithDSSThing_PlaySound(0, &pos, pSound, minDist_act, maxDist_act, flagsTmp, refId, -1, 255);
    }

    if ( playingSound )
        sithCogExec_PushInt(pCog, playingSound->refid);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSound_PlaySoundLocal(sithCog *pCog)
{
    int flags = sithCogExec_PopInt(pCog);
    cog_flex_t pan = sithCogExec_PopFlex(pCog);
    cog_flex_t volume = sithCogExec_PopFlex(pCog);
    sithSound* pSound = sithCogExec_PopSound(pCog);

    //printf("sithCogFunctionSound_PlaySoundLocal %s\n", ctx->aName);

    if (!pSound)
    {
        sithCogExec_PushInt(pCog, -1);
        return;
    }
    
    if ( pan < -1.0 )
    {
        pan = -1.0;
    }
    else if ( pan > 1.0 )
    {
        pan = 1.0;
    }

    if ( volume < 0.0 )
    {
        volume = 0.0;
    }
    else if ( volume > 1.5 )
    {
        volume = 1.5;
    }

    sithPlayingSound* playingSound = sithSoundMixer_PlaySound(pSound, volume, pan, flags & ~(SITHSOUNDFLAG_FOLLOWSTHING|SITHSOUNDFLAG_ABSOLUTE));

    if ( playingSound )
        sithCogExec_PushInt(pCog, playingSound->refid);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSound_PlaySoundGlobal(sithCog *pCog)
{
    int flags = sithCogExec_PopInt(pCog);
    cog_flex_t pan = sithCogExec_PopFlex(pCog);
    cog_flex_t volume = sithCogExec_PopFlex(pCog);
    sithSound* pSound = sithCogExec_PopSound(pCog);

    //printf("sithCogFunctionSound_PlaySoundGlobal %s\n", ctx->aName);

    if (!pSound)
    {
        sithCogExec_PushInt(pCog, -1);
        return;
    }

    if ( pan < -1.0 )
    {
        pan = -1.0;
    }
    else if ( pan > 1.0 )
    {
        pan = 1.0;
    }
    if ( volume < 0.0 )
    {
        volume = 0.0;
    }
    else if ( volume > 1.5 )
    {
        volume = 1.5;
    }

    int flagsTmp = flags & ~(SITHSOUNDFLAG_FOLLOWSTHING|SITHSOUNDFLAG_ABSOLUTE);
    sithPlayingSound* playingSound = sithSoundMixer_PlaySound(pSound, volume, pan, flagsTmp);
    if ( playingSound )
    {
        if (COG_SHOULD_SYNC(pCog))
        {
            sithDSSThing_PlaySound(0, 0, pSound, volume, pan, flagsTmp, playingSound->refid, -1, 255);
        }
        sithCogExec_PushInt(pCog, playingSound->refid);
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionSound_StopSound(sithCog *pCog)
{
    cog_flex_t fadeOut = sithCogExec_PopFlex(pCog);
    int refId = sithCogExec_PopInt(pCog);
    sithPlayingSound* playingSound = sithSoundMixer_GetChannelHandle(refId);

    if ( playingSound && (playingSound->sound || playingSound->pSoundBuf) )
    {
        if (COG_SHOULD_SYNC(pCog))
        {
            sithDSSThing_StopSound(playingSound, fadeOut, -1, 255);
        }
        if ( fadeOut > 0.0 )
        {
            sithSoundMixer_FadeVolume(playingSound, 0.0, fadeOut);
            playingSound->flags |= SITHSOUNDFLAG_FADING;
        }
        else
        {
            sithSoundMixer_StopSound(playingSound);
        }
    }
}

void sithCogFunctionSound_LoadSound(sithCog *pCog)
{
    sithSound* pSound;

    char* path = sithCogExec_PopString(pCog);
    if ( path && (pSound = sithSound_Load(path, 0)) != 0 )
        sithCogExec_PushInt(pCog, pSound->id);
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSound_PlaySoundClass(sithCog *pCog)
{
    sithPlayingSound *pPlayingSound;

    int soundClassId = sithCogExec_PopInt(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);

    if ( pThing && pThing->pSoundClass && (pPlayingSound = sithSoundClass_PlayModeRandom(pThing, soundClassId)) != 0 )
    {
        sithCogExec_PushInt(pCog, pPlayingSound->refid);
        if (COG_SHOULD_SYNC(pCog))
        {
            sithDSSThing_PlaySoundMode(pThing, soundClassId, pPlayingSound->refid, -1.0);
        }
    }
    else
    {
        sithCogExec_PushInt(pCog, -1);
    }
}

void sithCogFunctionSound_ChangeVolume(sithCog *pCog)
{
    cog_flex_t fadeintime_ = sithCogExec_PopFlex(pCog);
    cog_flex_t vol = sithCogExec_PopFlex(pCog);
    int ref = sithCogExec_PopInt(pCog);
    sithPlayingSound* playing_sound = sithSoundMixer_GetChannelHandle(ref);

    if ( playing_sound && fadeintime_ > 0.0 )
    {
        if ( vol < 0.0 )
        {
            vol = 0.0;
        }
        else if ( vol > 1.5 )
        {
            vol = 1.5;
        }
        sithSoundMixer_FadeVolume(playing_sound, vol, fadeintime_);
    }
}

void sithCogFunctionSound_ChangePitch(sithCog *pCog)
{
    cog_flex_t changetime = sithCogExec_PopFlex(pCog);
    cog_flex_t pitch = sithCogExec_PopFlex(pCog);
    int ref = sithCogExec_PopInt(pCog);
    sithPlayingSound* pPlayingSound = sithSoundMixer_GetChannelHandle(ref);

    if ( pPlayingSound && changetime > 0.0 && pitch > 0.0 )
        sithSoundMixer_SetPitch(pPlayingSound, pitch, changetime);
}

void sithCogFunctionSound_SectorSound(sithCog *pCog)
{
    cog_flex_t vol = sithCogExec_PopFlex(pCog);
    sithSound* pSound = sithCogExec_PopSound(pCog);
    SithSector* sector = sithCogExec_PopSector(pCog);

    if ( sector )
        sithSoundMixer_SetSectorAmbientSound(sector, pSound, vol);
}

void sithCogFunctionSound_SetMusicVol(sithCog *pCog)
{
    cog_flex_t vol = sithCogExec_PopFlex(pCog);
    if ( vol < 0.0 )
    {
        vol = 0.0;
    }
    else if ( vol > 1.0 )
    {
        vol = 1.0;
    }
    sithSoundMixer_SetMusicVol(vol);
}

void sithCogFunctionSound_GetSoundLen(sithCog *pCog)
{
    sithSound* pSound = sithCogExec_PopSound(pCog);

    if (pSound)
    {
        sithCogExec_PushFlex(pCog, (flex_d_t)pSound->sound_len * 0.001);
    }
    else
    {
        sithCogExec_PushFlex(pCog, 0.0);
    }
}

// MOTS added
void sithCogFunctionSound_PlaySoundThingLocal(sithCog *pCog)
{
    flex_d_t maxDist_act; // st7
    __int32 flagsTmp; // ebx
    sithPlayingSound *playingSound; // eax
    sithPlayingSound *playingSound_; // ebp
    int refid_; // eax
    int refid; // eax
    cog_flex_t minDist_act; // [esp+10h] [ebp-Ch]
    cog_flex_t maxDist_act_; // [esp+14h] [ebp-8h]

    int flags = sithCogExec_PopInt(pCog);
    cog_flex_t maxDist = sithCogExec_PopFlex(pCog);
    cog_flex_t minDist = sithCogExec_PopFlex(pCog);
    cog_flex_t volume = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    sithSound* pSound = sithCogExec_PopSound(pCog);

    //printf("sithCogFunctionSound_PlaySoundThing %s\n", ctx->aName);

    if ( !pSound )
    {
        sithCogExec_PushInt(pCog, -1);
        return;
    }

    if ( minDist >= 0.0 )
        minDist_act = minDist * 0.1;
    else
        minDist_act = 0.5;
    if ( maxDist >= 0.0 )
        maxDist_act = maxDist * 0.1;
    else
        maxDist_act = 2.5;
    maxDist_act_ = maxDist_act;
    if ( maxDist_act <= minDist_act )
        maxDist_act_ = minDist_act;
    if ( volume < 0.0 )
    {
        volume = 0.0;
    }
    else if ( volume > 1.5 )
    {
        volume = 1.5;
    }
    if ( pThing )
    {
        if (!(flags & SITHSOUNDFLAG_FOLLOWSTHING))
        {
            flagsTmp = flags | SITHSOUNDFLAG_ABSOLUTE;
            playingSound = sithSoundMixer_PlaySoundPos(pSound, &pThing->position, pThing->sector, volume, minDist_act, maxDist_act_, flagsTmp);
        }
        else
        {
            flagsTmp = flags & ~SITHSOUNDFLAG_ABSOLUTE;
            playingSound = sithSoundMixer_PlaySoundThing(pSound, pThing, volume, minDist_act, maxDist_act_, flagsTmp);
        }
    }
    else
    {
        flags &= ~(SITHSOUNDFLAG_FOLLOWSTHING|SITHSOUNDFLAG_ABSOLUTE);
        playingSound = sithSoundMixer_PlaySound(pSound, volume, 0.0, flags);
    }
    if ( playingSound )
        sithCogExec_PushInt(pCog, playingSound->refid);
    else
        sithCogExec_PushInt(pCog, -1);
}

// MOTS added
void sithCogFunctionSound_PlaySoundPosLocal(sithCog *pCog)
{
    sithPlayingSound *playingSound; // eax
    int v7; // ecx
    int refId; // eax
    cog_flex_t maxDist_act; // [esp+10h] [ebp-14h]
    cog_flex_t minDist_act; // [esp+28h] [ebp+4h]

    rdVector3 pos;

    int flags = sithCogExec_PopInt(pCog);
    cog_flex_t maxDist = sithCogExec_PopFlex(pCog);
    cog_flex_t minDist = sithCogExec_PopFlex(pCog);
    cog_flex_t volume = sithCogExec_PopFlex(pCog);
    int posVal = sithCogExec_PopVector(pCog, &pos);
    sithSound* pSound = sithCogExec_PopSound(pCog);

    if ( !pSound || !posVal )
    {
        sithCogExec_PushInt(pCog, -1);
        return;
    }

    minDist_act = minDist >= 0.0 ? (cog_flex_t)(minDist * (cog_flex_t)0.1) : (cog_flex_t)0.5; // FLEXTODO
    maxDist_act = maxDist >= 0.0 ? (cog_flex_t)(maxDist * (cog_flex_t)0.1) : (cog_flex_t)2.5; // FLEXTODO
    if ( volume < 0.0 )
    {
        volume = 0.0;
    }
    else if ( volume > 1.5 )
    {
        volume = 1.5;
    }
    if ( minDist_act > (flex_d_t)maxDist_act )
        maxDist_act = minDist_act;
    playingSound = sithSoundMixer_PlaySoundPos(pSound, &pos, 0, volume, minDist_act, maxDist_act, flags | SITHSOUNDFLAG_ABSOLUTE);

    if ( playingSound )
        sithCogExec_PushInt(pCog, playingSound->refid);
    else
        sithCogExec_PushInt(pCog, -1);
}

// Droidworks added
void sithCogFunctionSound_PlaySoundThingAndWait(sithCog *pCog)
{
    flex_d_t maxDist_act; // st7
    __int32 flagsTmp; // ebx
    sithPlayingSound *playingSound; // eax
    sithPlayingSound *playingSound_; // ebp
    int refid_; // eax
    int refid; // eax
    cog_flex_t minDist_act; // [esp+10h] [ebp-Ch]
    cog_flex_t maxDist_act_; // [esp+14h] [ebp-8h]

    int flags = sithCogExec_PopInt(pCog);
    cog_flex_t maxDist = sithCogExec_PopFlex(pCog);
    cog_flex_t minDist = sithCogExec_PopFlex(pCog);
    cog_flex_t volume = sithCogExec_PopFlex(pCog);
    SithThing* pThing = sithCogExec_PopThing(pCog);
    sithSound* pSound = sithCogExec_PopSound(pCog);

    //printf("sithCogFunctionSound_PlaySoundThing %s\n", ctx->aName);

    if ( !pSound )
    {
        sithCogExec_PushInt(pCog, -1);
        return;
    }

    if ( minDist >= 0.0 )
        minDist_act = minDist * 0.1;
    else
        minDist_act = 0.5;
    if ( maxDist >= 0.0 )
        maxDist_act = maxDist * 0.1;
    else
        maxDist_act = 2.5;
    maxDist_act_ = maxDist_act;
    if ( maxDist_act <= minDist_act )
        maxDist_act_ = minDist_act;
    if ( volume < 0.0 )
    {
        volume = 0.0;
    }
    else if ( volume > 1.5 )
    {
        volume = 1.5;
    }
    if ( pThing )
    {
        if (!(flags & SITHSOUNDFLAG_FOLLOWSTHING))
        {
            flagsTmp = flags | SITHSOUNDFLAG_ABSOLUTE;
            playingSound = sithSoundMixer_PlaySoundPos(pSound, &pThing->position, pThing->sector, volume, minDist_act, maxDist_act_, flagsTmp);
        }
        else
        {
            flagsTmp = flags & ~SITHSOUNDFLAG_ABSOLUTE;
            playingSound = sithSoundMixer_PlaySoundThing(pSound, pThing, volume, minDist_act, maxDist_act_, flagsTmp);
        }
        if (COG_SHOULD_SYNC(pCog))
        {
            if ( playingSound )
                refid_ = playingSound->refid;
            else
                refid_ = -1;
            sithDSSThing_PlaySound(pThing, &pThing->position, pSound, minDist_act, maxDist_act_, flagsTmp, refid_, -1, 255);
        }
    }
    else
    {
        flags &= ~(SITHSOUNDFLAG_FOLLOWSTHING|SITHSOUNDFLAG_ABSOLUTE);
        playingSound = sithSoundMixer_PlaySound(pSound, volume, 0.0, flags);
        if (COG_SHOULD_SYNC(pCog))
        {
            if ( playingSound )
                refid = playingSound->refid;
            else
                refid = -1;
            sithDSSThing_PlaySound(0, 0, pSound, volume, 0.0, flags, refid, -1, 255);
        }
    }
    if ( playingSound ) {
        pCog->script_running = 2;
        pCog->msecTimerTimeout = sithTime_g_msecGameTime + pSound->sound_len;

        sithCogExec_PushInt(pCog, playingSound->refid);
    }
    else
        sithCogExec_PushInt(pCog, -1);
}

void sithCogFunctionSound_Startup(SithCogSymbolTable* pCog)
{
    sithCog_RegisterFunction(pCog, sithCogFunctionSound_PlaySong, "playsong");
    sithCog_RegisterFunction(pCog, sithCogFunctionSound_PlaySoundThing, "playsoundthing");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunctionSound_PlaySoundThingLocal, "playsoundthinglocal");
    }
    sithCog_RegisterFunction(pCog, sithCogFunctionSound_PlaySoundPos, "playsoundpos");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog, sithCogFunctionSound_PlaySoundPosLocal, "playsoundposlocal");
    }
    sithCog_RegisterFunction(pCog, sithCogFunctionSound_PlaySoundLocal, "playsoundlocal");
    sithCog_RegisterFunction(pCog, sithCogFunctionSound_PlaySoundGlobal, "playsoundglobal");
    if (Main_bMotsCompat) {
        sithCog_RegisterFunction(pCog,sithCogFunctionSound_PlaySoundThing,"playvoicething");
        sithCog_RegisterFunction(pCog,sithCogFunctionSound_PlaySoundPos,"playvoicepos");
        sithCog_RegisterFunction(pCog,sithCogFunctionSound_PlaySoundLocal,"playvoicelocal");
        sithCog_RegisterFunction(pCog,sithCogFunctionSound_PlaySoundGlobal,"playvoiceglobal");
    }
    sithCog_RegisterFunction(pCog, sithCogFunctionSound_StopSound, "stopsound");
    sithCog_RegisterFunction(pCog, sithCogFunctionSound_LoadSound, "loadsound");
    sithCog_RegisterFunction(pCog, sithCogFunctionSound_PlaySoundClass, "playsoundclass");
    sithCog_RegisterFunction(pCog, sithCogFunctionSound_ChangeVolume, "changesoundvol");
    sithCog_RegisterFunction(pCog, sithCogFunctionSound_ChangePitch, "changesoundpitch");
    sithCog_RegisterFunction(pCog, sithCogFunctionSound_SectorSound, "sectorsound");
    sithCog_RegisterFunction(pCog, sithCogFunctionSound_SetMusicVol, "setmusicvol");
    sithCog_RegisterFunction(pCog, sithCogFunctionSound_GetSoundLen, "getsoundlen");
    if (Main_bDwCompat) {
        sithCog_RegisterFunction(pCog,sithCogFunctionSound_PlaySoundThingAndWait,"playsoundthingandwait");
    }
}
