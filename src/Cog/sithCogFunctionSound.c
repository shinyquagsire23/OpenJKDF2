#include "sithCogFunctionSound.h"

#include "Engine/sithSoundSys.h"
#include "Engine/sithSoundClass.h"
#include "Engine/sithSound.h"
#include "World/sithSector.h"
#include "Dss/sithDSSThing.h"

void sithCogFunctionSound_PlaySong(sithCog *ctx)
{
    int trackFrom = sithCogVm_PopInt(ctx);
    int trackTo = sithCogVm_PopInt(ctx);
    int trackNum = sithCogVm_PopInt(ctx);

    if ( trackNum <= 0 )
        sithSoundSys_StopSong();
    else
        sithSoundSys_PlaySong(trackFrom, trackTo, trackNum, 1);
}

void sithCogFunctionSound_PlaySoundThing(sithCog *ctx)
{
    double maxDist_act; // st7
    __int32 flagsTmp; // ebx
    sithPlayingSound *playingSound; // eax
    sithPlayingSound *playingSound_; // ebp
    int refid_; // eax
    int refid; // eax
    float minDist_act; // [esp+10h] [ebp-Ch]
    float maxDist_act_; // [esp+14h] [ebp-8h]

    int flags = sithCogVm_PopInt(ctx);
    float maxDist = sithCogVm_PopFlex(ctx);
    float minDist = sithCogVm_PopFlex(ctx);
    float volume = sithCogVm_PopFlex(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);
    sithSound* sound = sithCogVm_PopSound(ctx);

    if ( !sound )
    {
        sithCogVm_PushInt(ctx, -1);
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
    if ( thing )
    {
        if (!(flags & SITHSOUNDFLAG_FOLLOWSTHING))
        {
            flagsTmp = flags | SITHSOUNDFLAG_ABSOLUTE;
            playingSound = sithSoundSys_PlaySoundPosAbsolute(sound, &thing->position, thing->sector, volume, minDist_act, maxDist_act_, flagsTmp);
        }
        else
        {
            flagsTmp = flags & ~SITHSOUNDFLAG_ABSOLUTE;
            playingSound = sithSoundSys_PlaySoundPosThing(sound, thing, volume, minDist_act, maxDist_act_, flagsTmp);
        }
        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200))
        {
            if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
            {
                if ( playingSound )
                    refid_ = playingSound->refid;
                else
                    refid_ = -1;
                sithDSSThing_SendPlaySoundPos(thing, &thing->position, sound, minDist_act, maxDist_act_, flagsTmp, refid_, -1, 255);
            }
        }
    }
    else
    {
        flags &= ~(SITHSOUNDFLAG_FOLLOWSTHING|SITHSOUNDFLAG_ABSOLUTE);
        playingSound = sithSoundSys_cog_playsound_internal(sound, volume, 0.0, flags);
        if (sithCogVm_multiplayerFlags 
            && !(ctx->flags & 0x200))
        {
            if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
            {
                if ( playingSound )
                    refid = playingSound->refid;
                else
                    refid = -1;
                sithDSSThing_SendPlaySoundPos(0, 0, sound, volume, 0.0, flags, refid, -1, 255);
            }
        }
    }
    if ( playingSound )
        sithCogVm_PushInt(ctx, playingSound->refid);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSound_PlaySoundPos(sithCog *ctx)
{
    int flagsTmp; // edi
    sithPlayingSound *playingSound; // eax
    int v7; // ecx
    int refId; // eax
    float maxDist_act; // [esp+10h] [ebp-14h]
    float minDist_act; // [esp+28h] [ebp+4h]

    rdVector3 pos;

    int flags = sithCogVm_PopInt(ctx);
    float maxDist = sithCogVm_PopFlex(ctx);
    float minDist = sithCogVm_PopFlex(ctx);
    float volume = sithCogVm_PopFlex(ctx);
    int posVal = sithCogVm_PopVector3(ctx, &pos);
    sithSound* sound = sithCogVm_PopSound(ctx);

    if ( !sound || !posVal )
    {
        sithCogVm_PushInt(ctx, -1);
        return;
    }

    minDist_act = minDist >= 0.0 ? (float)(minDist * 0.1) : 0.5;
    maxDist_act = maxDist >= 0.0 ? (float)(maxDist * 0.1) : 2.5;
    if ( volume < 0.0 )
    {
        volume = 0.0;
    }
    else if ( volume > 1.5 )
    {
        volume = 1.5;
    }
    if ( minDist_act > (double)maxDist_act )
        maxDist_act = minDist_act;
    flagsTmp = flags | SITHSOUNDFLAG_ABSOLUTE;
    playingSound = sithSoundSys_PlaySoundPosAbsolute(sound, &pos, 0, volume, minDist_act, maxDist_act, flagsTmp);
    if (sithCogVm_multiplayerFlags 
        && !(ctx->flags & 0x200))
    {
        if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
        {
            if ( playingSound )
                refId = playingSound->refid;
            else
                refId = -1;

            sithDSSThing_SendPlaySoundPos(0, &pos, sound, minDist_act, maxDist_act, flagsTmp, refId, -1, 255);
        }
    }

    if ( playingSound )
        sithCogVm_PushInt(ctx, playingSound->refid);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSound_PlaySoundLocal(sithCog *ctx)
{
    int flags = sithCogVm_PopInt(ctx);
    float pan = sithCogVm_PopFlex(ctx);
    float volume = sithCogVm_PopFlex(ctx);
    sithSound* sound = sithCogVm_PopSound(ctx);

    if (!sound)
    {
        sithCogVm_PushInt(ctx, -1);
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

    sithPlayingSound* playingSound = sithSoundSys_cog_playsound_internal(sound, volume, pan, flags & ~(SITHSOUNDFLAG_FOLLOWSTHING|SITHSOUNDFLAG_ABSOLUTE));

    if ( playingSound )
        sithCogVm_PushInt(ctx, playingSound->refid);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSound_PlaySoundGlobal(sithCog *ctx)
{
    int flags = sithCogVm_PopInt(ctx);
    float pan = sithCogVm_PopFlex(ctx);
    float volume = sithCogVm_PopFlex(ctx);
    sithSound* sound = sithCogVm_PopSound(ctx);
    if (!sound)
    {
        sithCogVm_PushInt(ctx, -1);
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
    sithPlayingSound* playingSound = sithSoundSys_cog_playsound_internal(sound, volume, pan, flagsTmp);
    if ( playingSound )
    {
        if (sithCogVm_multiplayerFlags
            && !(ctx->flags & 0x200))
        {
            if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
                sithDSSThing_SendPlaySoundPos(0, 0, sound, volume, pan, flagsTmp, playingSound->refid, -1, 255);
        }
        sithCogVm_PushInt(ctx, playingSound->refid);
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionSound_StopSound(sithCog *ctx)
{
    float fadeOut = sithCogVm_PopFlex(ctx);
    int refId = sithCogVm_PopInt(ctx);
    sithPlayingSound* playingSound = sithSoundSys_GetSoundFromRef(refId);

    if ( playingSound && (playingSound->sound || playingSound->pSoundBuf) )
    {
        if (sithCogVm_multiplayerFlags
            && !(ctx->flags & 0x200))
        {
            if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
                sithDSSThing_SendStopSound(playingSound, fadeOut, -1, 255);
        }
        if ( fadeOut > 0.0 )
        {
            sithSoundSys_FadeSound(playingSound, 0.0, fadeOut);
            playingSound->flags |= SITHSOUNDFLAG_FADING;
        }
        else
        {
            sithSoundSys_StopSound(playingSound);
        }
    }
}

void sithCogFunctionSound_LoadSound(sithCog *ctx)
{
    sithSound *sound;

    char* path = sithCogVm_PopString(ctx);
    if ( path && (sound = sithSound_LoadEntry(path, 0)) != 0 )
        sithCogVm_PushInt(ctx, sound->id);
    else
        sithCogVm_PushInt(ctx, -1);
}

void sithCogFunctionSound_PlaySoundClass(sithCog *ctx)
{
    sithSoundClass *soundclass;

    int soundClassId = sithCogVm_PopInt(ctx);
    sithThing* thing = sithCogVm_PopThing(ctx);

    if ( thing && thing->soundclass && (soundclass = sithSoundClass_ThingPlaySoundclass(thing, soundClassId)) != 0 )
    {
        sithCogVm_PushInt(ctx, (intptr_t)soundclass->entries[14]);
        if (sithCogVm_multiplayerFlags
            && !(ctx->flags & 0x200))
        {
            if ( ctx->trigId != SITH_MESSAGE_STARTUP && ctx->trigId != SITH_MESSAGE_SHUTDOWN )
                sithDSSThing_SoundClassPlay(thing, soundClassId, (intptr_t)soundclass->entries[14], -1.0);
        }
    }
    else
    {
        sithCogVm_PushInt(ctx, -1);
    }
}

void sithCogFunctionSound_ChangeSoundVol(sithCog *ctx)
{
    float fadeintime_ = sithCogVm_PopFlex(ctx);
    float vol = sithCogVm_PopFlex(ctx);
    int ref = sithCogVm_PopInt(ctx);
    sithPlayingSound* playing_sound = sithSoundSys_GetSoundFromRef(ref);

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
        sithSoundSys_FadeSound(playing_sound, vol, fadeintime_);
    }
}

void sithCogFunctionSound_ChangeSoundPitch(sithCog *ctx)
{
    float changetime = sithCogVm_PopFlex(ctx);
    float pitch = sithCogVm_PopFlex(ctx);
    int ref = sithCogVm_PopInt(ctx);
    sithPlayingSound* sound = sithSoundSys_GetSoundFromRef(ref);

    if ( sound && changetime > 0.0 && pitch > 0.0 )
        sithSoundSys_SetPitch(sound, pitch, changetime);
}

void sithCogFunctionSound_SectorSound(sithCog *ctx)
{
    float vol = sithCogVm_PopFlex(ctx);
    sithSound* sound = sithCogVm_PopSound(ctx);
    sithSector* sector = sithCogVm_PopSector(ctx);

    if ( sector )
        sithSoundSys_SectorSound(sector, sound, vol);
}

void sithCogFunctionSound_SetMusicVol(sithCog *ctx)
{
    float vol = sithCogVm_PopFlex(ctx);
    if ( vol < 0.0 )
    {
        vol = 0.0;
    }
    else if ( vol > 1.0 )
    {
        vol = 1.0;
    }
    sithSoundSys_SetMusicVol(vol);
}

void sithCogFunctionSound_GetSoundLen(sithCog *ctx)
{
    sithSound* sound = sithCogVm_PopSound(ctx);

    if (sound)
    {
        sithCogVm_PushFlex(ctx, (double)sound->sound_len * 0.001);
    }
    else
    {
        sithCogVm_PushFlex(ctx, 0.0);
    }
}

void sithCogFunctionSound_Initialize(void* ctx)
{
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSound_PlaySong, "playsong");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSound_PlaySoundThing, "playsoundthing");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSound_PlaySoundPos, "playsoundpos");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSound_PlaySoundLocal, "playsoundlocal");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSound_PlaySoundGlobal, "playsoundglobal");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSound_StopSound, "stopsound");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSound_LoadSound, "loadsound");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSound_PlaySoundClass, "playsoundclass");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSound_ChangeSoundVol, "changesoundvol");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSound_ChangeSoundPitch, "changesoundpitch");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSound_SectorSound, "sectorsound");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSound_SetMusicVol, "setmusicvol");
    sithCogScript_RegisterVerb(ctx, sithCogFunctionSound_GetSoundLen, "getsoundlen");

}
