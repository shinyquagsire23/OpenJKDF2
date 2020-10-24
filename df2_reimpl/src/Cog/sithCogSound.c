#include "sithCogSound.h"

static void (*sithCogSound_PlaySong)(sithCog* ctx) = (void*)0x004FF160;
static void (*sithCogSound_PlaySoundThing)(sithCog* ctx) = (void*)0x004FF1B0;
static void (*sithCogSound_PlaySoundPos)(sithCog* ctx) = (void*)0x004FF400;
static void (*sithCogSound_PlaySoundLocal)(sithCog* ctx) = (void*)0x004FF5B0;
static void (*sithCogSound_PlaySoundGlobal)(sithCog* ctx) = (void*)0x004FF6A0;
static void (*sithCogSound_StopSound)(sithCog* ctx) = (void*)0x004FF7D0;
static void (*sithCogSound_LoadSound)(sithCog* ctx) = (void*)0x004FF880;
static void (*sithCogSound_PlaySoundClass)(sithCog* ctx) = (void*)0x004FF8C0;
static void (*sithCogSound_ChangeSoundVol)(sithCog* ctx) = (void*)0x004FF950;
static void (*sithCogSound_ChangeSoundPitch)(sithCog* ctx) = (void*)0x004FF9F0;
static void (*sithCogSound_SectorSound)(sithCog* ctx) = (void*)0x004FFA60;
static void (*sithCogSound_SetMusicVol)(sithCog* ctx) = (void*)0x004FFAA0;
static void (*sithCogSound_GetSoundLen)(sithCog* ctx) = (void*)0x004FFB00;

void sithCogSound_Initialize(void* ctx)
{
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSound_PlaySong, "playsong");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSound_PlaySoundThing, "playsoundthing");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSound_PlaySoundPos, "playsoundpos");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSound_PlaySoundLocal, "playsoundlocal");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSound_PlaySoundGlobal, "playsoundglobal");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSound_StopSound, "stopsound");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSound_LoadSound, "loadsound");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSound_PlaySoundClass, "playsoundclass");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSound_ChangeSoundVol, "changesoundvol");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSound_ChangeSoundPitch, "changesoundpitch");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSound_SectorSound, "sectorsound");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSound_SetMusicVol, "setmusicvol");
    sithCogScript_RegisterVerb(ctx, (intptr_t)sithCogSound_GetSoundLen, "getsoundlen");

}
