#include "jkAI.h"

#include "AI/sithAI.h"
#include "AI/sithAIClass.h"
#include "Engine/sithTime.h"
#include "Engine/sithSoundClass.h"
#include "Engine/sithAnimClass.h"
#include "Engine/sithPuppet.h"
#include "World/jkPlayer.h"
#include "World/sithThing.h"
#include "World/sithActor.h"
#include "World/jkSaber.h"
#include "Cog/sithCog.h"
#include "../jk.h"

//#define jkAI_SaberFighting ((void*)jkAI_SaberFighting_ADDR)
//#define jkAI_SpecialAttack ((void*)jkAI_SpecialAttack_ADDR)
//#define jkAI_ForcePowers ((void*)jkAI_ForcePowers_ADDR)
//#define jkAI_SaberMove ((void*)jkAI_SaberMove_ADDR)

void jkAI_Startup()
{
    sithAI_RegisterCommand("saberfighting", jkAI_SaberFighting, 2, 0, 0);
    sithAI_RegisterCommand("forcepowers", jkAI_ForcePowers, 2, 0, 0);
    sithAI_RegisterCommand("sabermove", jkAI_SaberMove, 2, 0, 0);
    sithAI_RegisterCommand("specialattack", jkAI_SpecialAttack, 2, 0, 4);
}

int jkAI_SaberFighting(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, int extra)
{
    unsigned int v5; // edi
    sithThing *v7; // ecx
    jkPlayerInfo *v8; // eax
    sithThing *v9; // edx
    signed int result; // eax
    unsigned int v11; // eax
    int v12; // eax
    sithThing *v13; // ecx
    float *v14; // ecx
    int v17_lo; // rax lo
    double v18; // st7
    int v19; // ebx
    signed int v20; // edi
    sithThing *v21; // ecx
    int v23; // eax
    float a2a; // [esp+1Ch] [ebp+4h]
    float a3a; // [esp+28h] [ebp+10h]

    v5 = 0;
    if ( flags )
        return 0;
    v7 = actor->thing;
    v8 = actor->thing->playerInfo;
    if ( !v8 )
        return 0;
    v9 = actor->field_1D0;
    if ( !v9 )
        return 0;
    if ( (v9->thingflags & (SITH_TF_DEAD|SITH_TF_WILLBEREMOVED)) == 0 )
    {
        if ( (v7->actorParams.typeflags & THING_TYPEFLAGS_40000) == 0 )
        {
            if ( v8->polyline.length < (double)v8->length )
            {
                sithPuppet_SetArmedMode(v7, SITH_ANIM_WALK);
                actor->thing->jkFlags |= 4u;
            }
            v11 = sithTime_curMs;
            instinct->nextUpdate = sithTime_curMs + 500;
            if ( actor->field_288 <= v11 )
            {
                sithAI_sub_4EAD60(actor);
                v12 = actor->field_1F4;
                if ( v12 == 3
                  && ((actor->thing->actorParams.typeflags & SITH_TF_NOIMPACTDAMAGE) != 0
                   || (v13 = actor->field_1D0) != 0 && v13->actorParams.typeflags & SITHAIFLAGS_UNK80) )
                {
                    actor->field_1F0 = 0.0;
                }
                else
                {
                    if ( v12 != 3 )
                        sithAI_SetLookFrame(actor, &actor->field_1D0->position);
                    if ( actor->field_1F4 || aiclass->argsAsFloat[0] != 0.0 && aiclass->argsAsFloat[0] > _frand() )
                    {
LABEL_27:
                        if ( (actor->thing->actorParams.typeflags & SITHAIFLAGS_DISABLED) == 0 )
                        {
                            actor->thing->actorParams.typeflags |= SITHAIFLAGS_DISABLED;
                            return 0;
                        }
                        return 0;
                    }
                }
                v14 = &aiclass->argsAsFloat[1];
                do
                {
                    if ( actor->field_1F0 > (double)*v14 )
                        break;
                    ++v5;
                    v14 += 3;
                }
                while ( v5 < 4 );
                if ( !v5 )
                {
                    actor->flags &= ~SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE;
                    goto LABEL_27;
                }
                v17_lo = (int)(_frand() * (double)v5);
                if ( v17_lo )
                {
                    if ( v17_lo == 1 )
                    {
                        a2a = aiclass->argsAsFloat[5];
                        v19 = aiclass->argsAsInt[6];
                        v20 = SITH_ANIM_FIRE2;
                        a3a = aiclass->argsAsFloat[4];
                    }
                    else
                    {
                        if ( v17_lo == 2 )
                        {
                            a2a = aiclass->argsAsFloat[8];
                            v18 = aiclass->argsAsFloat[7];
                            v19 = aiclass->argsAsInt[9];
                            v20 = SITH_ANIM_FIRE3;
                        }
                        else
                        {
                            a2a = aiclass->argsAsFloat[11];
                            v18 = aiclass->argsAsFloat[10];
                            v19 = aiclass->argsAsInt[12];
                            v20 = SITH_ANIM_FIRE4;
                        }
                        a3a = v18;
                    }
                }
                else
                {
                    v19 = aiclass->argsAsInt[3];
                    v20 = SITH_ANIM_FIRE;
                    a2a = aiclass->argsAsFloat[2];
                    a3a = aiclass->argsAsFloat[1];
                }
                v21 = actor->thing;
                if ( (actor->thing->actorParams.typeflags & SITHAIFLAGS_DISABLED) != 0 )
                {
                    v21->actorParams.typeflags &= ~SITHAIFLAGS_DISABLED;
                }
                actor->flags |= SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE;
                sithSoundClass_ThingPlaySoundclass4(v21, v17_lo + SITH_SC_FIRE1);
                sithPuppet_PlayMode(actor->thing, v20, 0);
                jkSaber_Enable(actor->thing, a2a, a3a, 0.0);
                v23 = v19 + sithTime_curMs;
                instinct->nextUpdate = v19 + sithTime_curMs;
                actor->field_288 = v23;
            }
        }
        return 0;
    }
    if ( (actor->flags & SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE) != 0 )
    {
        sithSoundClass_ThingPlaySoundclass(v7, SITH_SC_VICTORY);
        sithPuppet_PlayMode(actor->thing, SITH_ANIM_VICTORY, 0);
    }
    result = 1;
    actor->flags = actor->flags & ~(SITHAIFLAGS_TARGET_SIGHTED_IN_RANGE|SITHAIFLAGS_AWAKE_AND_ACTIVE|SITHAIFLAGS_HAS_TARGET|SITHAIFLAGS_ATTACKING_TARGET) | SITHAIFLAGS_SEARCHING;
    return result;
}

int jkAI_SpecialAttack(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, sithThing *extra)
{
    rdPuppet *v5; // ebx
    int v6; // edx
    rdPuppet *v9; // ebp
    unsigned int v10; // eax
    int v11; // edx
    sithThing *v13; // eax
    uint32_t v14; // ecx
    sithThing *v15; // edx
    int v16; // eax
    int aiclassa; // [esp+24h] [ebp+8h]

    if ( flags != SITHAIFLAGS_SEARCHING || instinct->param0 == 0.0 )
    {
        if ( !flags )
        {
            if ( instinct->param0 == 0.0 )
            {
                v10 = sithTime_curMs;
            }
            else
            {
                v9 = actor->thing->rdthing.puppet;
                if ( v9 )
                    sithPuppet_StopKey(v9, (__int64)instinct->param0, 0.5);
                jkSaber_Disable(actor->thing);
                v10 = sithTime_curMs;
                v11 = sithTime_curMs + aiclass->argsAsInt[8];
                instinct->param0 = 0.0;
                instinct->nextUpdate = v11;
            }
            if ( actor->field_1D0 )
            {
                instinct->nextUpdate = v10 + aiclass->argsAsInt[0];
                if ( actor->field_288 <= v10 && aiclass->argsAsFloat[1] >= _frand() )
                {
                    sithAI_sub_4EAD60(actor);
                    if ( aiclass->argsAsFloat[2] <= (double)actor->field_1F0 && aiclass->argsAsFloat[3] >= (double)actor->field_1F0 )
                    {
                        sithSoundClass_ThingPlaySoundclass(actor->thing, SITH_SC_RESERVED1);
                        v13 = actor->thing;
                        if ( (actor->thing->actorParams.typeflags & SITHAIFLAGS_DISABLED) != 0 )
                        {
                            v13->actorParams.typeflags &= ~SITHAIFLAGS_DISABLED;
                        }
                        aiclassa = sithPuppet_PlayMode(v13, aiclass->argsAsInt[5], 0);
                        if ( aiclassa >= 0 )
                        {
                            v15 = actor->thing;
                            instinct->param0 = (float)aiclassa;
                            jkSaber_Enable(v15, aiclass->argsAsFloat[7], 0.30000001, 0.0);
                            sithAI_SetMoveThing(actor, &actor->field_1D4, 4.0);
                            v16 = aiclass->argsAsInt[4] + sithTime_curMs;
                            instinct->nextUpdate = v16;
                            actor->field_288 = v16;
                        }
                    }
                }
            }
        }
        return 0;
    }
    if ( !extra || extra != g_localPlayerThing )
        return 0;
    sithThing_Damage(extra, actor->thing, aiclass->argsAsFloat[7], 0x10);
    sithSoundClass_ThingPlaySoundclass(actor->thing, SITH_SC_RESERVED2);
    v5 = actor->thing->rdthing.puppet;
    if ( v5 )
        sithPuppet_StopKey(v5, (__int64)instinct->param0, 0.5);
    jkSaber_Disable(actor->thing);
    v6 = sithTime_curMs + aiclass->argsAsInt[8];
    instinct->param0 = 0.0;
    instinct->nextUpdate = v6;
    return 0;
}

int jkAI_ForcePowers(sithActor *actor, sithAIClassEntry *aiclass, sithActorInstinct *instinct, int flags, int extra)
{
    int v6; // ebx
    double v7; // st6
    int v8; // eax
    int v9; // eax
    float v12; // [esp+0h] [ebp-28h]
    float v13; // [esp+4h] [ebp-24h]
    int v14; // [esp+20h] [ebp-8h]
    float instincta; // [esp+34h] [ebp+Ch]

    v6 = 0;
    v14 = 0;
    instinct->nextUpdate = sithTime_curMs + aiclass->argsAsInt[0];
    sithAI_sub_4EAD60(actor);
    if ( !actor->field_1D0 || actor->field_1F4 )
        return 0;
    v7 = _frand();
    instincta = v7;
    if ( v7 < aiclass->argsAsFloat[7]
      && (aiclass->argsAsFloat[1] > (double)actor->field_1F0 || aiclass->argsAsFloat[2] < (double)actor->field_1F0 ? (v8 = 0) : (v8 = 1), v8) )
    {
        v6 = 1;
    }
    else if ( instincta < (double)aiclass->argsAsFloat[8]
           && (aiclass->argsAsFloat[3] > (double)actor->field_1F0 || aiclass->argsAsFloat[4] < (double)actor->field_1F0 ? (v9 = 0) : (v9 = 1), v9) )
    {
        v6 = 2;
    }
    else
    {
        if ( instincta >= (double)aiclass->argsAsFloat[9] )
            goto LABEL_25;
        if ( aiclass->argsAsFloat[5] > (double)actor->field_1F0 || aiclass->argsAsFloat[6] < (double)actor->field_1F0 )
            goto LABEL_25;
        v6 = 3;
    }
    v14 = v6;
LABEL_25:
    if ( v6 )
    {
        v13 = (float)v14;
        v12 = (float)(unsigned int)actor->field_1D0->thingIdx;
        sithCog_SendMessageFromThingEx(actor->thing, 0, SITH_MESSAGE_USER0, v12, v13, 0.0, 0.0);
        instinct->nextUpdate = sithTime_curMs + aiclass->argsAsInt[v6 + 9];
    }
    return 0;
}

int jkAI_SaberMove()
{
    return 0;
}
