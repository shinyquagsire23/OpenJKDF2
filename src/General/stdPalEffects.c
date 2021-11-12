#include "stdPalEffects.h"

#include "jk.h"

int stdPalEffects_NewRequest(int idx)
{
    int v2; // edx
    stdPalEffectRequest *v3; // eax

    if (stdPalEffects_numEffectRequests >= 0x20)
        return -1;

    for (v2 = 0; v2 < 32; v2++)
    {
        if ( !stdPalEffects_aEffects[v2].isValid )
            break;
    }

    _memset(&stdPalEffects_aEffects[v2].effect, 0, sizeof(stdPalEffects_aEffects[v2].effect));
    stdPalEffects_aEffects[v2].effect.fade = 1.0;
    stdPalEffects_aEffects[v2].isValid = 1;
    stdPalEffects_aEffects[v2].idx = idx;
    ++stdPalEffects_numEffectRequests;
    return v2;
}

void stdPalEffects_FreeRequest(uint32_t idx)
{
    if (idx >= 32)
        return;

    if ( stdPalEffects_aEffects[idx].isValid )
    {
        stdPalEffects_aEffects[idx].isValid = 0;
        --stdPalEffects_numEffectRequests;
    }
}

void stdPalEffects_FlushAllEffects()
{
    _memset(stdPalEffects_aEffects, 0, sizeof(stdPalEffectRequest) * 32); // sizeof(stdPalEffects_aEffects)
    stdPalEffects_numEffectRequests = 0;
}

stdPalEffect* stdPalEffects_GetEffectPointer(int idx)
{
    return &stdPalEffects_aEffects[idx].effect;
}

int stdPalEffects_RefreshPalette()
{
    stdPalEffects_state.field_3C = 1;
    stdPalEffects_state.field_40 = 1;
    stdPalEffects_state.field_48 = 1;
    stdPalEffects_state.field_44 = 1;
    stdPalEffects_state.bEnabled = 1;
    return 1;
}

void stdPalEffects_ResetEffectsState(stdPalEffectsState *effectsState)
{
    _memset(effectsState, 0, sizeof(stdPalEffectsState));
    _memset(&effectsState->effect, 0, sizeof(effectsState->effect));
    effectsState->effect.fade = 1.0;
    effectsState->effect.fade = 1.0;
}

void stdPalEffects_SetFilter(int idx, int a2, int a3, int a4)
{
    stdPalEffects_aEffects[idx].effect.filter.x = a2;
    stdPalEffects_aEffects[idx].effect.filter.y = a3;
    stdPalEffects_aEffects[idx].effect.filter.z = a4;
}

void stdPalEffects_SetTint(int idx, float a2, float a3, float a4)
{
    stdPalEffects_aEffects[idx].effect.tint.x = a2;
    stdPalEffects_aEffects[idx].effect.tint.y = a3;
    stdPalEffects_aEffects[idx].effect.tint.z = a4;
}

void stdPalEffects_SetAdd(int idx, int a2, int a3, int a4)
{
    stdPalEffects_aEffects[idx].effect.add.x = a2;
    stdPalEffects_aEffects[idx].effect.add.y = a3;
    stdPalEffects_aEffects[idx].effect.add.z = a4;
}

void stdPalEffects_SetFade(int idx, float fade)
{
    stdPalEffects_aEffects[idx].effect.fade = fade;
}
