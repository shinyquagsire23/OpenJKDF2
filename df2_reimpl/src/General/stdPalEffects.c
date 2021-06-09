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
