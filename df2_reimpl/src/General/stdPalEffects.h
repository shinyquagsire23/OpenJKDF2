#ifndef _STDPALEFFECTS_H
#define _STDPALEFFECTS_H

#include "Primitives/rdVector.h"
#include "types.h"

#define stdPalEffects_Open_ADDR (0x00428830)
#define stdPalEffects_Close_ADDR (0x00428890)
#define stdPalEffects_NewRequest_ADDR (0x004288A0)
#define stdPalEffects_FreeRequest_ADDR (0x00428910)
#define stdPalEffects_GetEffectPointer_ADDR (0x00428940)
#define stdPalEffects_FlushAllEffects_ADDR (0x00428950)
#define stdPalEffects_SetPaletteFunc_ADDR (0x00428970)
#define stdPalEffects_RefreshPalette_ADDR (0x00428980)
#define stdPalEffects_ResetEffectsState_ADDR (0x004289A0)
#define stdPalEffects_ResetEffect_ADDR (0x004289D0)
#define stdPalEffects_UpdatePalette_ADDR (0x004289F0)
#define stdPalEffects_GatherEffects_ADDR (0x00428E00)
#define stdPalEffects_SetUnk_ADDR (0x00428FC0)
#define stdPalEffects_SetFilter_ADDR (0x00428FF0)
#define stdPalEffects_SetTint_ADDR (0x00429020)
#define stdPalEffects_SetAdd_ADDR (0x00429050)
#define stdPalEffects_SetFade_ADDR (0x00429080)
#define stdPalEffects_ApplyFilter_ADDR (0x004290A0)
#define stdPalEffects_ApplyTint_ADDR (0x004290E0)
#define stdPalEffects_ApplyAdd_ADDR (0x00429200)
#define stdPalEffects_ApplyFade_ADDR (0x00429290)

#define stdPalEffects_Close_idk_ADDR (0x004C8620)

typedef struct stdPalEffect
{
    rdVector3 a;
    rdVector3 b;
    uint32_t field_18;
    uint32_t field_1C;
    uint32_t field_20;
    float scalar_idk;
} stdPalEffect;

static int (*stdPalEffects_ResetEffect)(stdPalEffect* effect) = (void*)stdPalEffects_ResetEffect_ADDR;

#endif // _STDPALEFFECTS_H
