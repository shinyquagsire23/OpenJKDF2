#ifndef _STDPALEFFECTS_H
#define _STDPALEFFECTS_H

#include "types.h"
#include "globals.h"

#ifdef __cplusplus
extern "C" {
#endif

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

int stdPalEffects_Open(stdPalEffectSetPaletteFunc_t a1);
void stdPalEffects_Close();
int stdPalEffects_NewRequest(int idx);
void stdPalEffects_FreeRequest(uint32_t idx);
void stdPalEffects_FlushAllEffects();
void stdPalEffects_FlushAllAdds();
stdPalEffect* stdPalEffects_GetEffectPointer(int idx);
int stdPalEffects_RefreshPalette();
void stdPalEffects_ResetEffectsState(stdPalEffectsState *effectsState);
void stdPalEffects_SetFilter(int idx, int r, int g, int b);
void stdPalEffects_SetTint(int idx, flex_t r, flex_t g, flex_t b);
void stdPalEffects_SetAdd(int idx, int r, int g, int b);
void stdPalEffects_SetFade(int idx, flex_t fade);
MATH_FUNC void stdPalEffects_UpdatePalette(const void *palette);
void stdPalEffects_GatherEffects();
MATH_FUNC void stdPalEffects_ApplyTint(rdColor24 *aPalette, flex_t tintR, flex_t tintG, flex_t tintB);
void stdPalEffects_ResetEffect(stdPalEffect *effect);

//static int (*stdPalEffects_Open)(void *a1) = (void*)stdPalEffects_Open_ADDR;
//static void (*stdPalEffects_Close)() = (void*)stdPalEffects_Close_ADDR;
//static void (*stdPalEffects_SetFilter)(int a1, int a2, int a3, int a4) = (void*)stdPalEffects_SetFilter_ADDR;
//static void (*stdPalEffects_SetTint)(int a1, flex_t a2, flex_t a3, flex_t a4) = (void*)stdPalEffects_SetTint_ADDR;
//static void (*stdPalEffects_SetAdd)(int a1, int a2, int a3, int a4) = (void*)stdPalEffects_SetAdd_ADDR;
//static void (*stdPalEffects_SetFade)(int a1, flex_t a2) = (void*)stdPalEffects_SetFade_ADDR;
//static void (*stdPalEffects_FreeRequest)(int a1) = (void*)stdPalEffects_FreeRequest_ADDR;
//static int (*stdPalEffects_ResetEffect)(stdPalEffect* effect) = (void*)stdPalEffects_ResetEffect_ADDR;
//static void (*stdPalEffects_UpdatePalette)(void*) = (void*)stdPalEffects_UpdatePalette_ADDR;
//static void (*stdPalEffects_RefreshPalette)() = (void*)stdPalEffects_RefreshPalette_ADDR;

#ifdef __cplusplus
}
#endif

#endif // _STDPALEFFECTS_H
