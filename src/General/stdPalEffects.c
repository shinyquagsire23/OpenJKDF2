#include "stdPalEffects.h"

#include "jk.h"

int stdPalEffects_Open(stdPalEffectSetPaletteFunc_t *a1)
{
    stdPalEffects_setPalette = a1;
    _memset(stdPalEffects_aEffects, 0, sizeof(stdPalEffects_aEffects));
    _memset(&stdPalEffects_state, 0, sizeof(stdPalEffects_state));
    _memset(&stdPalEffects_state.effect, 0, sizeof(stdPalEffects_state.effect));
    stdPalEffects_numEffectRequests = 0;
    stdPalEffects_state.effect.fade = 1.0;
    stdPalEffects_state.field_4 = 1;
    stdPalEffects_state.field_8 = 1;
    stdPalEffects_state.field_C = 1;
    stdPalEffects_state.field_10 = 1;
    return 1;
}

void stdPalEffects_Close()
{
    ;
}

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

// Added
void stdPalEffects_FlushAllAdds()
{
    for (int i = 0; i < 32; i++)
    {
        _memset(&stdPalEffects_aEffects[i].effect.add, 0, sizeof(stdPalEffects_aEffects[i].effect.add));
    }
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

void stdPalEffects_ResetEffect(stdPalEffect *effect)
{
    _memset(effect, 0, sizeof(stdPalEffect));
    effect->fade = 1.0;
}

void stdPalEffects_UpdatePalette(const void *palette)
{
    int v1; // esi
    int v2; // edi
    int v3; // ebp
    int v4; // edx
    int v5; // ecx
    int v6; // eax
    int v7; // ebp
    int v8; // edx
    int v9; // ebx
    int i; // eax
    int32_t v11; // ecx
    int32_t v12; // ecx
    int32_t v13; // ecx
    double v14; // st7
    int j; // esi
    uint8_t *v16; // edi
    __int64 v17; // rax
    int v18; // [esp+10h] [ebp-8h]

    v1 = 0;
    v18 = 0;
    v2 = 0;
    stdPalEffects_GatherEffects();
    if ( !stdPalEffects_state.field_3C && !stdPalEffects_state.field_40 && !stdPalEffects_state.field_48 && !stdPalEffects_state.field_44 )
        return;
    if ( stdPalEffects_state.field_4 )
    {
        v3 = stdPalEffects_state.effect.filter.y;
        if ( stdPalEffects_state.effect.filter.x )
        {
            v4 = stdPalEffects_state.effect.filter.z;
        }
        else
        {
            v4 = stdPalEffects_state.effect.filter.z;
            if ( !stdPalEffects_state.effect.filter.y && !stdPalEffects_state.effect.filter.z )
            {
                v5 = stdPalEffects_state.bEnabled;
                if ( stdPalEffects_state.bEnabled )
                {
                    v18 = 1;
                    stdPalEffects_state.field_3C = 0;
                    goto LABEL_23;
                }
                goto LABEL_21;
            }
        }
        v6 = 0;
        _memcpy(stdPalEffects_palette, palette, sizeof(stdPalEffects_palette));
        v2 = 1;
        do
        {
            if ( !stdPalEffects_state.effect.filter.x )
                stdPalEffects_palette[v6].r = (uint8_t)stdPalEffects_palette[v6].r >> 2;
            if ( !v3 )
                stdPalEffects_palette[v6].g = (uint8_t)stdPalEffects_palette[v6].g >> 2;
            if ( !v4 )
                stdPalEffects_palette[v6].b = (uint8_t)stdPalEffects_palette[v6].b >> 2;
            ++v6;
        }
        while ( v6 < 256 );
        v5 = 1;
        stdPalEffects_state.bEnabled = 1;
        v1 = 1;
LABEL_21:
        stdPalEffects_state.field_3C = 0;
        goto LABEL_23;
    }
    v5 = stdPalEffects_state.bEnabled;
LABEL_23:
    if ( stdPalEffects_state.field_8 )
    {
        if ( stdPalEffects_state.effect.tint.x == 0.0 && stdPalEffects_state.effect.tint.y == 0.0 && stdPalEffects_state.effect.tint.z == 0.0 )
        {
            if ( v5 )
                v18 = 1;
        }
        else
        {
            if ( !v2 )
            {
                _memcpy(stdPalEffects_palette, palette, sizeof(stdPalEffects_palette));
                v2 = 1;
            }
            stdPalEffects_ApplyTint(
                stdPalEffects_palette,
                stdPalEffects_state.effect.tint.x,
                stdPalEffects_state.effect.tint.y,
                stdPalEffects_state.effect.tint.z);
            v5 = 1;
            stdPalEffects_state.bEnabled = 1;
            v1 = 1;
        }
        stdPalEffects_state.field_40 = 0;
    }
    v7 = stdPalEffects_state.effect.add.z;
    v8 = stdPalEffects_state.effect.add.x;
    v9 = stdPalEffects_state.effect.add.y;
    if ( stdPalEffects_state.field_C )
    {
        if ( stdPalEffects_state.effect.add.x || stdPalEffects_state.effect.add.y || stdPalEffects_state.effect.add.z )
        {
            if ( !v2 )
            {
                _memcpy(stdPalEffects_palette, palette, sizeof(stdPalEffects_palette));
                v2 = 1;
            }
            for ( i = 0; i < 256; ++i )
            {
                v11 = (uint8_t)stdPalEffects_palette[i].r + v8;
                if ( v11 < 0 )
                {
                    v11 = 0;
                }
                else if ( v11 > 255 )
                {
                    v11 = 0xFF;
                }
                stdPalEffects_palette[i].r = v11;
                v12 = (uint8_t)stdPalEffects_palette[i].g + v9;
                if ( v12 < 0 )
                {
                    v12 = 0;
                }
                else if ( v12 > 255 )
                {
                    v12 = 0xFF;
                }
                stdPalEffects_palette[i].g = v12;
                v13 = (uint8_t)stdPalEffects_palette[i].b + v7;
                if ( v13 < 0 )
                {
                    v13 = 0;
                }
                else if ( v13 > 255 )
                {
                    v13 = 0xFF;
                }
                stdPalEffects_palette[i].b = v13;
            }
            v5 = 1;
            stdPalEffects_state.bEnabled = 1;
            v1 = 1;
        }
        else if ( v5 )
        {
            v18 = 1;
        }
        stdPalEffects_state.field_44 = 0;
    }
    if ( stdPalEffects_state.field_10 )
    {
        if ( stdPalEffects_state.effect.fade >= 1.0 )
        {
            if ( v5 )
                v18 = 1;
        }
        else
        {
            if ( !v2 )
                _memcpy(stdPalEffects_palette, palette, sizeof(stdPalEffects_palette));
            v14 = stdPalEffects_state.effect.fade;
            for ( j = 0; j < 256; ++j )
            {
                stdPalEffects_palette[j].r = (__int64)((double)(uint8_t)stdPalEffects_palette[j].r * v14 - -0.5);
                v16 = &stdPalEffects_palette[j].b;
                stdPalEffects_palette[j].g = (__int64)((double)(uint8_t)stdPalEffects_palette[j].g * v14 - -0.5);
                v17 = (__int64)((double)(uint8_t)stdPalEffects_palette[j].b * v14 - -0.5);
                *v16 = v17;
            }
            v8 = stdPalEffects_state.effect.add.x;
            v1 = 1;
            stdPalEffects_state.bEnabled = 1;
        }
        stdPalEffects_state.field_48 = 0;
    }
    if ( v1 )
    {
        stdPalEffects_setPalette(stdPalEffects_palette);
LABEL_71:
        v7 = stdPalEffects_state.effect.add.z;
        v9 = stdPalEffects_state.effect.add.y;
        v8 = stdPalEffects_state.effect.add.x;
        goto LABEL_72;
    }
    if ( v18 )
    {
        stdPalEffects_setPalette(palette);
        goto LABEL_71;
    }
LABEL_72:
    if ( !stdPalEffects_state.effect.filter.x
      && !stdPalEffects_state.effect.filter.y
      && !stdPalEffects_state.effect.filter.z
      && stdPalEffects_state.effect.tint.x == 0.0
      && stdPalEffects_state.effect.tint.y == 0.0
      && stdPalEffects_state.effect.tint.z == 0.0
      && stdPalEffects_state.effect.fade == 1.0
      && !v8
      && !v9
      && !v7 )
    {
        stdPalEffects_state.bEnabled = 0;
    }
}

void stdPalEffects_GatherEffects()
{
    uint32_t v0; // ebx
    double v1; // st7
    double v2; // st6
    int v3; // edi
    int v4; // esi
    int v5; // edx
    stdPalEffectRequest* v6; // ecx
    double v7; // st5
    stdPalEffect v8; // [esp+10h] [ebp-28h] BYREF

    v0 = 0;
    _memset(&v8, 0, sizeof(v8));
    v8.fade = 1.0;
    if ( stdPalEffects_numEffectRequests )
    {
        v1 = v8.tint.z;
        v2 = v8.tint.y;
        v3 = v8.add.z;
        v4 = v8.add.y;
        v5 = v8.add.x;
        v6 = &stdPalEffects_aEffects[0];
        v7 = v8.tint.x;
        do
        {
            if ( v6->isValid )
            {
                if ( v6->effect.filter.x )
                    v8.filter.x = 1;
                if ( v6->effect.filter.y )
                    v8.filter.y = 1;
                if ( v6->effect.filter.z )
                    v8.filter.z = 1;
                v7 = v7 + v6->effect.tint.x;
                v5 += v6->effect.add.x;
                v2 = v2 + v6->effect.tint.y;
                v4 += v6->effect.add.y;
                v3 += v6->effect.add.z;
                v1 = v1 + v6->effect.tint.z;
                if ( v8.fade >= (double)v6->effect.fade )
                    v8.fade = v6->effect.fade;
                ++v0;
            }
            ++v6;
        }
        while ( v0 < stdPalEffects_numEffectRequests );
        v8.tint.z = v1;
        v8.tint.y = v2;
        v8.tint.x = v7;
        v8.add.z = v3;
        v8.add.y = v4;
        v8.add.x = v5;
    }
    else
    {
        v1 = v8.tint.z;
        v2 = v8.tint.y;
        v3 = v8.add.z;
        v4 = v8.add.y;
        v5 = v8.add.x;
        v7 = v8.tint.x;
    }
    if ( v8.filter.x != stdPalEffects_state.effect.filter.x
      || v8.filter.y != stdPalEffects_state.effect.filter.y
      || v8.filter.z != stdPalEffects_state.effect.filter.z )
    {
        stdPalEffects_state.field_3C = 1;
    }
    if ( v7 != stdPalEffects_state.effect.tint.x || v2 != stdPalEffects_state.effect.tint.y || v1 != stdPalEffects_state.effect.tint.z )
        stdPalEffects_state.field_40 = 1;
    if ( v5 != stdPalEffects_state.effect.add.x || v4 != stdPalEffects_state.effect.add.y || v3 != stdPalEffects_state.effect.add.z )
        stdPalEffects_state.field_44 = 1;
    if ( v8.fade != stdPalEffects_state.effect.fade )
        stdPalEffects_state.field_48 = 1;
    _memcpy(&stdPalEffects_state.effect, &v8, sizeof(stdPalEffects_state.effect));
}

// setunk

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

// ApplyFilter

void stdPalEffects_ApplyTint(rdColor24 *aPalette, float tintR, float tintG, float tintB)
{
    double v4; // st7
    double v5; // st5
    double v7; // rt0
    double v8; // st5
    double v9; // rt2
    double v10; // st5
    double v11; // st7
    char *v12; // esi
    int v13; // ebx
    double v14; // st5
    double v15; // st6
    int v16; // eax
    signed int v17; // eax
    signed int v18; // eax
    float aPalettea; // [esp+4h] [ebp+4h]
    float aPaletteb; // [esp+4h] [ebp+4h]

    v4 = tintR * 0.5;
    v5 = tintB * 0.5;
    aPalettea = v5;
    v7 = v5;
    v8 = v4 + aPalettea;
    aPaletteb = tintG * 0.5;
    v9 = v8;
    v10 = v4;
    v11 = tintR - (v7 + aPaletteb);
    v12 = &aPalette->b;
    v13 = 256;
    v14 = tintB - (v10 + aPaletteb);
    v15 = tintG - v9;
    do
    {
        v16 = (uint8_t)*(v12 - 2) + (unsigned int)(__int64)((double)(uint8_t)*(v12 - 2) * v11 - -0.5);
        if ( v16 < 0 )
        {
            v16 = 0;
        }
        else if ( v16 > 255 )
        {
            v16 = 0xFF;
        }
        *(v12 - 2) = v16;
        v17 = (uint8_t)*(v12 - 1) + (unsigned int)(__int64)((double)(uint8_t)*(v12 - 1) * v15 - -0.5);
        if ( v17 < 0 )
        {
            v17 = 0;
        }
        else if ( v17 > 255 )
        {
            v17 = 0xFF;
        }
        *(v12 - 1) = v17;
        v18 = (uint8_t)*v12 + (unsigned int)(__int64)((double)(uint8_t)*v12 * v14 - -0.5);
        if ( v18 < 0 )
        {
            v18 = 0;
        }
        else if ( v18 > 255 )
        {
            v18 = 0xFF;
        }
        *v12 = v18;
        v12 += 3;
        --v13;
    }
    while ( v13 );
}

// ApplyAdd
// ApplyFade
