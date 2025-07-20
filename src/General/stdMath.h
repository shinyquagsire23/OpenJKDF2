#ifndef _STDMATH_H
#define _STDMATH_H

#include "hook.h"

#ifdef TARGET_TWL
#include <nds/arm9/math.h>
#endif

#define _USE_MATH_DEFINES
#include <math.h>

#define stdMath_FlexPower_ADDR (0x00431E20)
#define stdMath_NormalizeAngle_ADDR (0x00431E5B)
#define stdMath_NormalizeAngleAcute_ADDR (0x00431F10)
#define stdMath_NormalizeDeltaAngle_ADDR (0x00431F45)
#define stdMath_SinCos_ADDR (0x00431FBD)
#define stdMath_Tan_ADDR (0x00432396)
#define stdMath_ArcSin1_ADDR (0x00432623)
#define stdMath_ArcSin2_ADDR (0x004326FC)
#define stdMath_ArcSin3_ADDR (0x00432809)
#define stdMath_ArcTan1_ADDR (0x0043294A)
#define stdMath_ArcTan2_ADDR (0x00432AC6)
#define stdMath_ArcTan3_ADDR (0x00432C5C)
#define stdMath_ArcTan4_ADDR (0x00432E0C)
#define stdMath_FloorDivMod_ADDR (0x00432FD6)
#define stdMath_Dist2D1_ADDR (0x0043303E)
#define stdMath_Dist2D2_ADDR (0x004330E2)
#define stdMath_Dist2D3_ADDR (0x00433186)
#define stdMath_Dist2D4_ADDR (0x0043322A)
#define stdMath_Dist3D1_ADDR (0x00433302)
#define stdMath_Dist3D2_ADDR (0x00433418)
#define stdMath_Dist3D3_ADDR (0x0043352E)
#define stdMath_Floor_ADDR (0x00433650)
#define stdMath_Sqrt_ADDR (0x00433670)

MATH_FUNC flex_t stdMath_FlexPower(flex_t num, int32_t exp);
MATH_FUNC FAST_FUNC flex_t stdMath_NormalizeAngle(flex_t angle);
MATH_FUNC FAST_FUNC flex_t stdMath_NormalizeAngleAcute(flex_t angle);
MATH_FUNC FAST_FUNC flex_t stdMath_NormalizeDeltaAngle(flex_t a1, flex_t a2);
#ifdef EXPERIMENTAL_FIXED_POINT
MATH_FUNC FAST_FUNC void stdMath_SinCosVeryApproximate(flex_t angle, flex_t *pSinOut, flex_t *pCosOut);
#endif
MATH_FUNC FAST_FUNC void stdMath_SinCos(flex_t angle, flex_t *pSinOut, flex_t *pCosOut);
MATH_FUNC flex_t stdMath_Tan(flex_t a1);
MATH_FUNC flex_t stdMath_ArcSin1(flex_t val);
MATH_FUNC flex_t stdMath_ArcSin2(flex_t val);
MATH_FUNC flex_t stdMath_ArcSin3(flex_t val);
MATH_FUNC flex_t stdMath_ArcTan1(flex_t a1, flex_t a2);
MATH_FUNC flex_t stdMath_ArcTan2(flex_t a1, flex_t a2);
MATH_FUNC flex_t stdMath_ArcTan3(flex_t a1, flex_t a2);
MATH_FUNC flex_t stdMath_ArcTan4(flex_t a1, flex_t a2);
MATH_FUNC int32_t stdMath_FloorDivMod(int32_t in1, int32_t in2, int32_t *out1, int32_t *out2);

//IMPORT_FUNC(stdMath_SinCos, void, (flex_t, flex_t*, flex_t*), stdMath_SinCos_ADDR)
//IMPORT_FUNC(stdMath_Tan, flex_t, (flex_t), stdMath_Tan_ADDR)
//IMPORT_FUNC(stdMath_ArcSin1, flex_t, (flex_t), stdMath_ArcSin1_ADDR)
//IMPORT_FUNC(stdMath_ArcSin2, flex_t, (flex_t), stdMath_ArcSin2_ADDR)
//IMPORT_FUNC(stdMath_ArcSin3, flex_t, (flex_t), stdMath_ArcSin3_ADDR)
//IMPORT_FUNC(stdMath_ArcTan1, flex_t, (flex_t, flex_t), stdMath_ArcTan1_ADDR)
//IMPORT_FUNC(stdMath_ArcTan2, flex_t, (flex_t, flex_t), stdMath_ArcTan2_ADDR)
//IMPORT_FUNC(stdMath_ArcTan3, flex_t, (flex_t, flex_t), stdMath_ArcTan3_ADDR)
//IMPORT_FUNC(stdMath_ArcTan4, flex_t, (flex_t, flex_t), stdMath_ArcTan4_ADDR)
//IMPORT_FUNC(stdMath_FloorDivMod, int, (int, int, int*, int*), stdMath_FloorDivMod_ADDR)

//static void (*_stdMath_SinCos)(flex_t angle, flex_t *pSinOut, flex_t *pCosOut) = (void*)stdMath_SinCos_ADDR;

MATH_FUNC flex_t stdMath_Dist2D1(flex_t a1, flex_t a2);
MATH_FUNC flex_t stdMath_Dist2D2(flex_t a1, flex_t a2);
MATH_FUNC flex_t stdMath_Dist2D3(flex_t a1, flex_t a2);
MATH_FUNC flex_t stdMath_Dist2D4(flex_t a1, flex_t a2);
MATH_FUNC flex_t stdMath_Dist3D1(flex_t a1, flex_t a2, flex_t a3);
MATH_FUNC flex_t stdMath_Dist3D2(flex_t a1, flex_t a2, flex_t a3);
MATH_FUNC flex_t stdMath_Dist3D3(flex_t a1, flex_t a2, flex_t a3);
MATH_FUNC flex_t stdMath_Floor(flex_t a);
MATH_FUNC flex_t stdMath_Sqrt(flex_t a);

// Added
MATH_FUNC flex_t stdMath_ClipPrecision(flex_t val);
MATH_FUNC flex_t stdMath_Clamp(flex_t val, flex_t valMin, flex_t valMax);
MATH_FUNC flex_t stdMath_ClampValue(flex_t val, flex_t valAbsMax);
static inline flex_t stdMath_Fabs(flex_t val)
{
    //return fabs(val);
    return (val < 0.0) ? -val : val;
}

static inline flex_t stdMath_Fmod(flex_t a, flex_t b) {
    return (flex_t)fmod((float)a, (float)b);
} 

static inline flex_t stdMath_Ceil(flex_t a) {
#if defined(EXPERIMENTAL_FIXED_POINT)
    // This ceil is made of floor
    return flexdirect(a.to_raw() & ~((1<<FIXED_POINT_DECIMAL_BITS)-1));
#else
    return (flex_t)ceilf((float)a);
#endif
} 

static inline int32_t stdMath_ClampInt(int32_t val, int32_t valMin, int32_t valMax)
{
    if (val < valMin)
        return valMin;
    
    if (val > valMax)
        return valMax;

    return val;
}

static inline uint8_t stdMath_ClampU8(uint8_t val, uint8_t valMin, uint8_t valMax)
{
    if (val < valMin)
        return valMin;
    
    if (val > valMax)
        return valMax;

    return val;
}

#define stdMath_Min(a,b) ((a)<(b)?(a):(b))
#define stdMath_Max(a,b) ((a)>(b)?(a):(b))

#if defined(TARGET_TWL) && defined(EXPERIMENTAL_FIXED_POINT)
static inline flex_t divflex_mine(flex_t num, flex_t den)
{
    REG_DIV_NUMER = ((s64)num.to_raw()) << FIXED_POINT_DECIMAL_BITS;
    REG_DIV_DENOM_L = den.to_raw();

    while(REG_DIVCNT & DIV_BUSY);

    return flexdirect(REG_DIV_RESULT_L);
}

static inline s32 divf32_mine(s32 num, s32 den)
{
    REG_DIV_NUMER = ((s64)num) << 12;
    REG_DIV_DENOM_L = den;

    while(REG_DIVCNT & DIV_BUSY);

    return (REG_DIV_RESULT_L);
}

static inline flex_t sqrtfixed_mine(flex_t a)
{
    REG_SQRT_PARAM = ((s64)a.to_raw()) << FIXED_POINT_DECIMAL_BITS;

    while(REG_SQRTCNT & SQRT_BUSY);

    return flexdirect(REG_SQRT_RESULT);
}

static inline flex_t sqrt64fixed_mine(s64 a)
{
    REG_SQRT_PARAM = ((s64)a) << FIXED_POINT_DECIMAL_BITS;

    while(REG_SQRTCNT & SQRT_BUSY);

    return flexdirect(REG_SQRT_RESULT);
}

static inline flex_t sqrt64fixed_mine_2(s64 a)
{
    REG_SQRT_PARAM = ((s64)a);

    while(REG_SQRTCNT & SQRT_BUSY);

    return flexdirect(REG_SQRT_RESULT);
}
#endif

extern const flex_t aSinTable[4096];
extern const flex_t aTanTable[4096];

#endif // _STDMATH_H
