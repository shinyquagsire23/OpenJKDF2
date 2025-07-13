#include "stdMath.h"

#include "stdMathTables.h"

flex_t stdMath_FlexPower(flex_t num, int32_t exp)
{
    flex_t retval = num;

    for (int32_t i = 0; i < exp - 1; ++i)
    {
        retval = retval * num;
    }
    return retval;
}

flex_t stdMath_NormalizeAngle(flex_t angle)
{
    flex_t retval;

    if (angle >= 0.0)
    {
        if ( angle < 360.0 )
            return angle;
        retval = angle - stdMath_Floor(angle / 360.0) * 360.0;
    }
    else
    {
        if (-angle >= 360.0)
        {
            retval = 360.0 - (-angle - stdMath_Floor(-angle / 360.0) * 360.0);
        }
        else
        {
            retval = 360.0 + angle;
        }
    }

    if (retval == 360.0)
        retval = 0.0;

    return retval;
}

flex_t stdMath_NormalizeAngleAcute(flex_t angle)
{
    flex_t norm = stdMath_NormalizeAngle(angle);
    if ( norm > 180.0 )
        return -(360.0 - norm);
    return norm;
}

flex_t stdMath_NormalizeDeltaAngle(flex_t a1, flex_t a2)
{
    flex_t result;
    flex_t delta;

    delta = stdMath_NormalizeAngle(a2) - stdMath_NormalizeAngle(a1);
    if ( delta >= 0.0 )
    {
        if ( delta > 180.0 )
            result = -(360.0 - delta);
        else
            result = delta;
    }
    else if ( delta < -180.0 )
    {
        result = delta + 360.0;
    }
    else
    {
        result = delta;
    }

    return result;
}

void stdMath_SinCos(flex_t angle, flex_t *pSinOut, flex_t *pCosOut)
{
    flex_t normalized; // st7
    flex_t v4; // st7
    flex_t v5; // st7
    flex_t v6; // [esp+Ch] [ebp-20h]
    flex_t a1; // [esp+10h] [ebp-1Ch]
    int32_t v8; // [esp+14h] [ebp-18h]
    flex_t v9; // [esp+18h] [ebp-14h]
    flex_t v10; // [esp+18h] [ebp-14h]
    flex_t v11; // [esp+18h] [ebp-14h]
    flex_t v12; // [esp+18h] [ebp-14h]
    flex_t v13; // [esp+18h] [ebp-14h]
    int32_t quantized; // [esp+1Ch] [ebp-10h]
    int32_t quantized_plus1; // [esp+20h] [ebp-Ch]
    flex32_t normalized_; // why tho (flex_t broke TWL matrix rotations)
    flex_t v17; // [esp+28h] [ebp-4h]
    flex_t v18; // [esp+28h] [ebp-4h]
    flex_t v19; // [esp+28h] [ebp-4h]
    flex_t v20; // [esp+28h] [ebp-4h]
    flex_t v21; // [esp+28h] [ebp-4h]
    flex_t v22; // [esp+28h] [ebp-4h]
    flex_t v23; // [esp+28h] [ebp-4h]
    flex_t v24; // [esp+28h] [ebp-4h]
    
    //_stdMath_SinCos(angle, pSinOut, pCosOut);
    //return;

    normalized = stdMath_NormalizeAngle(angle);
    normalized_ = normalized;
    if ( normalized >= 90.0 )
    {
        if ( normalized_ >= 180.0 )
        {
            if ( normalized_ >= 270.0 )
                v8 = 3;
            else
                v8 = 2;
        }
        else
        {
            v8 = 1;
        }
    }
    else
    {
        v8 = 0;
    }
    a1 = normalized_ * 45.511112;
    v6 = a1 - stdMath_Floor(a1);
    quantized = (int32_t)a1;
    // TODO quantized is set to -0x800000000??
#if defined(ARCH_64BIT) || defined(EXPERIMENTAL_FIXED_POINT)
    if (quantized > 0x8000 || quantized < -0x8000)
    {
        quantized = 0;
        quantized_plus1 = quantized + 1;
        v17 = aSinTable[quantized_plus1];
        v18 = aSinTable[4095 - quantized_plus1];
        *pSinOut = (v17 - aSinTable[quantized]) * v6 + aSinTable[quantized];
        *pCosOut = (v18 - aSinTable[4095 - quantized]) * v6 + aSinTable[4095 - quantized];
        return;
    }
#endif
    quantized_plus1 = quantized + 1;
    switch ( v8 )
    {
        case 0:
            if ( quantized_plus1 < 4096 )
                v17 = aSinTable[quantized_plus1];
            else
                v17 = aSinTable[4095 - (quantized - 4095)];
            *pSinOut = (v17 - aSinTable[quantized]) * v6 + aSinTable[quantized];
            if ( quantized_plus1 < 4096 )
                v18 = aSinTable[4095 - quantized_plus1];
            else
                v18 = -aSinTable[quantized_plus1 - 0x1000];
            *pCosOut = (v18 - aSinTable[4095 - quantized]) * v6 + aSinTable[4095 - quantized];
            break;
        case 1:
            if ( quantized_plus1 < 0x2000 )
                v19 = aSinTable[4095 - (quantized - 4095)];
            else
                v19 = -aSinTable[quantized_plus1 - 0x2000];
            v9 = aSinTable[4095 - (quantized - 4096)];
            *pSinOut = (v19 - v9) * v6 + v9;
            if ( quantized_plus1 < 0x2000 )
                v4 = -aSinTable[quantized_plus1 - 0x1000];
            else
                v4 = -aSinTable[4095 - (quantized - 0x1FFF)];
            v20 = v4;
            v10 = -aSinTable[quantized - 0x1000];
            *pCosOut = (v20 - v10) * v6 + v10;
            break;
        case 2:
            if ( quantized_plus1 < 0x3000 )
                v5 = -aSinTable[quantized_plus1 - 0x2000];
            else
                v5 = -aSinTable[4095 - (quantized - 12287)];
            v21 = v5;
            v11 = -aSinTable[quantized - 0x2000];
            *pSinOut = (v21 - v11) * v6 + v11;
            if ( quantized_plus1 < 0x3000 )
                v22 = -aSinTable[4095 - (quantized - 0x1FFF)];
            else
                v22 = aSinTable[quantized_plus1 - 0x3000];
            v12 = -aSinTable[4095 - (quantized - 0x2000)];
            *pCosOut = (v22 - v12) * v6 + v12;
            break;
        case 3:
            if ( quantized_plus1 < 0x4000 )
                v23 = -aSinTable[4095 - (quantized - 0x2FFF)];
            else
                v23 = aSinTable[quantized_plus1 - 0x4000];
            v13 = -aSinTable[4095 - (quantized - 0x3000)];
            *pSinOut = (v23 - v13) * v6 + v13;
            if ( quantized_plus1 < 0x4000 )
                v24 = aSinTable[quantized_plus1 - 0x3000];
            else
                v24 = aSinTable[4095 - (quantized - 0x3FFF)];
            *pCosOut = (v24 - aSinTable[quantized - 0x3000]) * v6 + aSinTable[quantized - 0x3000];
            break;
        default:
            return;
    }
}

flex_t stdMath_Dist2D1(flex_t a1, flex_t a2)
{
  flex_t v3; // [esp+0h] [ebp-18h]
  flex_t v4; // [esp+4h] [ebp-14h]
  flex_t v5; // [esp+8h] [ebp-10h]
  flex_t v6; // [esp+Ch] [ebp-Ch]

  if ( a1 >= 0.0 )
    v6 = a1;
  else
    v6 = -a1;
  if ( a2 >= 0.0 )
    v5 = a2;
  else
    v5 = -a2;
  if ( v6 <= v5 )
    v4 = v5;
  else
    v4 = v6;
  if ( v6 >= v5 )
    v3 = v5;
  else
    v3 = v6;
  return v3 / 2.0 + v4;
}

flex_t stdMath_Dist2D2(flex_t a1, flex_t a2)
{
  flex_t v3; // [esp+0h] [ebp-18h]
  flex_t v4; // [esp+4h] [ebp-14h]
  flex_t v5; // [esp+8h] [ebp-10h]
  flex_t v6; // [esp+Ch] [ebp-Ch]

  if ( a1 >= 0.0 )
    v6 = a1;
  else
    v6 = -a1;
  if ( a2 >= 0.0 )
    v5 = a2;
  else
    v5 = -a2;
  if ( v6 <= v5 )
    v4 = v5;
  else
    v4 = v6;
  if ( v6 >= v5 )
    v3 = v5;
  else
    v3 = v6;
  return v3 / 4.0 + v4;
}

flex_t stdMath_Dist2D3(flex_t a1, flex_t a2)
{
  flex_t v3; // [esp+0h] [ebp-18h]
  flex_t v4; // [esp+4h] [ebp-14h]
  flex_t v5; // [esp+8h] [ebp-10h]
  flex_t v6; // [esp+Ch] [ebp-Ch]

  if ( a1 >= 0.0 )
    v6 = a1;
  else
    v6 = -a1;
  if ( a2 >= 0.0 )
    v5 = a2;
  else
    v5 = -a2;
  if ( v6 <= v5 )
    v4 = v5;
  else
    v4 = v6;
  if ( v6 >= v5 )
    v3 = v5;
  else
    v3 = v6;
  return v3 * 0.375 + v4;
}

flex_t stdMath_Dist2D4(flex_t a1, flex_t a2)
{
  flex_t v3; // [esp+0h] [ebp-1Ch]
  flex_t v4; // [esp+4h] [ebp-18h]
  flex_t v5; // [esp+8h] [ebp-14h]
  flex_t v6; // [esp+Ch] [ebp-10h]
  flex_t v7; // [esp+10h] [ebp-Ch]

  if ( a1 >= 0.0 )
    v7 = a1;
  else
    v7 = -a1;
  if ( a2 >= 0.0 )
    v6 = a2;
  else
    v6 = -a2;
  if ( v7 <= v6 )
    v5 = v6;
  else
    v5 = v7;
  if ( v7 >= v6 )
    v4 = v6;
  else
    v4 = v7;
  if ( v5 * 0.875 + v4 / 2.0 >= v5 )
    v3 = v5 * 0.875 + v4 / 2.0;
  else
    v3 = v5;
  return v3;
}

flex_t stdMath_Dist3D1(flex_t a1, flex_t a2, flex_t a3)
{
  flex_t v4; // [esp+0h] [ebp-18h]
  flex_t v5; // [esp+4h] [ebp-14h]
  flex_t v6; // [esp+8h] [ebp-10h]
  flex_t v7; // [esp+Ch] [ebp-Ch]
  flex_t v8; // [esp+10h] [ebp-8h]
  flex_t v9; // [esp+14h] [ebp-4h]

  // Added: fix undef behavior
  v9 = 0.0;
  v8 = 0.0;
  v7 = 0.0;

  if ( a1 >= 0.0 )
    v6 = a1;
  else
    v6 = -a1;
  if ( a2 >= 0.0 )
    v5 = a2;
  else
    v5 = -a2;
  if ( a3 >= 0.0 )
    v4 = a3;
  else
    v4 = -a3;
  if ( v6 <= v5 )
  {
    if ( v5 > v4 )
    {
      v8 = v5;
      if ( v6 <= v4 )
      {
        v9 = v4;
        v7 = v6;
      }
      else
      {
        v9 = v6;
        v7 = v4;
      }
    }
  }
  else if ( v6 > v4 )
  {
    v8 = v6;
    if ( v5 <= v4 )
    {
      v9 = v4;
      v7 = v5;
    }
    else
    {
      v9 = v5;
      v7 = v4;
    }
  }
  return v9 / 2.0 + v8 + v7 / 2.0;
}

flex_t stdMath_Dist3D2(flex_t a1, flex_t a2, flex_t a3)
{
  flex_t v4; // [esp+0h] [ebp-18h]
  flex_t v5; // [esp+4h] [ebp-14h]
  flex_t v6; // [esp+8h] [ebp-10h]
  flex_t v7; // [esp+Ch] [ebp-Ch]
  flex_t v8; // [esp+10h] [ebp-8h]
  flex_t v9; // [esp+14h] [ebp-4h]

  // Added: fix undef behavior
  v9 = 0.0;
  v8 = 0.0;
  v7 = 0.0;

  if ( a1 >= 0.0 )
    v6 = a1;
  else
    v6 = -a1;
  if ( a2 >= 0.0 )
    v5 = a2;
  else
    v5 = -a2;
  if ( a3 >= 0.0 )
    v4 = a3;
  else
    v4 = -a3;
  if ( v6 <= v5 )
  {
    if ( v5 > v4 )
    {
      v8 = v5;
      if ( v6 <= v4 )
      {
        v9 = v4;
        v7 = v6;
      }
      else
      {
        v9 = v6;
        v7 = v4;
      }
    }
  }
  else if ( v6 > v4 )
  {
    v8 = v6;
    if ( v5 <= v4 )
    {
      v9 = v4;
      v7 = v5;
    }
    else
    {
      v9 = v5;
      v7 = v4;
    }
  }
  return 0.3125 * v9 + v8 + v7 / 2.0;
}

flex_t stdMath_Dist3D3(flex_t a1, flex_t a2, flex_t a3)
{
  flex_t v4; // [esp+0h] [ebp-18h]
  flex_t v5; // [esp+4h] [ebp-14h]
  flex_t v6; // [esp+8h] [ebp-10h]
  flex_t v7; // [esp+Ch] [ebp-Ch]
  flex_t v8; // [esp+10h] [ebp-8h]
  flex_t v9; // [esp+14h] [ebp-4h]

  // Added: fix undef behavior
  v9 = 0.0;
  v8 = 0.0;
  v7 = 0.0;

  if ( a1 >= 0.0 )
    v6 = a1;
  else
    v6 = -a1;
  if ( a2 >= 0.0 )
    v5 = a2;
  else
    v5 = -a2;
  if ( a3 >= 0.0 )
    v4 = a3;
  else
    v4 = -a3;
  if ( v6 <= v5 )
  {
    if ( v5 > v4 )
    {
      v8 = v5;
      if ( v6 <= v4 )
      {
        v9 = v4;
        v7 = v6;
      }
      else
      {
        v9 = v6;
        v7 = v4;
      }
    }
  }
  else if ( v6 > v4 )
  {
    v8 = v6;
    if ( v5 <= v4 )
    {
      v9 = v4;
      v7 = v5;
    }
    else
    {
      v9 = v5;
      v7 = v4;
    }
  }
  return 0.34375 * v9 + v8 + v7 / 2.0;
}

flex_t stdMath_Floor(flex_t a)
{
#if defined(EXPERIMENTAL_FIXED_POINT)
    return flexdirect(a.to_raw() & ~((1<<FIXED_POINT_DECIMAL_BITS)-1));
#else
    return floorf((float)a);
#endif
}

// From https://github.com/chmike/fpsqrt/blob/master/fpsqrt.c
int32_t sqrt_fx16_16_to_fx16_16(int32_t v) {
    uint32_t t, q, b, r;
    r = (int32_t)v; 
    q = 0;          
    b = 0x40000000UL;
    if( r < 0x40000200 )
    {
        while( b != 0x40 )
        {
            t = q + b;
            if( r >= t )
            {
                r -= t;
                q = t + b; // equivalent to q += 2*b
            }
            r <<= 1;
            b >>= 1;
        }
        q >>= 8;
        return q;
    }
    while( b > 0x40 )
    {
        t = q + b;
        if( r >= t )
        {
            r -= t;
            q = t + b; // equivalent to q += 2*b
        }
        if( (r & 0x80000000) != 0 )
        {
            q >>= 1;
            b >>= 1;
            r >>= 1;
            while( b > 0x20 )
            {
                t = q + b;
                if( r >= t )
                {
                    r -= t;
                    q = t + b;
                }
                r <<= 1;
                b >>= 1;
            }
            q >>= 7;
            return q;
        }
        r <<= 1;
        b >>= 1;
    }
    q >>= 8;
    return q;
}

flex_t stdMath_Sqrt(flex_t a)
{
#if 0
    static int last_frame = 0;
    static int num_sqrts = 0;
    extern int std3D_frameCount;
    if (last_frame != std3D_frameCount) {
        printf("sqrts %d\n", num_sqrts);
        last_frame = std3D_frameCount;
        num_sqrts = 0;
    }
    num_sqrts += 1;
#endif

    if (a < (flex_t)0.0)
        return (flex_t)0.0;

#if defined(TARGET_TWL)
    //return f32toflex(sqrtf32_mine(flextof32(a)));
    //return flexdirect(sqrt_fx16_16_to_fx16_16(a.to_raw()));
    return sqrtfixed_mine(a);
#elif defined(EXPERIMENTAL_FIXED_POINT)
    //return flexdirect(sqrt_fx16_16_to_fx16_16(a.to_raw()));
    return sqrtf((float)a);
#else
    return sqrtf((float)a);
#endif
}

flex_t stdMath_Tan(flex_t a1)
{
    flex_d_t v1; // st7
    flex_t v3; // [esp+Ch] [ebp-20h]
    flex_t a1a; // [esp+10h] [ebp-1Ch]
    int32_t v5; // [esp+14h] [ebp-18h]
    flex_t v6; // [esp+18h] [ebp-14h]
    flex_t v7; // [esp+18h] [ebp-14h]
    int32_t v8; // [esp+1Ch] [ebp-10h]
    flex_t v9; // [esp+20h] [ebp-Ch]
    int32_t v10; // [esp+24h] [ebp-8h]
    flex_t v11; // [esp+28h] [ebp-4h]
    flex_t v12; // [esp+28h] [ebp-4h]
    flex_t v13; // [esp+28h] [ebp-4h]
    flex_t v14; // [esp+28h] [ebp-4h]
    flex_t v15; // [esp+34h] [ebp+8h]

    v1 = stdMath_NormalizeAngle(a1);
    v15 = v1;
    if ( v1 >= 90.0 )
    {
        if ( v15 >= 180.0 )
        {
            if ( v15 >= 270.0 )
                v5 = 3;
            else
                v5 = 2;
        }
        else
        {
            v5 = 1;
        }
    }
    else
    {
        v5 = 0;
    }
    a1a = v15 / 360.0 * 16384.0;
    v3 = a1a - stdMath_Floor(a1a);
    v8 = (__int64)a1a;
    v10 = v8 + 1;
    switch ( v5 )
    {
        case 0:
            if ( v10 < 0x1000 )
                v11 = aTanTable[v10];
            else
                v11 = -aTanTable[0xFFF - (v8 - 0xFFF)];
            v9 = (v11 - aTanTable[v8]) * v3 + aTanTable[v8];
            break;
        case 1:
            if ( v10 < 0x2000 )
                v12 = -aTanTable[0xFFF - (v8 - 0xFFF)];
            else
                v12 = aTanTable[v10 - 0x2000];
            v6 = -aTanTable[0xFFF - (v8 - 0x1000)];
            v9 = (v12 - v6) * v3 + v6;
            break;
        case 2:
            if ( v10 < 0x3000 )
                v13 = aTanTable[v10 - 0x3000];
            else
                v13 = -aTanTable[0xFFF - (v8 - 0x2FFF)];
            v9 = (v13 - aTanTable[0xFFF - (v8 - 0x2000)]) * v3 + aTanTable[0xFFF - (v8 - 0x2000)];
            break;
        case 3:
            if ( v10 < 0x4000 )
                v14 = -aTanTable[0xFFF - (v8 - 0x2FFF)];
            else
                v14 = aTanTable[v10 - 0x4000];
            v7 = -aTanTable[0xFFF - (v8 - 0x3000)];
            v9 = (v14 - v7) * v3 + v7;
            break;
        default:
            v9 = 0.0; // added
            return v9;
    }
    return v9;
}

flex_t stdMath_ArcSin1(flex_t val)
{
    flex_d_t angle; // st7
    flex_t v2; // [esp+0h] [ebp-14h]
    flex_t v3; // [esp+4h] [ebp-10h]
    flex_t v5; // [esp+10h] [ebp-4h]
    flex_t v6; // [esp+1Ch] [ebp+8h]

    if ( val >= 0.0 )
        v3 = val;
    else
        v3 = -val;

    // TODO: verify all these constants are expanded properly to the og values
    if ( v3 <= 0.70710677 )
    {
        v5 = (stdMath_FlexPower(v3, 3) * 0.212749 + v3) *  (180.0 / M_PI);
    }
    else
    {
        v2 = 1.0 - v3 * v3;
        v6 = stdMath_Sqrt(v2);
        v5 = 90.0 - (stdMath_FlexPower(v6, 3) * 0.212749 + v6) *  (180.0 / M_PI);
    }

    if ( val < 0.0 )
        angle = -v5;
    else
        angle = v5;

    return angle;
}

flex_t stdMath_ArcSin2(flex_t val)
{
    flex_d_t angle; // st7
    flex_t v2; // [esp+0h] [ebp-1Ch]
    flex_t v3; // [esp+4h] [ebp-18h]
    flex_t v4; // [esp+8h] [ebp-14h]
    flex_t v5; // [esp+Ch] [ebp-10h]

    flex_t v7; // [esp+18h] [ebp-4h]
    flex_t v8; // [esp+24h] [ebp+8h]

    if ( val >= 0.0 )
        v5 = val;
    else
        v5 = -val;

    // TODO: verify all these constants are expanded properly to the og values
    if ( v5 <= 0.70710677 )
    {
        v3 = stdMath_FlexPower(v5, 3) / 6.0 + v5;
        v7 = (stdMath_FlexPower(v5, 5) * 0.105502 + v3) *  (180.0 / M_PI);
    }
    else
    {
        v2 = 1.0 - v5 * v5;
        v8 = stdMath_Sqrt(v2);
        v4 = stdMath_FlexPower(v8, 3) / 6.0 + v8;
        v7 = 90.0 - (stdMath_FlexPower(v8, 5) * 0.105502 + v4) *  (180.0 / M_PI);
    }

    if ( val < 0.0 )
        angle = -v7;
    else
        angle = v7;

    return angle;
}

flex_t stdMath_ArcSin3(flex_t a1)
{
    flex_t v2; // [esp+0h] [ebp-24h]
    flex_t v3; // [esp+4h] [ebp-20h]
    flex_t v4; // [esp+8h] [ebp-1Ch]
    flex_t v5; // [esp+Ch] [ebp-18h]
    flex_t v6; // [esp+10h] [ebp-14h]
    flex_t v7; // [esp+14h] [ebp-10h]
    flex_t v9; // [esp+20h] [ebp-4h]
    flex_t v10; // [esp+2Ch] [ebp+8h]


    if ( a1 >= 0.0 )
        v7 = a1;
    else
        v7 = -a1;

    if ( v7 <= 0.70710677 )
    {
        v4 = stdMath_FlexPower(v7, 3) / 6.0 + v7;
        v3 = stdMath_FlexPower(v7, 5) * 0.075000003 + v4;
        v9 = (stdMath_FlexPower(v7, 7) * 0.066797003 + v3) * (180.0 / M_PI);
    }
    else
    {
        v2 = 1.0 - v7 * v7;
        v10 = stdMath_Sqrt(v2);
        v6 = stdMath_FlexPower(v10, 3) / 6.0 + v10;
        v5 = stdMath_FlexPower(v10, 5) * 0.075000003 + v6;
        v9 = 90.0 - (stdMath_FlexPower(v10, 7) * 0.066797003 + v5) * (180.0 / M_PI);
    }
    if ( a1 < 0.0 )
        return -v9;
    else
        return v9;
}

flex_t stdMath_ArcTan1(flex_t a1, flex_t a2)
{
    flex_d_t v3; // st7
    flex_t v4; // [esp+0h] [ebp-24h]
    flex_t v5; // [esp+4h] [ebp-20h]
    flex_t v6; // [esp+Ch] [ebp-18h]
    flex_t v7; // [esp+1Ch] [ebp-8h]
    flex_t v8; // [esp+1Ch] [ebp-8h]
    flex_t v9; // [esp+20h] [ebp-4h]

    if ( a2 == 0.0 && a1 == 0.0 )
        return 0.0;
    if ( a1 >= 0.0 )
        v6 = a1;
    else
        v6 = -a1;
    if ( a2 >= 0.0 )
        v5 = a2;
    else
        v5 = -a2;
    if ( v5 <= (flex_d_t)v6 )
        v3 = v5 / v6;
    else
        v3 = v6 / v5;
    v9 = v3;
    if ( v9 >= 0.0 )
        v4 = v3;
    else
        v4 = -v9;
    v7 = (v4 - stdMath_FlexPower(v4, 3) * 0.22629) * (180.0 / M_PI);
    if ( v6 >= (flex_d_t)v5 )
        v7 = 90.0 - v7;
    v8 = 90.0 - v7;
    if ( a1 < 0.0 )
        v8 = 180.0 - v8;
    if ( a2 >= 0.0 )
        v8 = -v8;
    return v8;
}

flex_t stdMath_ArcTan2(flex_t a1, flex_t a2)
{
    flex_d_t v3; // st7
    flex_t v4; // [esp+0h] [ebp-28h]
    flex_t v5; // [esp+4h] [ebp-24h]
    flex_t v6; // [esp+8h] [ebp-20h]
    flex_t v7; // [esp+10h] [ebp-18h]
    flex_t v8; // [esp+20h] [ebp-8h]
    flex_t v9; // [esp+20h] [ebp-8h]
    flex_t v10; // [esp+24h] [ebp-4h]

    if ( a2 == 0.0 && a1 == 0.0 )
        return 0.0;
    if ( a1 >= 0.0 )
        v7 = a1;
    else
        v7 = -a1;
    if ( a2 >= 0.0 )
        v6 = a2;
    else
        v6 = -a2;
    if ( v6 <= (flex_d_t)v7 )
        v3 = v6 / v7;
    else
        v3 = v7 / v6;
    v10 = v3;
    if ( v10 >= 0.0 )
        v5 = v3;
    else
        v5 = -v10;
    v4 = v5 - stdMath_FlexPower(v5, 3) / 3.0;
    v8 = (stdMath_FlexPower(v5, 5) * 0.12366 + v4) * (180.0 / M_PI);
    if ( v7 >= (flex_d_t)v6 )
        v8 = 90.0 - v8;
    v9 = 90.0 - v8;
    if ( a1 < 0.0 )
        v9 = 180.0 - v9;
    if ( a2 >= 0.0 )
        v9 = -v9;
    return v9;
}

flex_t stdMath_ArcTan3(flex_t a1, flex_t a2)
{
    flex_d_t v3; // st7
    flex_t v4; // [esp+0h] [ebp-2Ch]
    flex_t v5; // [esp+4h] [ebp-28h]
    flex_t v6; // [esp+8h] [ebp-24h]
    flex_t v7; // [esp+Ch] [ebp-20h]
    flex_t v8; // [esp+14h] [ebp-18h]
    flex_t v9; // [esp+24h] [ebp-8h]
    flex_t v10; // [esp+24h] [ebp-8h]
    flex_t v11; // [esp+28h] [ebp-4h]

    if ( a2 == 0.0 && a1 == 0.0 )
        return 0.0;
    if ( a1 >= 0.0 )
        v8 = a1;
    else
        v8 = -a1;
    if ( a2 >= 0.0 )
        v7 = a2;
    else
        v7 = -a2;
    if ( v7 <= (flex_d_t)v8 )
        v3 = v7 / v8;
    else
        v3 = v8 / v7;
    v11 = v3;
    if ( v11 >= 0.0 )
        v6 = v3;
    else
        v6 = -v11;
    v5 = v6 - stdMath_FlexPower(v6, 3) / 3.0;
    v4 = stdMath_FlexPower(v6, 5) / 5.0 + v5;
    v9 = (v4 - stdMath_FlexPower(v6, 7) * 0.083920002) * (180.0 / M_PI);
    if ( v8 >= (flex_d_t)v7 )
        v9 = 90.0 - v9;
    v10 = 90.0 - v9;
    if ( a1 < 0.0 )
        v10 = 180.0 - v10;
    if ( a2 >= 0.0 )
        v10 = -v10;
    return v10;
}

flex_t stdMath_ArcTan4(flex_t a1, flex_t a2)
{
    flex_d_t v3; // st7
    flex_t v4; // [esp+0h] [ebp-30h]
    flex_t v5; // [esp+4h] [ebp-2Ch]
    flex_t v6; // [esp+8h] [ebp-28h]
    flex_t v7; // [esp+Ch] [ebp-24h]
    flex_t v8; // [esp+10h] [ebp-20h]
    flex_t v9; // [esp+18h] [ebp-18h]
    flex_t v10; // [esp+28h] [ebp-8h]
    flex_t v11; // [esp+28h] [ebp-8h]
    flex_t v12; // [esp+2Ch] [ebp-4h]

    if ( a2 == 0.0 && a1 == 0.0 )
        return 0.0;
    if ( a1 >= 0.0 )
        v9 = a1;
    else
        v9 = -a1;
    if ( a2 >= 0.0 )
        v8 = a2;
    else
        v8 = -a2;
    if ( v8 <= (flex_d_t)v9 )
        v3 = v8 / v9;
    else
        v3 = v9 / v8;
    v12 = v3;
    if ( v12 >= 0.0 )
        v7 = v3;
    else
        v7 = -v12;
    v6 = v7 - stdMath_FlexPower(v7, 3) / 3.0;
    v5 = stdMath_FlexPower(v7, 5) / 5.0 + v6;
    v4 = v5 - stdMath_FlexPower(v7, 7) / 7.0;
    v10 = (stdMath_FlexPower(v7, 9) * 0.063235 + v4) * (180.0 / M_PI);
    if ( v9 >= (flex_d_t)v8 )
        v10 = 90.0 - v10;
    v11 = 90.0 - v10;
    if ( a1 < 0.0 )
        v11 = 180.0 - v11;
    if ( a2 >= 0.0 )
        v11 = -v11;
    return v11;
}

int32_t stdMath_FloorDivMod(int32_t in1, int32_t in2, int32_t *out1, int32_t *out2)
{
    int32_t result; // eax
    int32_t v5; // [esp+0h] [ebp-8h]
    int32_t v6; // [esp+4h] [ebp-4h]

    if ( in1 < 0 )
    {
        v6 = -(-in1 / in2);
        v5 = -in1 % in2;
        if ( v5 )
        {
            --v6;
            v5 = in2 - v5;
        }
    }
    else
    {
        v6 = in1 / in2;
        v5 = in1 % in2;
    }
    result = v6;
    *out1 = v6;
    *out2 = v5;
    return result;
}

flex_t stdMath_ClipPrecision(flex_t val)
{
    if (stdMath_Fabs(val) <= 0.00001)
        return 0.0;
    return val;
}

flex_t stdMath_Clamp(flex_t val, flex_t valMin, flex_t valMax)
{
    if (val < valMin)
        return valMin;
    
    if (val > valMax)
        return valMax;

    return val;
}

flex_t stdMath_ClampValue(flex_t val, flex_t valAbsMax)
{
    valAbsMax = stdMath_Fabs(valAbsMax);
    
    if (val < -valAbsMax)
        return -valAbsMax;
    
    if (val > valAbsMax)
        return valAbsMax;

    return val;
}