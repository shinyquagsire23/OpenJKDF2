#include "stdMath.h"

#include <math.h>

#include "stdMathTables.h"

float stdMath_FlexPower(float num, int exp)
{
    float retval = num;

    for (int i = 0; i < exp - 1; ++i)
    {
        retval = retval * num;
    }
    return retval;
}

float stdMath_NormalizeAngle(float angle)
{
    float retval;

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

float stdMath_NormalizeAngleAcute(float angle)
{
    float norm = stdMath_NormalizeAngle(angle);
    if ( norm > 180.0 )
        return -(360.0 - norm);
    return norm;
}

float stdMath_NormalizeDeltaAngle(float a1, float a2)
{
    float result;
    float delta;

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

void stdMath_SinCos(float angle, float *pSinOut, float *pCosOut)
{
    double normalized; // st7
    double v4; // st7
    double v5; // st7
    float v6; // [esp+Ch] [ebp-20h]
    float a1; // [esp+10h] [ebp-1Ch]
    int v8; // [esp+14h] [ebp-18h]
    float v9; // [esp+18h] [ebp-14h]
    float v10; // [esp+18h] [ebp-14h]
    float v11; // [esp+18h] [ebp-14h]
    float v12; // [esp+18h] [ebp-14h]
    float v13; // [esp+18h] [ebp-14h]
    int quantized; // [esp+1Ch] [ebp-10h]
    int quantized_plus1; // [esp+20h] [ebp-Ch]
    float normalized_; // [esp+24h] [ebp-8h]
    float v17; // [esp+28h] [ebp-4h]
    float v18; // [esp+28h] [ebp-4h]
    float v19; // [esp+28h] [ebp-4h]
    float v20; // [esp+28h] [ebp-4h]
    float v21; // [esp+28h] [ebp-4h]
    float v22; // [esp+28h] [ebp-4h]
    float v23; // [esp+28h] [ebp-4h]
    float v24; // [esp+28h] [ebp-4h]
    
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
    quantized = (int)a1;
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

float stdMath_Dist2D1(float a1, float a2)
{
  float v3; // [esp+0h] [ebp-18h]
  float v4; // [esp+4h] [ebp-14h]
  float v5; // [esp+8h] [ebp-10h]
  float v6; // [esp+Ch] [ebp-Ch]

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

float stdMath_Dist2D2(float a1, float a2)
{
  float v3; // [esp+0h] [ebp-18h]
  float v4; // [esp+4h] [ebp-14h]
  float v5; // [esp+8h] [ebp-10h]
  float v6; // [esp+Ch] [ebp-Ch]

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

float stdMath_Dist2D3(float a1, float a2)
{
  float v3; // [esp+0h] [ebp-18h]
  float v4; // [esp+4h] [ebp-14h]
  float v5; // [esp+8h] [ebp-10h]
  float v6; // [esp+Ch] [ebp-Ch]

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

float stdMath_Dist2D4(float a1, float a2)
{
  float v3; // [esp+0h] [ebp-1Ch]
  float v4; // [esp+4h] [ebp-18h]
  float v5; // [esp+8h] [ebp-14h]
  float v6; // [esp+Ch] [ebp-10h]
  float v7; // [esp+10h] [ebp-Ch]

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

float stdMath_Dist3D1(float a1, float a2, float a3)
{
  float v4; // [esp+0h] [ebp-18h]
  float v5; // [esp+4h] [ebp-14h]
  float v6; // [esp+8h] [ebp-10h]
  float v7; // [esp+Ch] [ebp-Ch]
  float v8; // [esp+10h] [ebp-8h]
  float v9; // [esp+14h] [ebp-4h]

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

float stdMath_Dist3D2(float a1, float a2, float a3)
{
  float v4; // [esp+0h] [ebp-18h]
  float v5; // [esp+4h] [ebp-14h]
  float v6; // [esp+8h] [ebp-10h]
  float v7; // [esp+Ch] [ebp-Ch]
  float v8; // [esp+10h] [ebp-8h]
  float v9; // [esp+14h] [ebp-4h]

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

float stdMath_Dist3D3(float a1, float a2, float a3)
{
  float v4; // [esp+0h] [ebp-18h]
  float v5; // [esp+4h] [ebp-14h]
  float v6; // [esp+8h] [ebp-10h]
  float v7; // [esp+Ch] [ebp-Ch]
  float v8; // [esp+10h] [ebp-8h]
  float v9; // [esp+14h] [ebp-4h]

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

float stdMath_Floor(float a)
{
    return floorf(a);
}

float stdMath_Sqrt(float a)
{
    if (a < 0.0)
        return 0.0;

    return sqrtf(a);
}

float stdMath_ArcSin3(float a1)
{
    float v2; // [esp+0h] [ebp-24h]
    float v3; // [esp+4h] [ebp-20h]
    float v4; // [esp+8h] [ebp-1Ch]
    float v5; // [esp+Ch] [ebp-18h]
    float v6; // [esp+10h] [ebp-14h]
    float v7; // [esp+14h] [ebp-10h]
    float v9; // [esp+20h] [ebp-4h]
    float v10; // [esp+2Ch] [ebp+8h]


    if ( a1 >= 0.0 )
        v7 = a1;
    else
        v7 = -a1;

    if ( v7 <= 0.70710677 )
    {
        v4 = stdMath_FlexPower(v7, 3) / 6.0 + v7;
        v3 = stdMath_FlexPower(v7, 5) * 0.075000003 + v4;
        v9 = (stdMath_FlexPower(v7, 7) * 0.066797003 + v3) * 57.295784;
    }
    else
    {
        v2 = 1.0 - v7 * v7;
        v10 = stdMath_Sqrt(v2);
        v6 = stdMath_FlexPower(v10, 3) / 6.0 + v10;
        v5 = stdMath_FlexPower(v10, 5) * 0.075000003 + v6;
        v9 = 90.0 - (stdMath_FlexPower(v10, 7) * 0.066797003 + v5) * 57.295784;
    }
    if ( a1 < 0.0 )
        return -v9;
    else
        return v9;
}

float stdMath_Tan(float a1)
{
    double v1; // st7
    float v3; // [esp+Ch] [ebp-20h]
    float a1a; // [esp+10h] [ebp-1Ch]
    int v5; // [esp+14h] [ebp-18h]
    float v6; // [esp+18h] [ebp-14h]
    float v7; // [esp+18h] [ebp-14h]
    int v8; // [esp+1Ch] [ebp-10h]
    float v9; // [esp+20h] [ebp-Ch]
    int v10; // [esp+24h] [ebp-8h]
    float v11; // [esp+28h] [ebp-4h]
    float v12; // [esp+28h] [ebp-4h]
    float v13; // [esp+28h] [ebp-4h]
    float v14; // [esp+28h] [ebp-4h]
    float v15; // [esp+34h] [ebp+8h]

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
