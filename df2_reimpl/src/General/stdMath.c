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
    return sqrtf(a);
}
