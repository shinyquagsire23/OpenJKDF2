#include "rdClip.h"

#include "rdCanvas.h"

int rdClip_Line2(rdCanvas *canvas, signed int *pX1, signed int *pY1, signed int *pX2, signed int *pY2)
{
    unsigned int clipOutcodeX1Y1;
    signed int clipOutcodeX2Y2;
    signed int fY1_same_fY2;
    unsigned int clipCode;
    double x_clipped;
    double y_clipped;
    float fY1;
    float fX2;
    float fY2;
    float fX1;

    clipOutcodeX1Y1 = rdClip_CalcOutcode2(canvas, *pX1, *pY1);
    clipOutcodeX2Y2 = rdClip_CalcOutcode2(canvas, *pX2, *pY2);
    
    if ( !clipOutcodeX1Y1 && !clipOutcodeX2Y2 )
        return 1;
    if ( clipOutcodeX2Y2 & clipOutcodeX1Y1 )
        return 0;

    fX1 = (double)*pX1;
    fX2 = (double)*pX2;
    fY1 = (double)*pY1;
    fY2 = (double)*pY2;

    clipCode = clipOutcodeX1Y1;
    if ( !clipOutcodeX1Y1 )
        clipCode = clipOutcodeX2Y2;

    // TODO this doesn't feel correct?
    if (clipCode & CLIP_TOP)
    {
        x_clipped = (fY2 == fY1) ? fX1 : (fX2 - fX1) / (fY2 - fY1) * ((double)canvas->yStart - fY1) + fX1;
        y_clipped = (double)canvas->yStart;
    }
    else if (clipCode & CLIP_BOTTOM)
    {
        x_clipped = (fY2 == fY1) ? fX1 : (fX2 - fX1) / (fY2 - fY1) * ((double)canvas->heightMinusOne - fY1) + fX1;
        y_clipped = (double)canvas->heightMinusOne;
    }
    else if (clipCode & CLIP_RIGHT)
    {
        x_clipped = (double)canvas->widthMinusOne;
        y_clipped = (fX2 == fX1) ? fY1 : (fY2 - fY1) / (fX2 - fX1) * ((double)canvas->widthMinusOne - fX1) + fY1;
    }
    else if (clipCode & CLIP_LEFT)
    {
        x_clipped = (double)canvas->xStart;
        y_clipped = (fX2 == fX1) ? fY1 : (float)((fY2 - fY1) / (fX2 - fX1) * ((double)canvas->xStart - fX1) + fY1);
    }

    if (clipCode == clipOutcodeX1Y1)
    {
        fX1 = x_clipped;
        fY1 = y_clipped;
        clipOutcodeX1Y1 = rdClip_CalcOutcode2(canvas, (int)x_clipped, (int)y_clipped);
    }
    else
    {
        fX2 = x_clipped;
        fY2 = y_clipped;
        clipOutcodeX2Y2 = rdClip_CalcOutcode2(canvas, (int)x_clipped, (int)y_clipped);
    }
    
    if ( clipOutcodeX2Y2 & clipOutcodeX1Y1 )
        return 0;
    
    *pX1 = (signed __int64)fX1;
    *pY1 = (signed __int64)fY1;
    *pX2 = (signed __int64)fX2;
    *pY2 = (signed __int64)fY2;
    return 1;
}


int rdClip_CalcOutcode2(rdCanvas *canvas, int x, int y)
{
    int result = 0;

    if (x > canvas->widthMinusOne)
        result |= CLIP_RIGHT;
    else if (x < canvas->xStart)
        result |= CLIP_LEFT;

    if (y < canvas->yStart)
        result |= CLIP_TOP;
    else if (y > canvas->heightMinusOne)
        result |= CLIP_BOTTOM;

    return result;
}
