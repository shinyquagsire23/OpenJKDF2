// rdAFRaster textured span-sampler template — NOT a normal header (no include guard). rdAFRaster.c
// #includes it once per GrimFandango DrawSpanNGon<V>_8 symbol with the mode macros set; the trailer
// #undefs them. Same #define/#ifdef/#undef metaprogramming JK used to spin its combinatorial family
// out of one inner loop (see rdZRaster_ngon.h / rdNRaster_ngon.h).
//
// This is the AFFINE active-edge module's per-span sampler: it consumes one rdActiveSpan (built by
// rdActive_BuildSpans) and writes its pixels. Two surface families share this body:
//   - AT (affine):     u,v step linearly as 16.16 fixed across the span (EmitSpan pre-applied mip).
//   - IT (perspective): u/z,v/z,1/z interpolate as floats; the sampler divides per pixel (>>mip).
// The per-face texture/light params are latched into rdAFRaster_cur* globals by the DrawNGon flush.
//
// Caller sets before including:
//   RDA_NAME         function name to emit (e.g. rdAFRaster_DrawSpanNGonMGIT_8)
//   RDA_PERSP        0 = affine (AT);  1 = perspective (IT, per-pixel 1/z divide)
//   RDA_MASKED       1 = skip transparent texels (palette index 0)
//   RDA_SHADE        RDA_FLAT (raw texel) / RDA_LIT (one light row) / RDA_GOURAUD (per-pixel light)

static void RDA_NAME(rdActiveSpan* pSpan)
{
    tVBuffer* pVBuffer = rdCamera_g_pCurCamera->pCanvas->pVBuffer;
    uint32_t stride = pVBuffer->format.rowSize;
    int fbW = pVBuffer->format.width;
    int fbH = pVBuffer->format.height;
    int y = pSpan->y;
    if (y < 0 || y >= fbH)
        return;

    int xStart = pSpan->xStart;
    int count = pSpan->width;

#if RDA_PERSP
    flex_t uoz  = rdAFRaster_SlotToFloat(pSpan->u);
    flex_t duoz = rdAFRaster_SlotToFloat(pSpan->du);
    flex_t voz  = rdAFRaster_SlotToFloat(pSpan->v);
    flex_t dvoz = rdAFRaster_SlotToFloat(pSpan->dv);
    flex_t ooz  = pSpan->oneOverZ;
    flex_t dooz = pSpan->dOneOverZ;
    int mip = rdAFRaster_curMip;
#else
    int32_t du = pSpan->du;
    int32_t dv = pSpan->dv;
    uint32_t uAcc = (uint32_t)pSpan->u + (uint32_t)rdAFRaster_curURoundBias;
    uint32_t vAcc = (uint32_t)pSpan->v + (uint32_t)rdAFRaster_curVRoundBias;
#endif
#if RDA_SHADE == RDA_GOURAUD
    int32_t dz = pSpan->dz;
    uint32_t zAcc = (uint32_t)pSpan->z;
#endif

    // Clip the span to the framebuffer (geometry clipped to the canvas can still land a pixel or
    // two outside); advance the interpolants across any left-clipped pixels.
    if (xStart < 0)
    {
        int skip = -xStart;
        if (skip >= count)
            return;
#if RDA_PERSP
        uoz += duoz * (flex_t)skip; voz += dvoz * (flex_t)skip; ooz += dooz * (flex_t)skip;
#else
        uAcc += (uint32_t)du * (uint32_t)skip; vAcc += (uint32_t)dv * (uint32_t)skip;
#endif
#if RDA_SHADE == RDA_GOURAUD
        zAcc += (uint32_t)dz * (uint32_t)skip;
#endif
        xStart = 0;
        count -= skip;
    }
    if (xStart + count > fbW)
        count = fbW - xStart;
    if (count <= 0)
        return;

    const uint8_t* pTexels = rdAFRaster_curTexels;
#if RDA_SHADE != RDA_FLAT
    const uint8_t* pLight = rdAFRaster_curLightTable;
#endif
    uint32_t uMask = rdAFRaster_curUMask;
    uint32_t vMask = rdAFRaster_curVMask;
    int vshiftAmt = 0x10 - rdAFRaster_curVShift;
    uint8_t* pDst = (uint8_t*)pVBuffer->surface_lock_alloc + xStart + y * stride;

    for (int i = 0; i < count; i++)
    {
#if RDA_PERSP
        flex_t w = (ooz != 0.0f) ? (1.0f / ooz) : 0.0f;
        uint32_t uAcc = (uint32_t)(((int32_t)(uoz * w * 65536.0f)) >> mip) + (uint32_t)rdAFRaster_curURoundBias;
        uint32_t vAcc = (uint32_t)(((int32_t)(voz * w * 65536.0f)) >> mip) + (uint32_t)rdAFRaster_curVRoundBias;
#endif
        uint32_t col = (uAcc & uMask) >> 16;
        uint32_t row = (vAcc >> vshiftAmt) & vMask;
        uint8_t texel = pTexels[row + col];
#if RDA_MASKED
        if (texel != 0)
        {
#endif
#if RDA_SHADE == RDA_LIT
            texel = pLight[texel];
#elif RDA_SHADE == RDA_GOURAUD
            texel = pLight[((zAcc & 0x3f0000) >> 8) + texel];
#endif
            // Word-safe byte write (the vbuffer can live in word-addressable VRAM/extram).
            stdPlatform_WriteByte16(pDst + i, texel);
#if RDA_MASKED
        }
#endif
#if RDA_PERSP
        uoz += duoz; voz += dvoz; ooz += dooz;
#else
        uAcc += (uint32_t)du; vAcc += (uint32_t)dv;
#endif
#if RDA_SHADE == RDA_GOURAUD
        zAcc += (uint32_t)dz;
#endif
    }
}

#undef RDA_NAME
#undef RDA_PERSP
#undef RDA_MASKED
#undef RDA_SHADE
