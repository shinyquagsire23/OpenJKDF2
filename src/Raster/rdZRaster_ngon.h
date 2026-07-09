// rdZRaster DrawNGon variant template — NOT a normal header (no include guard). rdZRaster.c
// #includes this once per JK.EXE/GrimFandango DrawNGon symbol with the mode macros set; the
// trailer at the bottom #undefs them. This is the same metaprogramming JK used to spin its
// combinatorial rasterizer family out of one scanline body: each #include emits a real,
// separately-named function so the decompiled symbol list is complete, while the logic lives in
// exactly one place. Every variant is z-buffered.
//
// Caller sets before including:
//   RDZ_NAME         function name to emit (e.g. rdZRaster_DrawNGonMTGAT)
//   RDZ_SOLID        1 = flat solid fill (untextured);  0 = textured
//   RDZ_AFFINE       (textured only) 1 = affine u,v (AT);  0 = perspective-correct u/w,v/w (IT)
//   RDZ_MASKED       1 = skip transparent texels (palette index 0)
//   RDZ_TRANSLUCENT  1 = blend the source over the destination via the colormap transparency LUT
//   RDZ_SHADE        RDZ_FLAT (no light) / RDZ_LIT (constant level) / RDZ_GOURAUD (per-pixel level)

static void RDZ_NAME(const rdZVertex* pVerts, int numVerts, const rdZRasterState* st)
{
    tVBuffer* pVBuffer = rdCamera_g_pCurCamera->pCanvas->pVBuffer;
    rdCanvas* pCanvas = rdCamera_g_pCurCamera->pCanvas;
    int fbW = pVBuffer->format.width;
    uint32_t stride = pVBuffer->format.rowSize;
    uint8_t* pBase = (uint8_t*)pVBuffer->surface_lock_alloc;

    if (fbW > rdZRaster_zbWidth || pVBuffer->format.height > rdZRaster_zbHeight)
        return;

    int yTop = pCanvas->yStart;
    int yBot = pCanvas->heightMinusOne;

#if !RDZ_SOLID
    const uint8_t* pTexels = st->pTexels;
    uint32_t uMask = (uint32_t)(st->mipW - 1);
    uint32_t vMask = (uint32_t)(st->mipH - 1);
    int mip = st->mip;
    int mipStride = st->mipStride;
#endif
#if RDZ_SHADE != RDZ_FLAT
    const uint8_t* pLightBase = st->pLightBase;
#endif
#if RDZ_TRANSLUCENT
    const uint8_t* pTransTable = st->pTransTable;
#endif

    flex_t fyMin = pVerts[0].sy, fyMax = pVerts[0].sy;
    for (int i = 1; i < numVerts; i++)
    {
        if (pVerts[i].sy < fyMin) fyMin = pVerts[i].sy;
        if (pVerts[i].sy > fyMax) fyMax = pVerts[i].sy;
    }
    int yMin = (int)ceilf((float)fyMin);
    int yMax = (int)floorf((float)fyMax);
    if (yMin < yTop) yMin = yTop;
    if (yMax > yBot) yMax = yBot;

    for (int y = yMin; y <= yMax; y++)
    {
        rdZVertex cross[2];
        int nCross = 0;
        flex_t yc = (flex_t)y;

        for (int i = 0; i < numVerts && nCross < 2; i++)
        {
            const rdZVertex* a = &pVerts[i];
            const rdZVertex* b = &pVerts[(i + 1 == numVerts) ? 0 : i + 1];
            const rdZVertex* top = (a->sy <= b->sy) ? a : b;
            const rdZVertex* bot = (a->sy <= b->sy) ? b : a;
            if (yc < top->sy || yc >= bot->sy)
                continue;
            flex_t t = (yc - top->sy) / (bot->sy - top->sy);
            rdZVertex* c = &cross[nCross++];
            c->sx        = top->sx        + (bot->sx        - top->sx)        * t;
            c->oneOverW  = top->oneOverW  + (bot->oneOverW  - top->oneOverW)  * t;
            c->uOverW    = top->uOverW    + (bot->uOverW    - top->uOverW)    * t;
            c->vOverW    = top->vOverW    + (bot->vOverW    - top->vOverW)    * t;
            c->u         = top->u         + (bot->u         - top->u)         * t;
            c->v         = top->v         + (bot->v         - top->v)         * t;
            c->intensity = top->intensity + (bot->intensity - top->intensity) * t;
        }
        if (nCross < 2)
            continue;

        const rdZVertex* pL = &cross[0];
        const rdZVertex* pR = &cross[1];
        if (pR->sx < pL->sx) { const rdZVertex* tmp = pL; pL = pR; pR = tmp; }

        int xL = (int)ceilf((float)pL->sx);
        int xR = (int)ceilf((float)pR->sx);
        if (xL < 0) xL = 0;
        if (xR > fbW) xR = fbW;
        if (xR <= xL)
            continue;

        flex_t span = pR->sx - pL->sx;
        flex_t inv = (span != 0.0f) ? (1.0f / span) : 0.0f;
        flex_t frac = ((flex_t)xL - pL->sx) * inv;
        flex_t oow  = pL->oneOverW + (pR->oneOverW - pL->oneOverW) * frac;
        flex_t doow = (pR->oneOverW - pL->oneOverW) * inv;
#if RDZ_SHADE == RDZ_GOURAUD
        flex_t inte = pL->intensity + (pR->intensity - pL->intensity) * frac;
        flex_t dint = (pR->intensity - pL->intensity) * inv;
#elif RDZ_SHADE == RDZ_LIT
        int litLvl = (int)pL->intensity;
        if (litLvl < 0) litLvl = 0; else if (litLvl > 63) litLvl = 63;
#endif
#if !RDZ_SOLID
#if RDZ_AFFINE
        flex_t uu = pL->u + (pR->u - pL->u) * frac;
        flex_t vv = pL->v + (pR->v - pL->v) * frac;
        flex_t duu = (pR->u - pL->u) * inv;
        flex_t dvv = (pR->v - pL->v) * inv;
#else
        flex_t uow = pL->uOverW + (pR->uOverW - pL->uOverW) * frac;
        flex_t vow = pL->vOverW + (pR->vOverW - pL->vOverW) * frac;
        flex_t duow = (pR->uOverW - pL->uOverW) * inv;
        flex_t dvow = (pR->vOverW - pL->vOverW) * inv;
#endif
#endif
        uint8_t* pRow = pBase + y * stride;
        float* pZRow = rdZRaster_pZBuffer + y * rdZRaster_zbWidth;

        for (int x = xL; x < xR; x++)
        {
            if (oow > pZRow[x])
            {
#if RDZ_SOLID
                uint8_t texel = (uint8_t)st->solidColor;
#elif RDZ_AFFINE
                int u = ((int)uu >> mip) & (int)uMask;
                int v = ((int)vv >> mip) & (int)vMask;
                uint8_t texel = pTexels[v * mipStride + u];
#else
                flex_t w = 1.0f / oow;
                int u = ((int)(uow * w) >> mip) & (int)uMask;
                int v = ((int)(vow * w) >> mip) & (int)vMask;
                uint8_t texel = pTexels[v * mipStride + u];
#endif
#if RDZ_MASKED
                if (texel != 0)
                {
#endif
#if RDZ_SHADE == RDZ_LIT
                    texel = pLightBase[litLvl * 256 + texel];
#elif RDZ_SHADE == RDZ_GOURAUD
                    {
                        int lvl = (int)inte;
                        if (lvl < 0) lvl = 0; else if (lvl > 63) lvl = 63;
                        texel = pLightBase[lvl * 256 + texel];
                    }
#endif
#if RDZ_TRANSLUCENT
                    texel = pTransTable[(int)texel * 256 + pRow[x]];
#endif
                    stdPlatform_WriteByte16(pRow + x, texel);
                    pZRow[x] = oow;
#if RDZ_MASKED
                }
#endif
            }
            oow += doow;
#if RDZ_SHADE == RDZ_GOURAUD
            inte += dint;
#endif
#if !RDZ_SOLID
#if RDZ_AFFINE
            uu += duu; vv += dvv;
#else
            uow += duow; vow += dvow;
#endif
#endif
        }
    }
}

#undef RDZ_NAME
#undef RDZ_SOLID
#undef RDZ_AFFINE
#undef RDZ_MASKED
#undef RDZ_TRANSLUCENT
#undef RDZ_SHADE
