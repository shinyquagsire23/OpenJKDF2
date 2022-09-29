#include "rdColormap.h"

#include "Engine/rdroid.h"
#include "Platform/std3D.h"
#include "Win95/std.h"

static rdTexformat rdColormap_colorInfo = {1, 0x10, 5, 6, 5, 0x0B, 5, 0, 3, 2, 3, 0, 0, 0};

int rdColormap_SetCurrent(rdColormap *colormap)
{
    if (rdColormap_pCurMap != colormap)
        rdColormap_pCurMap = colormap;

    return rdColormap_SetIdentity(colormap);
}

int rdColormap_SetIdentity(rdColormap *colormap)
{
    if (!rdColormap_pIdentityMap && colormap)
    {
        rdColormap_pIdentityMap = colormap;
        if (rdroid_curAcceleration > 0)
            std3D_SetCurrentPalette(colormap->colors, 90);
    }
    return 1;
}

rdColormap* rdColormap_Load(char *colormap_fname)
{
    rdColormap *colormap;

    colormap = (rdColormap*)rdroid_pHS->alloc(sizeof(rdColormap));
 
    if (!colormap)
    {
        rdColormap_Free(colormap);
        return NULL;
    }

    *(int*)colormap->colormap_fname = 0;
    if (rdColormap_LoadEntry(colormap_fname, colormap))
      return colormap;
  
    return NULL;
}

// MOTS altered
int rdColormap_LoadEntry(char *colormap_fname, rdColormap *colormap)
{
    intptr_t colormap_fptr; // edi
    const char *v4; // eax
    int v6; // eax
    float v7; // edx
    float v8; // eax
    uint16_t *rgb16Alloc; // eax
    char *v10; // eax
    void *v11; // eax
    void *colorsLights; // eax
    char *transparencyAlloc; // eax
    rdColormapHeader header; // [esp+10h] [ebp-40h] BYREF

    colormap_fptr = rdroid_pHS->fileOpen(colormap_fname, "rb");
    if ( !colormap_fptr )
    {
        printf("failed to open colormap `%s`!\n", colormap_fname);
        return 0;
    }
    v4 = stdFileFromPath(colormap_fname);
    _strncpy(colormap->colormap_fname, v4, 0x1Fu);
    colormap->colormap_fname[31] = 0;
    rdroid_pHS->fileRead(colormap_fptr, &header, 0x40);
    v6 = header.flags;
    v7 = header.tint.y;
    colormap->tint.x = header.tint.x;
    colormap->flags = v6;
    v8 = header.tint.z;
    colormap->tint.y = v7;
    colormap->tint.z = v8;
    if ( _strncmp((const char *)&header.magic, "CMP ", 4u) )
    {
        jk_printf("CMP magic in `%s` is invalid!\n", colormap_fname);
        goto safe_fallback;
    }
    rdroid_pHS->fileRead(colormap_fptr, colormap->colors, 0x300);

    // JKDF2
    /*
    if ( (colormap->flags & 4) == 0 )
    {
        colorsLights = rdroid_pHS->alloc(0x4100);
        colormap->lightlevelAlloc = colorsLights;
        if (!colorsLights)
        {
            jk_printf("OpenJKDF2: colorsLights alloc in `%s` failed!\n", colormap_fname);
            goto safe_fallback;
        }

        colormap->lightlevel = colorsLights;
        if ( (intptr_t)colorsLights & 0xFF )
            colormap->lightlevel = (void*)((intptr_t)colorsLights - ((intptr_t)colorsLights & 0xFF) + 0x100);

        rdroid_pHS->fileRead(colormap_fptr, colormap->lightlevel, 0x4000);
        if ( (colormap->flags & 1) != 0 )
        {
            transparencyAlloc = rdroid_pHS->alloc(0x10100);
            colormap->transparencyAlloc = transparencyAlloc;
            if ( !transparencyAlloc )
            {
                jk_printf("OpenJKDF2: transparency alloc in `%s` failed!\n", colormap_fname);
                goto safe_fallback;
            }
            colormap->transparency = transparencyAlloc;
            if ( (intptr_t)transparencyAlloc & 0xFF )
                colormap->transparency = (void*)((intptr_t)transparencyAlloc - (((intptr_t)transparencyAlloc) & 0xFF) + 256);
            rdroid_pHS->fileRead(colormap_fptr, colormap->transparency, 0x10000);
        }
        colormap->rgb16Alloc = 0;
        colormap->dword34C = 0;
        goto LABEL_26;
    }
    rgb16Alloc = (uint16_t *)rdroid_pHS->alloc(0x8000);
    colormap->rgb16Alloc = rgb16Alloc;
    if ( !rgb16Alloc )
    {
        jk_printf("OpenJKDF2: rgb16Alloc alloc in `%s` failed!\n", colormap_fname);
        goto safe_fallback;
    }
    rdColormap_BuildRGB16(rgb16Alloc, colormap->colors, 0, 0, 0, &rdColormap_colorInfo);
    if ( (colormap->flags & 1) != 0 )
    {
        v10 = rdroid_pHS->alloc(0x10100);
        colormap->transparencyAlloc = v10;
        if (!v10)
        {
            jk_printf("OpenJKDF2: transparencyAlloc alloc in `%s` failed!\n", colormap_fname);
            goto safe_fallback;
        }
        
        colormap->transparency = v10;
        if ( ((intptr_t)v10) & 0xFF )
            colormap->transparency = (void*)((intptr_t)v10 - (((intptr_t)v10) & 0xFF) + 256);
        rdroid_pHS->fileRead(colormap_fptr, colormap->transparency, 0x10000);
        v11 = rdroid_pHS->alloc(0x10000);
        colormap->dword34C = v11;
        if ( v11 )
        {
            if ( rdColormap_colorInfo.g_bits == 5 )
                rdroid_pHS->fseek(colormap_fptr, 0x10000, 1);
            rdroid_pHS->fileRead(colormap_fptr, colormap->dword34C, 0x10000);
            goto LABEL_15;
        }
    }
LABEL_15:
    colormap->lightlevel = 0;
    colormap->lightlevelAlloc = 0;
    colormap->dword340 = 0;
    colormap->dword344 = 0;
LABEL_26:
    rdroid_pHS->fileClose(colormap_fptr);
    return 1;
    */

    if (!(colormap->flags & 4)) {
        colormap->rgb16Alloc = NULL;
    }
    else {
        rgb16Alloc = (uint16_t *)rdroid_pHS->alloc(0x8000);
        colormap->rgb16Alloc = rgb16Alloc;
        if ( !rgb16Alloc )
        {
            jk_printf("OpenJKDF2: rgb16Alloc alloc in `%s` failed!\n", colormap_fname);
            goto safe_fallback;
        }
        rdColormap_BuildRGB16(rgb16Alloc, colormap->colors, 0, 0, 0, &rdColormap_colorInfo);
    }

    colorsLights = rdroid_pHS->alloc(0x4100);
    colormap->lightlevelAlloc = colorsLights;
    if (!colorsLights)
    {
        jk_printf("OpenJKDF2: colorsLights alloc in `%s` failed!\n", colormap_fname);
        goto safe_fallback;
    }


    colormap->lightlevel = colorsLights;
    if ( (intptr_t)colorsLights & 0xFF )
        colormap->lightlevel = (void*)((intptr_t)colorsLights - ((intptr_t)colorsLights & 0xFF) + 0x100);

    rdroid_pHS->fileRead(colormap_fptr, colormap->lightlevel, 0x4000);

    if (colormap->flags & 1) 
    {
        v10 = rdroid_pHS->alloc(0x10100);
        colormap->transparencyAlloc = v10;
        if (!v10)
        {
            jk_printf("OpenJKDF2: transparencyAlloc alloc in `%s` failed!\n", colormap_fname);
            goto safe_fallback;
        }
        
        colormap->transparency = v10;
        if ( ((intptr_t)v10) & 0xFF )
            colormap->transparency = (void*)((intptr_t)v10 - (((intptr_t)v10) & 0xFF) + 256);
        rdroid_pHS->fileRead(colormap_fptr, colormap->transparency, 0x10000);

        if ((colormap->flags & 4) == 0) {
            colormap->dword34C = NULL;
        }
        else {
            v11 = (*rdroid_pHS->alloc)(0x10000);
            colormap->dword34C = v11;
            if (v11 == NULL) goto safe_fallback;

            if (rdColormap_colorInfo.g_bits == 5) {
                rdroid_pHS->fseek(colormap_fptr,0x10000,1);
                rdroid_pHS->fileRead(colormap_fptr,colormap->dword34C,0x10000);
            }
            else {
                rdroid_pHS->fileRead(colormap_fptr,v11,0x10000);
                rdroid_pHS->fseek(colormap_fptr,0x10000,1);
            }
        }
        colormap->dword340 = 0;
        colormap->dword344 = 0;
    }
    rdroid_pHS->fileClose(colormap_fptr);
    return 1;

    // Generate a gray ramp if something fails
safe_fallback:    
    rdroid_pHS->fileClose(colormap_fptr);
    rdColormap_BuildGrayRamp(colormap);
    return 1;
}

void rdColormap_Free(rdColormap *colormap)
{
    rdColormap_FreeEntry(colormap);
    rdroid_pHS->free(colormap);
}

void rdColormap_FreeEntry(rdColormap *colormap)
{
    if (colormap->lightlevelAlloc)
    {
        rdroid_pHS->free(colormap->lightlevelAlloc);
        colormap->lightlevelAlloc = 0;
    }
    if (colormap->rgb16Alloc)
    {
        rdroid_pHS->free(colormap->rgb16Alloc);
        colormap->rgb16Alloc = 0;
    }
    if (colormap->flags & 1)
    {
        if (colormap->transparencyAlloc)
        {
            rdroid_pHS->free(colormap->transparencyAlloc);
            colormap->transparencyAlloc = 0;
        }
        if (colormap->dword34C)
        {
            rdroid_pHS->free(colormap->dword34C);
            colormap->dword34C = 0;
        }
    }
}

// MOTS altered
int rdColormap_Write(char *outpath, rdColormap *colormap)
{
    int fd;
    rdColormapHeader header;

    _memset(&header, 0, sizeof(header));
    _strncpy((char*)&header.magic, "CMP ", 4);
    header.version = 30;
    rdVector_Copy3(&header.tint, &colormap->tint);
    header.flags = colormap->flags;

    fd = rdroid_pHS->fileOpen(outpath, "wb+");
    if (!fd)
        return 0;

    rdroid_pHS->fileWrite(fd, &header, sizeof(header));
    rdroid_pHS->fileWrite(fd, colormap->colors, sizeof(colormap->colors));

    // JKDF2
    /*
    if ( colormap->flags & 4 )
    {
      if ( colormap->flags & 1 )
      {
        rdroid_pHS->fileWrite(fd, colormap->transparency, 0x10000);
        rdroid_pHS->fileWrite(fd, colormap->dword34C, 0x20000);
      }
    }
    else
    {
      rdroid_pHS->fileWrite(fd, colormap->lightlevel, 0x4000);
      if ( colormap->flags & 1 )
        rdroid_pHS->fileWrite(fd, colormap->transparency, 0x10000);
    }
    */

    // MOTS
    rdroid_pHS->fileWrite(fd, colormap->lightlevel, 0x4000);
    if ( colormap->flags & 1 ) {
        rdroid_pHS->fileWrite(fd, colormap->transparency, 0x10000);
        if ( colormap->flags & 4 ) {
            rdroid_pHS->fileWrite(fd, colormap->dword34C, 0x20000);
        }
    }


    rdroid_pHS->fileClose(fd);

    return 1;
}

int rdColormap_BuildRGB16(uint16_t *paColors16, rdColor24 *paColors24, uint8_t a4, uint8_t a5, uint8_t a6, rdTexformat *format)
{
    return 1;
}
