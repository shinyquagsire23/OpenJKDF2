#include "rdColormap.h"

#include "Engine/rdroid.h"
#include "Win95/std3D.h"

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

int rdColormap_Write(char *outpath, rdColormap *colormap)
{
    int fd;
    rdColormapHeader header;

    _memset(&header, 0, sizeof(header));
    _strncpy(&header.magic, "CMP ", 4);
    header.version = 30;
    rdVector_Copy3(&header.tint, &colormap->tint);
    header.flags = colormap->flags;

    fd = rdroid_pHS->fileOpen(outpath, "wb+");
    if (!fd)
        return 0;

    rdroid_pHS->fileWrite(fd, &header, sizeof(header));
    rdroid_pHS->fileWrite(fd, colormap->colors, sizeof(colormap->colors));
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
    rdroid_pHS->fileClose(fd);

    return 1;
}
