#include "stdDisplay.h"

#include "stdPlatform.h"
#include "jk.h"

#ifdef WIN32
#else
stdVBuffer* stdDisplay_VBufferNew(texture_format *a1, int create_ddraw_surface, int gpu_mem, int is_paletted)
{
    stdVBuffer* out = std_pHS->alloc(sizeof(stdVBuffer));
    
    _memset(out, 0, sizeof(*out));
    
    _memcpy(&out->format, a1, sizeof(out->format));
    
    // force 0 reads
    //out->format.width = 0;
    //out->format.width_in_bytes = 0;
    out->surface_lock_alloc = std_pHS->alloc(0x100000);
    
    return out;
}

int stdDisplay_VBufferLock(stdVBuffer *a1)
{
    return 1;
}

void stdDisplay_VBufferUnlock(stdVBuffer *a1)
{
}

int stdDisplay_VBufferSetColorKey(stdVBuffer *vbuf, int color)
{
    //DDCOLORKEY v3; // [esp+0h] [ebp-8h] BYREF

    if ( vbuf->surface_locked )
    {
        /*if ( vbuf->surface_locked == 1 )
        {
            v3.dwColorSpaceLowValue = color;
            v3.dwColorSpaceHighValue = color;
            vbuf->ddraw_surface->lpVtbl->SetColorKey(vbuf->ddraw_surface, 8, &v3);
            return 1;
        }*/
        vbuf->transparent_color = color;
    }
    else
    {
        vbuf->transparent_color = color;
    }
    return 1;
}
#endif
