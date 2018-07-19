
#ifndef IDIRECTDRAWSURFACE3_H
#define IDIRECTDRAWSURFACE3_H

#include <QObject>
#include "dlls/kernel32.h"
#include "vm.h"
#include "dlls/winutils.h"

class IDirectDrawSurface3 : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE IDirectDrawSurface3() {}

    /*** Base ***/
    Q_INVOKABLE uint32_t QueryInterface(void* this_ptr, uint8_t* iid, uint32_t* lpInterface)
    {
        std::string iid_str = guid_to_string(iid);
        printf("STUB: IDirectDrawSurface3::QueryInterface %s\n", iid_str.c_str());
        
        return 1;
    }

    Q_INVOKABLE void AddRef(void* this_ptr)
    {
        printf("STUB: IDirectDrawSurface3::AddRef\n");
    }

    Q_INVOKABLE void Release(void* this_ptr)
    {
        printf("STUB: IDirectDrawSurface3::Release\n");
    }
    
    /*** IDirectDrawSurface methods ***/
    Q_INVOKABLE void AddAttachedSurface(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::AddAttachedSurface\n");
    }

    Q_INVOKABLE void AddOverlayDirtyRect(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::AddOverlayDirtyRect\n");
    }

    Q_INVOKABLE void Blt(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
    {
        printf("STUB: IDirectDrawSurface3::Blt\n");
    }

    Q_INVOKABLE void BltBatch(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB: IDirectDrawSurface3::BltBatch\n");
    }

    Q_INVOKABLE void BltFast(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
    {
        printf("STUB: IDirectDrawSurface3::BltFast\n");
    }

    Q_INVOKABLE void DeleteAttachedSurface(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::DeleteAttachedSurface\n");
    }

    Q_INVOKABLE void EnumAttachedSurfaces(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::EnumAttachedSurfaces\n");
    }

    Q_INVOKABLE void EnumOverlayZOrders(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB: IDirectDrawSurface3::EnumOverlayZOrders\n");
    }

    Q_INVOKABLE void Flip(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::Flip\n");
    }

    Q_INVOKABLE void GetAttachedSurface(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::GetAttachedSurface\n");
    }

    Q_INVOKABLE void GetBltStatus(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetBltStatus\n");
    }

    Q_INVOKABLE void GetCaps(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetCaps\n");
    }

    Q_INVOKABLE void GetClipper(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetClipper\n");
    }

    Q_INVOKABLE void GetColorKey(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::GetColorKey\n");
    }

    Q_INVOKABLE void GetDC(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetDC\n");
    }

    Q_INVOKABLE void GetFlipStatus(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetFlipStatus\n");
    }

    Q_INVOKABLE void GetOverlayPosition(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::GetOverlayPosition\n");
    }

    Q_INVOKABLE void GetPalette(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetPalette\n");
    }

    Q_INVOKABLE void GetPixelFormat(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetPixelFormat\n");
    }

    Q_INVOKABLE uint32_t GetSurfaceDesc(void* this_ptr, uint32_t* a)
    {
        printf("STUB: IDirectDrawSurface3::GetSurfaceDesc\n");
        
        *a = 0x123456;
        
        return 0;
    }

    Q_INVOKABLE void Initialize(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::Initialize\n");
    }

    Q_INVOKABLE void IsLost(void* this_ptr)
    {
        printf("STUB: IDirectDrawSurface3::IsLost\n");
    }

    Q_INVOKABLE void Lock(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB: IDirectDrawSurface3::lock\n");
    }

    Q_INVOKABLE void ReleaseDC(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::ReleaseDC\n");
    }

    Q_INVOKABLE void Restore(void* this_ptr)
    {
        printf("STUB: IDirectDrawSurface3::Restore\n");
    }

    Q_INVOKABLE void SetClipper(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::SetClipper\n");
    }

    Q_INVOKABLE void SetColorKey(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::SetColorKey\n");
    }

    Q_INVOKABLE void SetOverlayPosition(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::SetOverlayPosition\n");
    }

    Q_INVOKABLE uint32_t SetPalette(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::SetPalette\n");
        
        return 0;
    }

    Q_INVOKABLE void Unlock(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::Unlock\n");
    }

    Q_INVOKABLE void UpdateOverlay(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
    {
        printf("STUB: IDirectDrawSurface3::UpdateOverlay\n");
    }

    Q_INVOKABLE void UpdateOverlayDisplay(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::UpdateOverlayDisplay\n");
    }

    Q_INVOKABLE void UpdateOverlayZOrder(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::UpdateOverlayZOrder\n");
    }


    /*** IDirectDrawSurface2 methods ***/
    Q_INVOKABLE void GetDDInterface(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::GetDDInterface\n");
    }

    Q_INVOKABLE void PageLock(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::PageLock\n");
    }

    Q_INVOKABLE void PageUnlock(void* this_ptr, uint32_t a)
    {
        printf("STUB: IDirectDrawSurface3::PageUnlock\n");
    }


    /*** IDirectDrawSurface3 methods ***/
    Q_INVOKABLE void SetSurfaceDesc(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB: IDirectDrawSurface3::SetSurfaceDesc\n");
    }


//    Q_INVOKABLE uint32_t ();
};

extern IDirectDrawSurface3* idirectdrawsurface3;

#endif // IDIRECTDRAWSURFACE3_H
