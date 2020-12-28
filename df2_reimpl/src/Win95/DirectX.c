#include "DirectX.h"

#include "jk.h"
#include "types.h"

HRESULT DirectX_DirectDrawEnumerateA(LPDDENUMCALLBACKA lpCallback, LPVOID lpContext)
{
    return jk_DirectDrawEnumerateA(lpCallback, lpContext);
}

HRESULT DirectX_DirectDrawCreate(GUID *lpGUID, LPDIRECTDRAW *lplpDD, IUnknown *pUnkOuter)
{
    return jk_DirectDrawCreate(lpGUID, lplpDD, pUnkOuter);
}

HRESULT DirectX_DirectSoundCreate(LPGUID a1, LPDIRECTSOUND *a2, LPUNKNOWN a3)
{
    return jk_DirectSoundCreate(a1, a2, a3);
}

HRESULT DirectX_DirectPlayLobbyCreateA(LPGUID a1, LPDIRECTPLAYLOBBYA *a2, IUnknown *a3, LPVOID a4, DWORD a5)
{
    return jk_DirectPlayLobbyCreateA(a1, a2, a3, a4, a5);
}

HRESULT DirectX_DirectInputCreateA(HINSTANCE hinst, DWORD dwVersion, LPDIRECTINPUTA *ppDI, LPUNKNOWN punkOuter)
{
    return jk_DirectInputCreateA(hinst, dwVersion, ppDI, punkOuter);
}
