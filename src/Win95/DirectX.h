#ifndef _WIN95_DIRECTX_H
#define _WIN95_DIRECTX_H

#include "types.h"

#define DirectX_DirectDrawEnumerateA_ADDR (0x0050D680)
#define DirectX_DirectDrawCreate_ADDR (0x0050D686)
#define DirectX_DirectSoundCreate_ADDR (0x0050D68C)
#define DirectX_DirectPlayLobbyCreateA_ADDR (0x0050D692)
#define DirectX_DirectInputCreateA_ADDR (0x0050E748)

HRESULT DirectX_DirectDrawEnumerateA(LPDDENUMCALLBACKA lpCallback, LPVOID lpContext);
HRESULT DirectX_DirectDrawCreate(GUID *lpGUID, LPDIRECTDRAW *lplpDD, IUnknown *pUnkOuter);
HRESULT DirectX_DirectSoundCreate(LPGUID a1, LPDIRECTSOUND *a2, LPUNKNOWN a3);
HRESULT DirectX_DirectPlayLobbyCreateA(LPGUID a1, LPDIRECTPLAYLOBBYA *a2, IUnknown *a3, LPVOID a4, DWORD a5);
HRESULT DirectX_DirectInputCreateA(HINSTANCE hinst, DWORD dwVersion, LPDIRECTINPUTA *ppDI, LPUNKNOWN punkOuter);

#endif // _WIN95_DIRECTX_H
