
#ifndef IDIRECT3DDEVICE_H
#define IDIRECT3DDEVICE_H

#include <QObject>
#include "dlls/kernel32.h"
#include "vm.h"
#include "main.h"
#include "dlls/winutils.h"
#include "dlls/ddraw/IDirectDraw4.h"
#include "dlls/ddraw/IDirect3DExecuteBuffer.h"

#include "3rdparty/imgui/imgui.h"
#include "3rdparty/imgui/imgui_impl_sdl.h"
#include "3rdparty/imgui/imgui_impl_opengl3.h"
#include "renderer.h"

class IDirect3DDevice : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE IDirect3DDevice() {}

    /*** Base ***/
    Q_INVOKABLE uint32_t QueryInterface(void* this_ptr, uint8_t* iid, uint32_t* lpInterface)
    {
        std::string iid_str = guid_to_string(iid);
        printf("STUB: IDirect3DDevice::QueryInterface %s\n", iid_str.c_str());
        
        return GlobalQueryInterface(iid_str, lpInterface);
    }

    Q_INVOKABLE void AddRef(void* this_ptr)
    {
        printf("STUB: IDirect3DDevice::AddRef\n");
    }

    Q_INVOKABLE void Release(void* this_ptr)
    {
        printf("STUB: IDirect3DDevice::Release\n");
        
        idirect3dexecutebuffer->free_resources();
        
        GlobalRelease(this_ptr);
    }
    
    /* IDirect3DDevice methods */
    Q_INVOKABLE uint32_t Initialize(void* this_ptr, uint32_t a, uint32_t b, uint32_t c);
    Q_INVOKABLE uint32_t GetCaps(void* this_ptr, uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t SwapTextureHandles(void* this_ptr, uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t CreateExecuteBuffer(void* this_ptr, struct D3DEXECUTEBUFFERDESC* desc, uint32_t* lpDirect3DExecuteBuffer, uint32_t pUnkOuter);
    Q_INVOKABLE uint32_t GetStats(void* this_ptr, uint32_t a);
    Q_INVOKABLE uint32_t Execute(void* this_ptr, uint32_t a, uint32_t b, uint32_t c);
    Q_INVOKABLE uint32_t AddViewport(void* this_ptr, uint32_t a);
    Q_INVOKABLE uint32_t DeleteViewport(void* this_ptr, uint32_t a);
    Q_INVOKABLE uint32_t NextViewport(void* this_ptr, uint32_t a, uint32_t b, uint32_t c);
    Q_INVOKABLE uint32_t Pick(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d);
    Q_INVOKABLE uint32_t GetPickRecords(void* this_ptr, uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t EnumTextureFormats(void* this_ptr, uint32_t callback, uint32_t pUnkOuter);
    Q_INVOKABLE uint32_t CreateMatrix(void* this_ptr, uint32_t a);
    Q_INVOKABLE uint32_t SetMatrix(void* this_ptr, uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t GetMatrix(void* this_ptr, uint32_t a, uint32_t b);
    Q_INVOKABLE uint32_t DeleteMatrix(void* this_ptr, uint32_t a);
    Q_INVOKABLE uint32_t BeginScene(void* this_ptr);
    Q_INVOKABLE uint32_t EndScene(void* this_ptr);
    Q_INVOKABLE uint32_t GetDirect3D(void* this_ptr, uint32_t a);


//    Q_INVOKABLE uint32_t ();
};

extern IDirect3DDevice* idirect3ddevice;

#endif // IDIRECT3DDEVICE_H
