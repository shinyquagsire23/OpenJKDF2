
#ifndef IDIRECT3DVIEWPORT_H
#define IDIRECT3DVIEWPORT_H

#include <QObject>
#include "dlls/kernel32.h"
#include "vm.h"
#include "dlls/winutils.h"

class IDirect3DViewport : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE IDirect3DViewport() {}

    /*** Base ***/
    Q_INVOKABLE uint32_t QueryInterface(void* this_ptr, uint8_t* iid, uint32_t* lpInterface)
    {
        std::string iid_str = guid_to_string(iid);
        printf("STUB: IDirect3DViewport::QueryInterface %s\n", iid_str.c_str());
        
        return GlobalQueryInterface(iid_str, lpInterface);
    }

    Q_INVOKABLE void AddRef(void* this_ptr)
    {
        printf("STUB: IDirect3DViewport::AddRef\n");
    }

    Q_INVOKABLE void Release(void* this_ptr)
    {
        printf("STUB: IDirect3DViewport::Release\n");
        
        GlobalRelease(this_ptr);
    }
    
    /* IDirect3DViewport methods */
    Q_INVOKABLE uint32_t Initialize(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DDevice::Initialize\n");

        return 0;
    }

    Q_INVOKABLE uint32_t GetViewport(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DDevice::GetViewport\n");

        return 0;
    }

    Q_INVOKABLE uint32_t SetViewport(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DDevice::SetViewport\n");

        return 0;
    }

    Q_INVOKABLE uint32_t TransformVertices(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB:: IDirect3DDevice::TransformVertices\n");

        return 0;
    }

    Q_INVOKABLE uint32_t LightElements(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB:: IDirect3DDevice::LightElements\n");

        return 0;
    }

    Q_INVOKABLE uint32_t SetBackground(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DDevice::SetBackground\n");

        return 0;
    }

    Q_INVOKABLE uint32_t GetBackground(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB:: IDirect3DDevice::GetBackground\n");

        return 0;
    }

    Q_INVOKABLE uint32_t SetBackgroundDepth(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DDevice::SetBackgroundDepth\n");

        return 0;
    }

    Q_INVOKABLE uint32_t GetBackgroundDepth(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB:: IDirect3DDevice::GetBackgroundDepth\n");

        return 0;
    }

    Q_INVOKABLE uint32_t Clear(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB:: IDirect3DDevice::Clear\n");

        return 0;
    }

    Q_INVOKABLE uint32_t AddLight(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DDevice::AddLight\n");

        return 0;
    }

    Q_INVOKABLE uint32_t DeleteLight(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DDevice::DeleteLight\n");

        return 0;
    }

    Q_INVOKABLE uint32_t NextLight(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB:: IDirect3DDevice::NextLight\n");

        return 0;
    }

    Q_INVOKABLE uint32_t GetViewport2(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DDevice::GetViewport2\n");

        return 0;
    }

    Q_INVOKABLE uint32_t SetViewport2(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DDevice::SetViewport2\n");

        return 0;
    }

    Q_INVOKABLE uint32_t SetBackgroundDepth2(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DDevice::SetBackgroundDepth2\n");

        return 0;
    }

    Q_INVOKABLE uint32_t GetBackgroundDepth2(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB:: IDirect3DDevice::GetBackgroundDepth2\n");

        return 0;
    }

    Q_INVOKABLE uint32_t Clear2(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f)
    {
        printf("STUB:: IDirect3DDevice::Clear2\n");

        return 0;
    }


//    Q_INVOKABLE uint32_t ();
};

extern IDirect3DViewport* idirect3dviewport;

#endif // IDIRECT3DVIEWPORT_H
