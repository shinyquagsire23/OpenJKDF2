
#ifndef IDIRECT3DVIEWPORT_H
#define IDIRECT3DVIEWPORT_H

#include <QObject>
#include "dlls/kernel32.h"
#include "vm.h"
#include "dlls/winutils.h"
#include "main.h"
#include "dlls/ddraw/IDirect3D3.h"
#include "dlls/ddraw/IDirect3DExecuteBuffer.h"

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
        printf("STUB:: IDirect3DViewport::Initialize\n");

        return 0;
    }

    Q_INVOKABLE uint32_t GetViewport(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DViewport::GetViewport\n");

        return 0;
    }

    Q_INVOKABLE uint32_t SetViewport(void* this_ptr, struct D3DVIEWPORT* view)
    {
        printf("STUB:: IDirect3DViewport::SetViewport x %u, y %u, width %u, height %u, scaleX %f, scaleY %f, maxX %f, maxY %f, minZ %f, maxZ %f\n", view->dwX, view->dwY, view->dwWidth, view->dwHeight, view->dvScaleX, view->dvScaleY, view->dvMaxX, view->dvMaxY, view->dvMinZ, view->dvMaxZ);
        
        SDL_SetWindowSize(displayWindow, view->dwWidth, view->dwHeight);
        idirect3dexecutebuffer->view = *view;

        return 0;
    }

    Q_INVOKABLE uint32_t TransformVertices(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB:: IDirect3DViewport::TransformVertices\n");

        return 0;
    }

    Q_INVOKABLE uint32_t LightElements(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB:: IDirect3DViewport::LightElements\n");

        return 0;
    }

    Q_INVOKABLE uint32_t SetBackground(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DViewport::SetBackground\n");

        return 0;
    }

    Q_INVOKABLE uint32_t GetBackground(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB:: IDirect3DViewport::GetBackground\n");

        return 0;
    }

    Q_INVOKABLE uint32_t SetBackgroundDepth(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DViewport::SetBackgroundDepth\n");

        return 0;
    }

    Q_INVOKABLE uint32_t GetBackgroundDepth(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB:: IDirect3DViewport::GetBackgroundDepth\n");

        return 0;
    }

    Q_INVOKABLE uint32_t Clear(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB:: IDirect3DViewport::Clear\n");

        return 0;
    }

    Q_INVOKABLE uint32_t AddLight(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DViewport::AddLight\n");

        return 0;
    }

    Q_INVOKABLE uint32_t DeleteLight(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DViewport::DeleteLight\n");

        return 0;
    }

    Q_INVOKABLE uint32_t NextLight(void* this_ptr, uint32_t a, uint32_t b, uint32_t c)
    {
        printf("STUB:: IDirect3DViewport::NextLight\n");

        return 0;
    }

    Q_INVOKABLE uint32_t GetViewport2(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DViewport::GetViewport2\n");

        return 0;
    }

    Q_INVOKABLE uint32_t SetViewport2(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DViewport::SetViewport2\n");

        return 0;
    }

    Q_INVOKABLE uint32_t SetBackgroundDepth2(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DViewport::SetBackgroundDepth2\n");

        return 0;
    }

    Q_INVOKABLE uint32_t GetBackgroundDepth2(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB:: IDirect3DViewport::GetBackgroundDepth2\n");

        return 0;
    }

    Q_INVOKABLE uint32_t Clear2(void* this_ptr, uint32_t count, uint32_t lpRects, uint32_t flags, uint32_t color, uint32_t z, uint32_t stencil)
    {
        // Hacky but eh
        glClearColor(0.0, 0.0, 0.0, 1.0);
	    glClear(GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT);

        return 0;
    }


//    Q_INVOKABLE uint32_t ();
};

extern IDirect3DViewport* idirect3dviewport;

#endif // IDIRECT3DVIEWPORT_H
