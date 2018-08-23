
#ifndef IDIRECT3DEXECUTEBUFFER_H
#define IDIRECT3DEXECUTEBUFFER_H

#include <QObject>
#include "dlls/kernel32.h"
#include "vm.h"
#include "dlls/winutils.h"

struct D3DEXECUTEBUFFERDESC
{
    uint32_t dwSize;
    uint32_t dwFlags;
    uint32_t dwCaps;
    uint32_t dwBufferSize;
    uint32_t lpData;
};

class IDirect3DExecuteBuffer : public QObject
{
Q_OBJECT

private:
    std::map<uint32_t, uint32_t> locked_objs;

public:

    Q_INVOKABLE IDirect3DExecuteBuffer() {}

    /*** Base ***/
    Q_INVOKABLE uint32_t QueryInterface(void* this_ptr, uint8_t* iid, uint32_t* lpInterface)
    {
        std::string iid_str = guid_to_string(iid);
        printf("STUB: IDirect3DExecuteBuffer::QueryInterface %s\n", iid_str.c_str());
        
        return GlobalQueryInterface(iid_str, lpInterface);
    }

    Q_INVOKABLE void AddRef(void* this_ptr)
    {
        printf("STUB: IDirect3DExecuteBuffer::AddRef\n");
    }

    Q_INVOKABLE void Release(void* this_ptr)
    {
        printf("STUB: IDirect3DExecuteBuffer::Release\n");
        
        GlobalRelease(this_ptr);
    }
    
    /* IDirect3DExecuteBuffer methods */
    Q_INVOKABLE uint32_t Initialize(void* this_ptr, uint32_t a, uint32_t b)
    {
        printf("STUB:: IDirect3DExecuteBuffer::Initialize\n");

        return 0;
    }

    Q_INVOKABLE uint32_t Lock(void* this_ptr, struct D3DEXECUTEBUFFERDESC* desc)
    {
        printf("STUB:: IDirect3DExecuteBuffer::Lock\n");
        
        if (locked_objs[real_ptr_to_vm_ptr(this_ptr)])
            desc->lpData = locked_objs[real_ptr_to_vm_ptr(this_ptr)];
        else
        {
            desc->lpData = kernel32->VirtualAlloc(0, 0x10000, 0, 0); //TODO
            locked_objs[real_ptr_to_vm_ptr(this_ptr)] = desc->lpData;
        }

        return 0;
    }

    Q_INVOKABLE uint32_t Unlock(void* this_ptr)
    {
        printf("STUB:: IDirect3DExecuteBuffer::Unlock\n");

        kernel32->VirtualFree(locked_objs[real_ptr_to_vm_ptr(this_ptr)], 0, 0); //TODO
        locked_objs[real_ptr_to_vm_ptr(this_ptr)] = 0;

        return 0;
    }

    Q_INVOKABLE uint32_t SetExecuteData(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DExecuteBuffer::SetExecuteData\n");

        return 0;
    }

    Q_INVOKABLE uint32_t GetExecuteData(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DExecuteBuffer::GetExecuteData\n");

        return 0;
    }

    Q_INVOKABLE uint32_t Validate(void* this_ptr, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
    {
        printf("STUB:: IDirect3DExecuteBuffer::Validate\n");

        return 0;
    }

    Q_INVOKABLE uint32_t Optimize(void* this_ptr, uint32_t a)
    {
        printf("STUB:: IDirect3DExecuteBuffer::Optimize\n");

        return 0;
    }


//    Q_INVOKABLE uint32_t ();
};

extern IDirect3DExecuteBuffer* idirect3dexecutebuffer;

#endif // IDIRECT3DEXECUTEBUFFER_H
