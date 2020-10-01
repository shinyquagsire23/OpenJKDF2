
#ifndef IDIRECTDRAWPALETTE_H
#define IDIRECTDRAWPALETTE_H

#include <QObject>
#include "vm.h"
#include "dlls/winutils.h"
#include "dlls/ddraw/IDirectDraw4.h"
#include "dlls/gdi32.h"

#include "main.h"

class IDirectDrawPalette : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE IDirectDrawPalette() {}

    /*** Base ***/
    Q_INVOKABLE uint32_t QueryInterface(void* this_ptr, uint8_t* iid, uint32_t* lpInterface)
    {
        std::string iid_str = guid_to_string(iid);
        printf("STUB: IDirectDrawPalette::QueryInterface %s\n", iid_str.c_str());

        return GlobalQueryInterface(iid_str, lpInterface);
    }

    Q_INVOKABLE void AddRef(void* this_ptr)
    {
        printf("STUB: IDirectDrawPalette::AddRef\n");
    }

    Q_INVOKABLE void Release(void* this_ptr)
    {
        printf("STUB: IDirectDrawPalette::Release %x %x\n", real_ptr_to_vm_ptr(this_ptr), *(uint32_t*)this_ptr);
        
        GlobalRelease(this_ptr);
    }
    
    /*** IDirectDrawPalette methods ***/
    
    Q_INVOKABLE uint32_t GetCaps(void* this_ptr, uint32_t* lpdwCaps)
    {
        printf("STUB: IDirectDrawPalette::GetCaps\n");

        return 0;
    }

    Q_INVOKABLE uint32_t GetEntries(void* this_ptr, uint32_t dwFlags, uint32_t dwBase, uint32_t dwNumEntries, uint32_t* lpEntries)
    {
        printf("STUB: IDirectDrawPalette::GetEntries\n");

        return 0;
    }

    Q_INVOKABLE uint32_t Initialize(void* this_ptr, uint32_t ddraw, uint32_t flags, uint32_t *color_table)
    {
        printf("STUB: IDirectDrawPalette::Initialize\n");

        return 0;
    }

    Q_INVOKABLE uint32_t SetEntries(void* this_ptr, uint32_t dwFlags, uint32_t dwStartingEntry, uint32_t dwCount, struct ddraw_color* lpEntries)
    {
        printf("STUB: IDirectDrawPalette::SetEntries flags %x start %x cnt %x %08x\n", dwFlags, dwStartingEntry, dwCount, real_ptr_to_vm_ptr(this_ptr));
        
        uint32_t key = *(uint32_t*)this_ptr;
        
        for(uint32_t i = 0; i < dwCount; i++)
        {
            if (i+dwStartingEntry == 0xFE)
                printf("%x: %08x %08x->%p\n", i+dwStartingEntry, *(uint32_t*)&lpEntries[i], key, idirectdraw4->palettes[key]); 
            idirectdraw4->palettes[key][i+dwStartingEntry].r = lpEntries[i].r;
            idirectdraw4->palettes[key][i+dwStartingEntry].g = lpEntries[i].g;
            idirectdraw4->palettes[key][i+dwStartingEntry].b = lpEntries[i].b;
            idirectdraw4->palettes[key][i+dwStartingEntry].a = 0xFF;
        }

        return 0;
    }


//    Q_INVOKABLE uint32_t ();
};

extern IDirectDrawPalette* idirectdrawpalette;

#endif // IDIRECTDRAWPALETTE_H
