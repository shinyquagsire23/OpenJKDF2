#include "jkGUI.h"

#include "General/Darray.h"
#include "General/stdBitmap.h"
#include "General/stdFont.h"
#include "Engine/rdMaterial.h" // TODO move stdVBuffer
#include "Primitives/rdVector.h"
#include "Win95/stdDisplay.h"
#include "Win95/stdControl.h"
#include "Win95/Window.h"
#include "Win95/stdGdi.h"
#include "General/stdString.h"
#include "stdPlatform.h"
#include "jk.h"
#include "Gui/jkGUIRend.h"

void jkGui_InitMenu(jkGuiMenu *menu, stdBitmap *bgBitmap)
{
    stdVBuffer **v3; // edx
    wchar_t *v4; // eax
    int v5; // eax
    wchar_t *v6; // eax
    int v7; // eax

    if ( bgBitmap )
    {
        v3 = bgBitmap->mipSurfaces;
        menu->palette = (char *)bgBitmap->palette;
        menu->texture = *v3;
    }
    
    jkGuiElement* iter = menu->clickables;
    while ( iter->type != 9 )
    {
        if ( iter->hintText )
        {
            v4 = jkStrings_GetText2((const char *)iter->hintText);
            if ( v4 )
                iter->hintText = (jkGuiStringEntry *)v4;
        }

        if ( !iter->type || iter->type == 2 || iter->type == 3 )
        {
            if ( iter->unistr )
            {
                v6 = jkStrings_GetText2((const char *)iter->unistr);
                if ( v6 )
                    iter->unistr = (jkGuiStringEntry *)v6;
            }
        }
        ++iter;
    }
}
