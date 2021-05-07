#include "stdFont.h"

#include "stdPlatform.h"
#include "General/stdBitmap.h"

stdFont* stdFont_Load(char *fpath, int a2, int a3)
{
    stdFont *result; // eax
    stdFont *fd; // ebx
    int16_t charLast; // bp
    unsigned int totalAlloc; // esi
    stdFont *fontAlloc; // edx
    stdFont *fontAlloc_; // ebp
    const char *fname; // eax
    stdFontEntry *pEntries; // edx
    int charMin; // ecx
    uint16_t charMax; // ax
    int16_t charLast_1; // bx
    stdFontCharset *lastCharset; // esi
    stdFontCharset *i; // ecx
    int v16; // edi
    stdFontCharset *charset; // eax
    size_t entries_readsize; // esi
    stdBitmap *bitmap; // eax
    stdFontCharset *v20; // esi
    stdFontCharset *v21; // edi
    struct common_functions *v22; // ecx
    int marginY; // [esp+14h] [ebp-40h]
    int marginX; // [esp+18h] [ebp-3Ch]
    int16_t header_field_10; // [esp+1Ch] [ebp-38h]
    int16_t charFirst; // [esp+20h] [ebp-34h]
    int16_t charFirsta; // [esp+20h] [ebp-34h]
    stdFontExtHeader extHeader; // [esp+24h] [ebp-30h] BYREF
    stdFontHeader header; // [esp+2Ch] [ebp-28h] BYREF
    int fpatha; // [esp+58h] [ebp+4h]

    fd = std_pHS->fileOpen(fpath, "rb");

    if (!fd)
        return NULL;

    if ( std_pHS->fileRead(fd, &header, 0x28) != 40 )
        goto LABEL_28;
    if ( _memcmp(&header, "SFNT", 4u) )
        return 0;
    if ( header.version != 10 )
        return 0;
    if ( std_pHS->fileRead((int)fd, &extHeader, 4) != 4 )
        goto LABEL_28;
    charLast = extHeader.characterLast;
    charFirst = extHeader.characterFirst;
    header_field_10 = header.field_10;
    marginX = header.marginX;
    totalAlloc = 8 * (extHeader.characterLast - extHeader.characterFirst) + 0x44;
    marginY = header.marginY;
    fontAlloc = (stdFont *)std_pHS->alloc(totalAlloc);
    if ( fontAlloc )
    {
        _memset(fontAlloc, 0, totalAlloc);
        fontAlloc->charsetHead.pEntries = &fontAlloc->charsetHead.entries;
        fontAlloc->marginY = marginY;
        fontAlloc->marginX = marginX;
        fontAlloc->charsetHead.charLast = charLast;
        fontAlloc->field_28 = header_field_10;
        fontAlloc->charsetHead.charFirst = charFirst;
        fontAlloc_ = fontAlloc;
    }
    else
    {
        fontAlloc_ = 0;
    }
    fname = stdFileFromPath(fpath);
    _strncpy(fontAlloc_->name, fname, 0x1Fu);
    pEntries = fontAlloc_->charsetHead.pEntries;
    charMin = (uint16_t)fontAlloc_->charsetHead.charFirst;
    charMax = fontAlloc_->charsetHead.charLast;
    fontAlloc_->name[31] = 0;
    if ( std_pHS->fileRead((int)fd, pEntries, 8 * (charMax - charMin + 1)) != 8 * (charMax - charMin + 1) )
        goto LABEL_28;
    fpatha = 1;
    if ( header.numCharsets > 1 )
    {
        while ( std_pHS->fileRead((int)fd, &extHeader, 4) == 4 )
        {
            charLast_1 = extHeader.characterLast;
            charFirsta = extHeader.characterFirst;
            lastCharset = &fontAlloc_->charsetHead;
            for ( i = fontAlloc_->charsetHead.previous; i; i = i->previous )
                lastCharset = i;
            v16 = 8 * (extHeader.characterLast - extHeader.characterFirst + 1) + 0xC;
            charset = (stdFontCharset *)std_pHS->alloc(v16);
            if ( charset )
            {
                lastCharset->previous = charset;
                _memset(charset, 0, v16);
                charset->pEntries = &charset->entries;
                charset->charFirst = charFirsta;
                charset->charLast = charLast_1;
            }
            if ( !charset )
            {
                std_pHS->fileClose(fd);
                return 0;
            }
            entries_readsize = 8 * ((uint16_t)charset->charLast - (uint16_t)charset->charFirst + 1);
            if ( std_pHS->fileRead(fd, charset->pEntries, entries_readsize) != entries_readsize )
            {
                break;
            }
            if ( ++fpatha >= header.numCharsets )
                goto LABEL_21;
        }
LABEL_28:
        std_pHS->fileClose((int)fd);
        return 0;
    }
LABEL_21:
    bitmap = stdBitmap_LoadFromFile((int)fd, a2, a3);
    fontAlloc_->bitmap = bitmap;
    if ( bitmap )
    {
        _strncpy((char *)bitmap, "FONTSTRIP", 0x1Fu);
        v22 = std_pHS;
        fontAlloc_->bitmap->field_1F = 0;
        v22->fileClose((int)fd);
        result = fontAlloc_;
    }
    else
    {
        v20 = fontAlloc_->charsetHead.previous;
        std_pHS->free(fontAlloc_);
        if ( v20 )
        {
            do
            {
                v21 = v20->previous;
                std_pHS->free(v20);
                v20 = v21;
            }
            while ( v21 );
        }
        result = 0;
    }
    return result;
}
