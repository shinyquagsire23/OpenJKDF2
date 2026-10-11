#ifndef _DWGUISTATSPART_H
#define _DWGUISTATSPART_H

// dwGuiStatsPart / dwGuiPartImage — two small droid-PART display widgets that
// share one DroidWorks.exe compile unit (the tail of the dwPart unit).
//
// Decompiled from DroidWorks.exe:
//   dwGuiStatsPart (keyword STATS_PART; dwGuiStatsPart_vtbl;
//                  struct 0x50; derives dwWidget)
//   dwGuiPartImage (keyword PART_IMAGE; dwGuiPartImage_vtbl;
//                  struct 0x34; derives dwWidget)
// Verifiably C++ (vtables + ctor/dtor pairs + MSVC EH frames / ExceptionList
// around dwString locals) -> C++ classes.
//
// ⚠ NAME-SWAP FIX (Ghidra 2026-07-13): the two classes were previously
// mis-named; the CreateControl keywords prove which is which — STATS_PART is
// the part statistics info-card, PART_IMAGE is the 3D part preview widget.
//
// The dwPartNode / dwPart blueprint classes that ALSO live in this address
// window were translated in P5 (dwPart.cpp) — only the two GUI widgets are here.

#include "Dw/dwWidget.h"   // base class + dwWidgetMsg
#include "Dw/dwFont.h"     // dwFont*
#include "Dw/dwString.h"   // dwString (dwGuiPartImage::partName by value)

#ifndef __cplusplus

typedef struct dwGuiStatsPart dwGuiStatsPart; // C++ classes; opaque in the C view
typedef struct dwGuiPartImage dwGuiPartImage;

#else // __cplusplus

struct dwPart; // Dw/dwPart.h (blueprint; refd by pointer)
struct dwAnim; // Dw/dwAnim.h (dwGuiPartImage preview player)

// ---- dwGuiStatsPart --------------------------------------------------------
//
// A part STATISTICS info-card: shows the selected part's display name +
// description + materials list + MASS / MAGNETIC / DURABILITY. It caches the
// selected part on message 2000 and formats the value strings then.

struct dwGuiStatsPart : dwWidget
{
    dwPart* pPart;             // 0x10: currently-displayed part (cached on msg 2000)
    dwFont* pLabelFont;        // 0x14: label font
    uint8_t colorLabel;        // 0x18
    dwFont* pValueFont;        // 0x1c: value font
    uint8_t colorValue;        // 0x20
    char* pLabelMaterials;     // 0x24: "MATERIALS:" (localized; loaded, not drawn)
    char* pLabelMass;          // 0x28: "MASS:"
    char massValue[20];        // 0x2c: formatted mass (MASS_FMT)
    char* pLabelMagnetic;      // 0x40: "MAGNETIC:"
    char* pValueMagnetic;      // 0x44: NO / YES (localized)
    char* pLabelDurability;    // 0x48: "DURABILITY:"
    char* pValueDurability;    // 0x4c: NONE..HIGH (localized)

    // dwWidget(pRect); loads the two fonts; localizes the four labels.
    dwGuiStatsPart(dwRect* pRect, char* pLabelFontName, uint8_t colorLabel,
                   char* pValueFontName, uint8_t colorValue);
    // (dwGuiStatsPart_DtorDelete) — frees the two fonts.
    virtual ~dwGuiStatsPart();

    // dispatch hover-help {0x7531, 0x7919}; return 1.
    virtual int OnHover(int16_t x, int16_t y) override;
    // msg 2000: rebind pPart and format mass/magnetic/durability.
    virtual int OnMessage(dwWidgetMsg* pMsg) override;
    // draw the whole info-card.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect) override;
};

// ---- dwGuiPartImage --------------------------------------------------------
//
// A part PREVIEW widget: shows the selected part's model/icon image plus its
// name with a typewriter reveal, and (once the reveal completes) swaps in a
// dwAnim child that plays the part's SPIN flc as a spinning preview.

struct dwGuiPartImage : dwWidget
{
    dwPart* pPart;             // 0x10: currently-displayed part
    dwString partName;         // 0x14: revealed name text
    dwFont* pFont;             // 0x20: name font
    uint8_t color;             // 0x24
    dwAnim* pAnim;             // 0x28: spinning-preview child (NULL until revealed)
    float revealTimer;         // 0x2c: seconds since the part was selected
    uint8_t bHighlight;        // 0x30: hover/selection highlight

    // dwWidget(pRect); default partName; loads pFont.
    dwGuiPartImage(dwRect* pRect, char* pFontName, uint8_t color);
    // (dwGuiPartImage_DtorDelete) — FreeImages, delete pAnim, free font+name.
    virtual ~dwGuiPartImage();

    // advance the reveal timer; reveal the name char-by-char, then
    // spawn the spinning preview once the 0.5s window elapses.
    virtual void Update(float dt) override;
    // dispatch hover-help {0x7531, 0x7918}; return 1.
    virtual int OnHover(int16_t x, int16_t y) override;
    // 0x7e5/0x7e6 set/clear bHighlight; 2000 rebinds pPart.
    virtual int OnMessage(dwWidgetMsg* pMsg) override;
    // translate the rect and forward to the child anim.
    virtual void Move(int16_t dx, int16_t dy) override;
    // (Ghidra: dwGuiPartImage_Precache) — child anim EnsureImages.
    virtual void EnsureImages() override;
    // (Ghidra: dwGuiPartImage_FreeAnim) — child anim FreeImages.
    virtual void FreeImages() override;
    // draw the part image (or the child anim) + the name text.
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect) override;
};

#endif // __cplusplus

#endif // _DWGUISTATSPART_H
