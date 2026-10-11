#ifndef _DWREF_H
#define _DWREF_H

// dwRef — the DroidWorks reference-room CONTENT controls (built by
// dwGuiReference_CreateControl's GRAPH / PULLDOWN_MENU keywords):
//
//   dwRefGraph    (dwWidgetGroup subclass, dwRefGraph_vtbl, struct 0x50) —
//                 the material-properties comparison CHART control (keyword
//                 "GRAPH"). Plots droid-part topics in a 3-column chart:
//                 dwGuiHypText topic-name labels (LayoutLabels, Arial10) +
//                 colored arrow markers (LayoutMarkers: ROrange/RGreen/
//                 RBlueArrow.RLE dwGuiPicture children). Data comes from the
//                 TPC/SUB topic conf files (LoadTopics -> ParseTopicFile reads
//                 TOPIC_NAME/DENSITY/STRENGTH; FREQUENCY>0 gate ->
//                 AddDataPoint). Update eases a cur->target rect and plays a
//                 dwSound tick while animating; OnMessage codes 0x1b62/0x1b63
//                 flip the view mode.
//
//   dwRefPulldown (dwWidget subclass, dwRefPulldown_vtbl, struct 0x104) — the
//                 scrollable pull-down MENU control (keyword "PULLDOWN_MENU").
//                 Collapsed it shows one selected label; a click expands a
//                 scrollable list of dwRefMenuItem entries; an item that owns
//                 a submenu spawns a nested dwRefPulldown (BuildSubmenu). The
//                 items are built from the TPC/SUB topic files matching a
//                 TOPIC_CATEGORY, sorted by category (dwString_CompareI).
//
//   dwRefMenuItem (plain record, struct 0x30) — one pull-down entry:
//                 { dwString label; dwString sortKey; dwString topic;
//                   int value; u8 flag; dwRefPulldown* pSubmenu }.
//
// Decompiled from DroidWorks.exe (the shared
// dwRect_Set COMDAT lives here but is declared in Dw/dwRect.h). The
// genuine dwHelp unit starts at dwHelp_Ctor (a different agent owns it) — this file
// does NOT translate past dwRefPulldown_FreeImages.
//
// Everything is verifiably C++ (vtables, ctor/dtor pairs, MSVC EH frames).

#include "Dw/dwTypes.h"
#include "Dw/dwRect.h"

#ifdef __cplusplus
struct dwRefGraph;
struct dwRefPulldown;
struct dwRefMenuItem;
struct dwConfFile;   // Dw/dwConfFile.h (plain-C)
extern "C" {
#else
typedef struct dwRefGraph dwRefGraph;
typedef struct dwRefPulldown dwRefPulldown;
typedef struct dwRefMenuItem dwRefMenuItem;
typedef struct dwConfFile dwConfFile;
#endif

// No binary counterpart; kept for the project-wide soft-reset convention (the
// unit owns no module statics).
void dwRef_Startup(void);

#ifdef __cplusplus
} // extern "C"

#include "Dw/dwWidget.h"
#include "Dw/dwWidgetGroup.h"
#include "Dw/dwString.h"
#include "Dw/dwList.h"
#include "Dw/dwFont.h"

struct dwConfFile; // Dw/dwConfFile.h (plain-C struct)

// ---- dwRefGraph -----------------------------------------------------------------

// One plotted data point: a 0x14 record holding the topic name plus its two
// numeric properties (density/strength). Nodes of pDataPoints hold these.
struct dwRefGraphPoint
{
    dwString name;   // 0x00: TOPIC_NAME
    float density;   // 0x0c: DENSITY value
    float strength;  // 0x10: STRENGTH value

    dwRefGraphPoint(const char* pName, float density, float strength)
        : name(pName, 0), density(density), strength(strength) {}
};

// dwWidgetGroup base @0x00 (0x14) + fields below — sizeof 0x50. vtable
// dwRefGraph_vtbl overrides only DtorDelete(+0x00), Update(+0x14), OnMessage(+0x1c).
struct dwRefGraph : dwWidgetGroup
{
    dwList pDataPoints;   // 0x14: dwRefGraphPoint* payloads
    dwList pTopicsTPC;    // 0x18: TPC topic-file records (inits_EnumFilesByExt)
    dwList pTopicsSUB;    // 0x1c: SUB topic-file records (inits_EnumFilesByExt)
    int dataPointCount;   // 0x20
    void* pScreen;        // 0x24 (Ghidra: pScreen) — the localized NAME token
    int32_t viewMode;     // 0x28: SetMode0(0)/SetMode1(1) via 0x1b62/0x1b63
    float config1;        // 0x2c: first GRAPH float param
    float config2;        // 0x30: second GRAPH float param
    int16_t animOriginX;  // 0x34
    int16_t curY;         // 0x36
    int16_t curX;         // 0x38
    int16_t targetY;      // 0x3a
    float animTime;       // 0x3c
    dwString soundName;   // 0x40: animation-tick loop wav
    uint8_t bDirtyX;      // 0x4c
    uint8_t bDirtyY;      // 0x4d

    // dwRefGraph_Ctor — dwWidgetGroup(pRect); LoadTopics ->
    // LayoutLabels -> LayoutMarkers at construction.
    dwRefGraph(dwRect* pRect, void* pScreen, float config1, float config2, char* pSoundName);

    // dwRefGraph_Dtor (scalar-deleting wrapper dwRefGraph_DtorDelete = vtbl +0x00) —
    // free the 3 data lists + soundName; the base group dtor deletes children.
    virtual ~dwRefGraph();

    // vtbl +0x14 dwRefGraph_Update — ease cur->target rect, play the tick loop, forward.
    virtual void Update(float dt);
    // vtbl +0x1c dwRefGraph_OnMessage — 0x1b62 SetMode0 / 0x1b63 SetMode1 (re-tick + redraw).
    virtual int OnMessage(dwWidgetMsg* pMsg);

    // ---- non-virtual helpers ----
    void AddDataPoint(char* pName, float density, float strength);
    void LayoutLabels();   // the 3-column hyptext name labels
    void LayoutMarkers();  // the colored arrow-marker pictures
    void LoadTopics();     // enumerate + parse TPC/SUB topic files
    void ParseTopicFile(dwConfFile* pConf);
    void SetMode0() { this->viewMode = 0; }
    void SetMode1() { this->viewMode = 1; }
};

// ---- dwRefMenuItem --------------------------------------------------------------

// One pull-down entry (0x30). AddItem builds these; the item dtor dwRefMenuItem_Dtor
// (scalar-deleting wrapper dwRefMenuItem_DtorDelete) deletes any submenu then frees the strings.
struct dwRefMenuItem
{
    dwString label;         // 0x00
    dwString sortKey;       // 0x0c: category sort key
    dwString topic;         // 0x18: topic file the entry points at
    int value;              // 0x24
    uint8_t flag;           // 0x28
    dwRefPulldown* pSubmenu;// 0x2c: nested pull-down (owned) or NULL

    dwRefMenuItem(const char* pLabel, const char* pSortKey, const char* pTopic,
                  int value, uint8_t flag, dwRefPulldown* pSubmenu);
    ~dwRefMenuItem();
};

// ---- dwRefPulldown --------------------------------------------------------------

// dwWidget base @0x00 (0xe) + fields below — sizeof 0x104. dwRefPulldown_vtbl
// overrides DtorDelete/OnMouseMove/OnMouseDown/Update(no-op)/OnMessage(ret 0)/
// Invalidate/EnsureImages/FreeImages/Draw. Field names follow the Ghidra
// struct dump; several remain field_0xNN where the role is only structural.
struct dwRefPulldown : dwWidget
{
    uint8_t bLayingOut;       // 0x10
    void* pRootMenu;          // 0x14: top-level menu (self when not a submenu)
    uint32_t field_0x18;      // 0x18
    uint8_t field_0x1c;       // 0x1c: font-color param carried to submenus
    uint8_t field_0x1d;       // 0x1d: highlight-dirty flag
    uint8_t field_0x1e;       // 0x1e: hot-font-color param carried to submenus
    void* pImageNormal;       // 0x20
    dwString imageNameNormal; // 0x24
    void* pImagePressed;      // 0x30
    dwString imageNameHot;    // 0x34
    void* pSelectedItem;      // 0x40: dwRefMenuItem* currently highlighted
    uint32_t field_0x44;      // 0x44
    dwFont* pFontNormal;      // 0x48
    uint32_t field_0x4c;      // 0x4c: label-color param
    uint8_t bExpanded;        // 0x50
    uint8_t bOpen;            // 0x51
    dwString label;           // 0x54: collapsed label text
    dwListNode* pVisibleHead; // 0x60: head node of the visible list (into pItems)
    dwList pItems;            // 0x64: dwRefMenuItem* payloads (sorted by category)
    dwList pListB;            // 0x68: TPC enumeration list
    dwList pListC;            // 0x6c: SUB enumeration list
    int16_t width;            // 0x70
    dwString topicScratch;    // 0x74
    int16_t field_0x80;       // 0x80
    int16_t expandHeight;     // 0x82
    int16_t rectExpandLeft;   // 0x84
    int16_t rectExpandTop;    // 0x86
    int16_t rectExpandRight;  // 0x88
    int16_t rectExpandBottom; // 0x8a
    int16_t savedLeft;        // 0x8c
    int16_t savedTop;         // 0x8e
    int16_t savedRight;       // 0x90
    int16_t savedBottom;      // 0x92
    int16_t field_0x94;       // 0x94
    int16_t field_0x96;       // 0x96
    int16_t field_0x98;       // 0x98
    int16_t field_0x9a;       // 0x9a
    int16_t field_0x9c;       // 0x9c: expanded-list left
    int16_t field_0x9e;       // 0x9e: expanded-list top
    int16_t field_0xa0;       // 0xa0: expanded-list right
    int16_t field_0xa2;       // 0xa2: expanded-list bottom
    dwString field_0xa4;      // 0xa4: normal font name
    dwString field_0xb0;      // 0xb0: normal image name (root menu only)
    dwString field_0xbc;      // 0xbc: hot image name (root menu only)
    uint8_t bIsSubmenu;       // 0xc8
    int16_t field_0xca;       // 0xca: last submenu-hover row
    uint8_t field_0xcc;       // 0xcc: hovered flag
    uint8_t field_0xcd;       // 0xcd: text-color param
    dwFont* pFontHot;         // 0xd0
    dwString field_0xd4;      // 0xd4: hover-enter wav
    dwString field_0xe0;      // 0xe0: open wav
    dwString field_0xec;      // 0xec: select wav
    dwString field_0xf8;      // 0xf8: close wav

    // dwRefPulldown_Ctor — dwWidget(pRect); builds the item list and
    // (for a root menu) precaches images + snapshots its collapsed rect.
    dwRefPulldown(dwRect* pRect, char* pFontName, uint8_t colorParam, uint8_t hotColorParam,
                  uint32_t labelColor, char* pImgNormal, char* pImgHot, char* pOpenWav,
                  char* pSelectWav, char* pCloseWav, char* pHoverWav, char* pLabel,
                  uint8_t textColor, char* pFontHot, uint8_t bIsSubmenu);

    // dwRefPulldown_Dtor (scalar-deleting wrapper dwRefPulldown_DtorDelete = vtbl +0x00)
    virtual ~dwRefPulldown();

    virtual int OnMouseMove(int16_t x, int16_t y); // vtbl +0x04 dwRefPulldown_OnMouseMove
    virtual int OnMouseDown(int16_t x, int16_t y); // vtbl +0x08 dwRefPulldown_OnMouseDown
    virtual int OnMessage(dwWidgetMsg* pMsg);      // vtbl +0x1c dwRefPulldown_OnMessage (ret 0)
    virtual void EnsureImages();                   // vtbl +0x3c dwRefPulldown_EnsureImages
    virtual void FreeImages();                     // vtbl +0x40 dwRefPulldown_FreeImages
    virtual void Draw(dwImageBits* pDestBits, dwRect* pClipRect); // vtbl +0x44 dwRefPulldown_Draw

    // ---- non-virtual helpers ----
    void AddItem(char* pTopicFile, char* pLabel, char* pSortKey, uint32_t labelColor,
                 uint8_t flag, dwRefPulldown* pSubmenu);
    void ApplyBounds();
    void BuildItems();
    dwRefPulldown* BuildSubmenu(char* pTopicFile);
    void ComputeRect();
    int16_t MeasureWidth();
    void LayoutExpanded(int16_t left, int16_t top, int hoverRow);
};

#endif // __cplusplus

#endif // _DWREF_H
