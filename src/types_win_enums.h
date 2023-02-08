#ifndef _OPENJKDF2_TYPES_WIN_ENUMS_H
#define _OPENJKDF2_TYPES_WIN_ENUMS_H

#include <stdint.h>

#define D3DBLEND_ZERO            (1)
#define D3DBLEND_ONE             (2)
#define D3DBLEND_SRCCOLOR        (3)
#define D3DBLEND_INVSRCCOLOR     (4)
#define D3DBLEND_SRCALPHA        (5)
#define D3DBLEND_INVSRCALPHA     (6)
#define D3DBLEND_DESTALPHA       (7)
#define D3DBLEND_INVDESTALPHA    (8)
#define D3DBLEND_DESTCOLOR       (9)
#define D3DBLEND_INVDESTCOLOR    (10)
#define D3DBLEND_SRCALPHASAT     (11)
#define D3DBLEND_BOTHSRCALPHA    (12)
#define D3DBLEND_BOTHINVSRCALPHA (13)

/****************************************************************************
 *
 *      DirectInput keyboard scan codes
 *
 ****************************************************************************/
#define DIK_ESCAPE          0x01
#define DIK_1               0x02
#define DIK_2               0x03
#define DIK_3               0x04
#define DIK_4               0x05
#define DIK_5               0x06
#define DIK_6               0x07
#define DIK_7               0x08
#define DIK_8               0x09
#define DIK_9               0x0A
#define DIK_0               0x0B
#define DIK_MINUS           0x0C    /* - on main keyboard */
#define DIK_EQUALS          0x0D
#define DIK_BACK            0x0E    /* backspace */
#define DIK_TAB             0x0F
#define DIK_Q               0x10
#define DIK_W               0x11
#define DIK_E               0x12
#define DIK_R               0x13
#define DIK_T               0x14
#define DIK_Y               0x15
#define DIK_U               0x16
#define DIK_I               0x17
#define DIK_O               0x18
#define DIK_P               0x19
#define DIK_LBRACKET        0x1A
#define DIK_RBRACKET        0x1B
#define DIK_RETURN          0x1C    /* Enter on main keyboard */
#define DIK_LCONTROL        0x1D
#define DIK_A               0x1E
#define DIK_S               0x1F
#define DIK_D               0x20
#define DIK_F               0x21
#define DIK_G               0x22
#define DIK_H               0x23
#define DIK_J               0x24
#define DIK_K               0x25
#define DIK_L               0x26
#define DIK_SEMICOLON       0x27
#define DIK_APOSTROPHE      0x28
#define DIK_GRAVE           0x29    /* accent grave */
#define DIK_LSHIFT          0x2A
#define DIK_BACKSLASH       0x2B
#define DIK_Z               0x2C
#define DIK_X               0x2D
#define DIK_C               0x2E
#define DIK_V               0x2F
#define DIK_B               0x30
#define DIK_N               0x31
#define DIK_M               0x32
#define DIK_COMMA           0x33
#define DIK_PERIOD          0x34    /* . on main keyboard */
#define DIK_SLASH           0x35    /* / on main keyboard */
#define DIK_RSHIFT          0x36
#define DIK_MULTIPLY        0x37    /* * on numeric keypad */
#define DIK_LMENU           0x38    /* left Alt */
#define DIK_SPACE           0x39
#define DIK_CAPITAL         0x3A
#define DIK_F1              0x3B
#define DIK_F2              0x3C
#define DIK_F3              0x3D
#define DIK_F4              0x3E
#define DIK_F5              0x3F
#define DIK_F6              0x40
#define DIK_F7              0x41
#define DIK_F8              0x42
#define DIK_F9              0x43
#define DIK_F10             0x44
#define DIK_NUMLOCK         0x45
#define DIK_SCROLL          0x46    /* Scroll Lock */
#define DIK_NUMPAD7         0x47
#define DIK_NUMPAD8         0x48
#define DIK_NUMPAD9         0x49
#define DIK_SUBTRACT        0x4A    /* - on numeric keypad */
#define DIK_NUMPAD4         0x4B
#define DIK_NUMPAD5         0x4C
#define DIK_NUMPAD6         0x4D
#define DIK_ADD             0x4E    /* + on numeric keypad */
#define DIK_NUMPAD1         0x4F
#define DIK_NUMPAD2         0x50
#define DIK_NUMPAD3         0x51
#define DIK_NUMPAD0         0x52
#define DIK_DECIMAL         0x53    /* . on numeric keypad */
#define DIK_OEM_102         0x56    /* <> or \| on RT 102-key keyboard (Non-U.S.) */
#define DIK_F11             0x57
#define DIK_F12             0x58
#define DIK_F13             0x64    /*                     (NEC PC98) */
#define DIK_F14             0x65    /*                     (NEC PC98) */
#define DIK_F15             0x66    /*                     (NEC PC98) */
#define DIK_KANA            0x70    /* (Japanese keyboard)            */
#define DIK_ABNT_C1         0x73    /* /? on Brazilian keyboard */
#define DIK_CONVERT         0x79    /* (Japanese keyboard)            */
#define DIK_NOCONVERT       0x7B    /* (Japanese keyboard)            */
#define DIK_YEN             0x7D    /* (Japanese keyboard)            */
#define DIK_ABNT_C2         0x7E    /* Numpad . on Brazilian keyboard */
#define DIK_NUMPADEQUALS    0x8D    /* = on numeric keypad (NEC PC98) */
#define DIK_CIRCUMFLEX      0x90
#define DIK_PREVTRACK       0x90    /* Previous Track (DIK_CIRCUMFLEX on Japanese keyboard) */
#define DIK_AT              0x91    /*                     (NEC PC98) */
#define DIK_COLON           0x92    /*                     (NEC PC98) */
#define DIK_UNDERLINE       0x93    /*                     (NEC PC98) */
#define DIK_KANJI           0x94    /* (Japanese keyboard)            */
#define DIK_STOP            0x95    /*                     (NEC PC98) */
#define DIK_AX              0x96    /*                     (Japan AX) */
#define DIK_UNLABELED       0x97    /*                        (J3100) */
#define DIK_NEXTTRACK       0x99    /* Next Track */
#define DIK_NUMPADENTER     0x9C    /* Enter on numeric keypad */
#define DIK_RCONTROL        0x9D
#define DIK_MUTE            0xA0    /* Mute */
#define DIK_CALCULATOR      0xA1    /* Calculator */
#define DIK_PLAYPAUSE       0xA2    /* Play / Pause */
#define DIK_MEDIASTOP       0xA4    /* Media Stop */
#define DIK_VOLUMEDOWN      0xAE    /* Volume - */
#define DIK_VOLUMEUP        0xB0    /* Volume + */
#define DIK_WEBHOME         0xB2    /* Web home */
#define DIK_NUMPADCOMMA     0xB3    /* , on numeric keypad (NEC PC98) */
#define DIK_DIVIDE          0xB5    /* / on numeric keypad */
#define DIK_SYSRQ           0xB7
#define DIK_RMENU           0xB8    /* right Alt */
#define DIK_PAUSE           0xC5    /* Pause */
#define DIK_HOME            0xC7    /* Home on arrow keypad */
#define DIK_UP              0xC8    /* UpArrow on arrow keypad */
#define DIK_PRIOR           0xC9    /* PgUp on arrow keypad */
#define DIK_LEFT            0xCB    /* LeftArrow on arrow keypad */
#define DIK_RIGHT           0xCD    /* RightArrow on arrow keypad */
#define DIK_END             0xCF    /* End on arrow keypad */
#define DIK_DOWN            0xD0    /* DownArrow on arrow keypad */
#define DIK_NEXT            0xD1    /* PgDn on arrow keypad */
#define DIK_INSERT          0xD2    /* Insert on arrow keypad */
#define DIK_DELETE          0xD3    /* Delete on arrow keypad */
#define DIK_LWIN            0xDB    /* Left Windows key */
#define DIK_RWIN            0xDC    /* Right Windows key */
#define DIK_APPS            0xDD    /* AppMenu key */
#define DIK_POWER           0xDE    /* System Power */
#define DIK_SLEEP           0xDF    /* System Sleep */
#define DIK_WAKE            0xE3    /* System Wake */
#define DIK_WEBSEARCH       0xE5    /* Web Search */
#define DIK_WEBFAVORITES    0xE6    /* Web Favorites */
#define DIK_WEBREFRESH      0xE7    /* Web Refresh */
#define DIK_WEBSTOP         0xE8    /* Web Stop */
#define DIK_WEBFORWARD      0xE9    /* Web Forward */
#define DIK_WEBBACK         0xEA    /* Web Back */
#define DIK_MYCOMPUTER      0xEB    /* My Computer */
#define DIK_MAIL            0xEC    /* Mail */
#define DIK_MEDIASELECT     0xED    /* Media Select */

#define DPSYS_ADDPLAYER               0x0003  // DPMSG_ADDPLAYER
#define DPSYS_DELETEPLAYER            0x0005  // DPMSG_DELETEPLAYER
#define DPSYS_ADDPLAYERTOGROUP        0x0007  // DPMSG_GROUPADD
#define DPSYS_INVITE                  0x000e  // DPMSG_INVITE, Net only.
#define DPSYS_DELETEGROUP             0x0020  // DPMSG_DELETEPLAYER
#define DPSYS_DELETEPLAYERFROMGRP     0x0021  // DPMSG_GROUPDELETE
#define DPSYS_SESSIONLOST             0x0031
#define DPSYS_CONNECT                 0x484b  // DPMSG_GENERIC

#define DPID_SYSMSG         0
#define DPID_ALLPLAYERS     0
#define DPID_SERVERPLAYER   1
#define DPID_UNKNOWN        0xFFFFFFFF

#define WM_NULL             0x00
#define WM_CREATE           0x01
#define WM_DESTROY          0x02
#define WM_MOVE             0x03
#define WM_SIZE             0x05
#define WM_ACTIVATE         0x06
#define WM_SETFOCUS         0x07
#define WM_KILLFOCUS        0x08
#define WM_ENABLE           0x0A
#define WM_SETREDRAW        0x0B
#define WM_SETTEXT          0x0C
#define WM_GETTEXT          0x0D
#define WM_GETTEXTLENGTH    0x0E
#define WM_PAINT            0x0F
#define WM_CLOSE            0x10
#define WM_QUERYENDSESSION  0x11
#define WM_QUIT             0x12
#define WM_QUERYOPEN        0x13
#define WM_ERASEBKGND       0x14
#define WM_SYSCOLORCHANGE   0x15
#define WM_ENDSESSION       0x16
#define WM_SYSTEMERROR      0x17
#define WM_SHOWWINDOW       0x18
#define WM_CTLCOLOR         0x19
#define WM_WININICHANGE     0x1A
#define WM_SETTINGCHANGE    0x1A
#define WM_DEVMODECHANGE    0x1B
#define WM_ACTIVATEAPP      0x1C
#define WM_FONTCHANGE       0x1D
#define WM_TIMECHANGE       0x1E
#define WM_CANCELMODE       0x1F
#define WM_SETCURSOR        0x20
#define WM_MOUSEACTIVATE    0x21
#define WM_CHILDACTIVATE    0x22
#define WM_QUEUESYNC        0x23
#define WM_GETMINMAXINFO    0x24
#define WM_PAINTICON        0x26
#define WM_ICONERASEBKGND   0x27
#define WM_NEXTDLGCTL       0x28
#define WM_SPOOLERSTATUS    0x2A
#define WM_DRAWITEM         0x2B
#define WM_MEASUREITEM      0x2C
#define WM_DELETEITEM       0x2D
#define WM_VKEYTOITEM       0x2E
#define WM_CHARTOITEM       0x2F

#define WM_SETFONT 0x30
#define WM_GETFONT 0x31
#define WM_SETHOTKEY 0x32
#define WM_GETHOTKEY 0x33
#define WM_QUERYDRAGICON 0x37
#define WM_COMPAREITEM 0x39
#define WM_COMPACTING 0x41
#define WM_WINDOWPOSCHANGING 0x46
#define WM_WINDOWPOSCHANGED 0x47
#define WM_POWER 0x48
#define WM_COPYDATA 0x4A
#define WM_CANCELJOURNAL 0x4B
#define WM_NOTIFY 0x4E
#define WM_INPUTLANGCHANGEREQUEST 0x50
#define WM_INPUTLANGCHANGE 0x51
#define WM_TCARD 0x52
#define WM_HELP 0x53
#define WM_USERCHANGED 0x54
#define WM_NOTIFYFORMAT 0x55
#define WM_CONTEXTMENU 0x7B
#define WM_STYLECHANGING 0x7C
#define WM_STYLECHANGED 0x7D
#define WM_DISPLAYCHANGE 0x7E
#define WM_GETICON 0x7F
#define WM_SETICON 0x80

#define WM_NCCREATE 0x81
#define WM_NCDESTROY 0x82
#define WM_NCCALCSIZE 0x83
#define WM_NCHITTEST 0x84
#define WM_NCPAINT 0x85
#define WM_NCACTIVATE 0x86
#define WM_GETDLGCODE 0x87
#define WM_NCMOUSEMOVE 0xA0
#define WM_NCLBUTTONDOWN 0xA1
#define WM_NCLBUTTONUP 0xA2
#define WM_NCLBUTTONDBLCLK 0xA3
#define WM_NCRBUTTONDOWN 0xA4
#define WM_NCRBUTTONUP 0xA5
#define WM_NCRBUTTONDBLCLK 0xA6
#define WM_NCMBUTTONDOWN 0xA7
#define WM_NCMBUTTONUP 0xA8
#define WM_NCMBUTTONDBLCLK 0xA9

#define WM_KEYFIRST 0x100
#define WM_KEYDOWN 0x100
#define WM_KEYUP 0x101
#define WM_CHAR 0x102
#define WM_DEADCHAR 0x103
#define WM_SYSKEYDOWN 0x104
#define WM_SYSKEYUP 0x105
#define WM_SYSCHAR 0x106
#define WM_SYSDEADCHAR 0x107
#define WM_KEYLAST 0x108

#define WM_IME_STARTCOMPOSITION 0x10D
#define WM_IME_ENDCOMPOSITION 0x10E
#define WM_IME_COMPOSITION 0x10F
#define WM_IME_KEYLAST 0x10F

#define WM_INITDIALOG 0x110
#define WM_COMMAND 0x111
#define WM_SYSCOMMAND 0x112
#define WM_TIMER 0x113
#define WM_HSCROLL 0x114
#define WM_VSCROLL 0x115
#define WM_INITMENU 0x116
#define WM_INITMENUPOPUP 0x117
#define WM_MENUSELECT 0x11F
#define WM_MENUCHAR 0x120
#define WM_ENTERIDLE 0x121

#define WM_CTLCOLORMSGBOX 0x132
#define WM_CTLCOLOREDIT 0x133
#define WM_CTLCOLORLISTBOX 0x134
#define WM_CTLCOLORBTN 0x135
#define WM_CTLCOLORDLG 0x136
#define WM_CTLCOLORSCROLLBAR 0x137
#define WM_CTLCOLORSTATIC 0x138

#define WM_MOUSEFIRST 0x200
#define WM_MOUSEMOVE 0x200
#define WM_LBUTTONDOWN 0x201
#define WM_LBUTTONUP 0x202
#define WM_LBUTTONDBLCLK 0x203
#define WM_RBUTTONDOWN 0x204
#define WM_RBUTTONUP 0x205
#define WM_RBUTTONDBLCLK 0x206
#define WM_MBUTTONDOWN 0x207
#define WM_MBUTTONUP 0x208
#define WM_MBUTTONDBLCLK 0x209
#define WM_MOUSEWHEEL 0x20A
#define WM_MOUSEHWHEEL 0x20E

#define WM_PARENTNOTIFY 0x210
#define WM_ENTERMENULOOP 0x211
#define WM_EXITMENULOOP 0x212
#define WM_NEXTMENU 0x213
#define WM_SIZING 0x214
#define WM_CAPTURECHANGED 0x215
#define WM_MOVING 0x216
#define WM_POWERBROADCAST 0x218
#define WM_DEVICECHANGE 0x219

#define WM_MDICREATE 0x220
#define WM_MDIDESTROY 0x221
#define WM_MDIACTIVATE 0x222
#define WM_MDIRESTORE 0x223
#define WM_MDINEXT 0x224
#define WM_MDIMAXIMIZE 0x225
#define WM_MDITILE 0x226
#define WM_MDICASCADE 0x227
#define WM_MDIICONARRANGE 0x228
#define WM_MDIGETACTIVE 0x229
#define WM_MDISETMENU 0x230
#define WM_ENTERSIZEMOVE 0x231
#define WM_EXITSIZEMOVE 0x232
#define WM_DROPFILES 0x233
#define WM_MDIREFRESHMENU 0x234

#define WM_IME_SETCONTEXT 0x281
#define WM_IME_NOTIFY 0x282
#define WM_IME_CONTROL 0x283
#define WM_IME_COMPOSITIONFULL 0x284
#define WM_IME_SELECT 0x285
#define WM_IME_CHAR 0x286
#define WM_IME_KEYDOWN 0x290
#define WM_IME_KEYUP 0x291

#define WM_MOUSEHOVER 0x2A1
#define WM_NCMOUSELEAVE 0x2A2
#define WM_MOUSELEAVE 0x2A3

#define WM_CUT 0x300
#define WM_COPY 0x301
#define WM_PASTE 0x302
#define WM_CLEAR 0x303
#define WM_UNDO 0x304

#define WM_RENDERFORMAT 0x305
#define WM_RENDERALLFORMATS 0x306
#define WM_DESTROYCLIPBOARD 0x307
#define WM_DRAWCLIPBOARD 0x308
#define WM_PAINTCLIPBOARD 0x309
#define WM_VSCROLLCLIPBOARD 0x30A
#define WM_SIZECLIPBOARD 0x30B
#define WM_ASKCBFORMATNAME 0x30C
#define WM_CHANGECBCHAIN 0x30D
#define WM_HSCROLLCLIPBOARD 0x30E
#define WM_QUERYNEWPALETTE 0x30F
#define WM_PALETTEISCHANGING 0x310
#define WM_PALETTECHANGED 0x311

#define WM_HOTKEY 0x312
#define WM_PRINT 0x317
#define WM_PRINTCLIENT 0x318

#define WM_HANDHELDFIRST 0x358
#define WM_HANDHELDLAST 0x35F
#define WM_PENWINFIRST 0x380
#define WM_PENWINLAST 0x38F
#define WM_COALESCE_FIRST 0x390
#define WM_COALESCE_LAST 0x39F
#define WM_DDE_FIRST 0x3E0
#define WM_DDE_INITIATE 0x3E0
#define WM_DDE_TERMINATE 0x3E1
#define WM_DDE_ADVISE 0x3E2
#define WM_DDE_UNADVISE 0x3E3
#define WM_DDE_ACK 0x3E4
#define WM_DDE_DATA 0x3E5
#define WM_DDE_REQUEST 0x3E6
#define WM_DDE_POKE 0x3E7
#define WM_DDE_EXECUTE 0x3E8
#define WM_DDE_LAST 0x3E8

#define WM_USER 0x400
#define WM_APP 0x8000

#define VK_BACK   (0x08)
#define VK_TAB    (0x09)
#define VK_RETURN (0x0D)
#define VK_SHIFT  (0x10)
#define VK_ESCAPE (0x1B)
#define VK_SPACE  (0x20)
#define VK_PRIOR  (0x21) // PAGE UP
#define VK_NEXT   (0x22) // PAGE DOWN
#define VK_END    (0x23)
#define VK_HOME   (0x24)
#define VK_LEFT   (0x25)
#define VK_UP     (0x26)
#define VK_RIGHT  (0x27) 
#define VK_DOWN   (0x28)
#define VK_INSERT (0x2D)
#define VK_DELETE (0x2E)

#define VK_LSHIFT (0xA0)
#define VK_RSHIFT (0xA1)
#define VK_OEM_3  (0xC0)

#define VK_LWIN   (0x5B)
#define VK_RWIN   (0x5C)

#define HKEY_LOCAL_MACHINE 0

#endif // _OPENJKDF2_TYPES_WIN_ENUMS_H