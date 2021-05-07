#ifndef _WIN95_VIDEO_H
#define _WIN95_VIDEO_H

#define Video_Startup_ADDR (0x004018C0)
#define Video_Shutdown_ADDR (0x00401910)
#define Video_SetVideoDesc_ADDR (0x00401940)
#define Video_SwitchToGDI_ADDR (0x00401C10)
#define Video_camera_related_ADDR (0x00401CD0)

#define Video_modeIdx (*(int*)0x008605C0)
#define Video_descIdx (*(int*)0x008605C4)
#define Video_8605C8 (*(int*)0x008605C8)
#define Video_8605EC (*(int*)0x008605EC)
#define Video_8605F0 (*(int*)0x008605F0)
#define Video_8606A4 (*(int*)0x008606A4)
#define Video_8606A8 (*(int*)0x008606A8)
#define Video_8606AC (*(int*)0x008606AC)
#define Video_8606B0 (*(int*)0x008606B0)
#define Video_8606B4 (*(int*)0x008606B4)
#define Video_8606B8 (*(int*)0x008606B8)
#define Video_8606BC (*(int*)0x008606BC)
#define Video_8606C0 (*(int*)0x008606C0)
#define Video_otherBuf (*(stdVBuffer*)0x00866CA0)
#define Video_dword_866D78 (*(int*)0x00866D78)
#define Video_curMode (*(int*)0x00866D7C)
#define Video_renderSurface ((stdVideoMode*)0x00866D80)
#define Video_menuBuffer (*(stdVBuffer*)0x0086AC00)
#define Video_pOtherBuf (*(stdVBuffer**)0x00552888)
#define Video_pMenuBuffer (*(stdVBuffer**)0x0055288C)
#define Video_bInitted (*(int*)0x005528B4)

static int (*Video_Startup)() = (void*)Video_Startup_ADDR;

#endif // _WIN95_VIDEO_H
