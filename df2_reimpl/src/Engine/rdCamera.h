#ifndef _RDCAMERA_H
#define _RDCAMERA_H

#define rdCamera_NewEntry_ADDR (0x00443260)
#define rdCamera_SetProjectType_ADDR (0x00443360)
#define rdCamera_Free_ADDR (0x00443440)
#define rdCamera_FreeEntry_ADDR (0x00443470)
#define rdCamera_SetCanvas_ADDR (0x00443490)
#define rdCamera_SetCurrent_ADDR (0x004434B0)
#define rdCamera_SetFOV_ADDR (0x004434D0)
#define rdCamera_idk2_ADDR (0x00443520)
#define rdCamera_idk3_ADDR (0x004435A0)
#define rdCamera_idk_ADDR (0x004435C0)
#define rdCamera_BuildFOV_ADDR (0x00443670)
#define rdCamera_443830_ADDR (0x00443830)
#define rdCamera_mat_stuff_ADDR (0x00443900)
#define rdCamera_PerspProject_ADDR (0x00443940)
#define rdCamera_PerspProjectLst_ADDR (0x00443980)
#define rdCamera_443A00_ADDR (0x00443A00)
#define rdCamera_443A40_ADDR (0x00443A40)
#define rdCamera_OrthoProject_ADDR (0x00443AB0)
#define rdCamera_OrthoProjectLst_ADDR (0x00443B00)
#define rdCamera_OrthoProjectSquare_ADDR (0x00443B80)
#define rdCamera_OrthoProjectSquareLst_ADDR (0x00443BC0)
#define rdCamera_SetAmbientLight_ADDR (0x00443C30)
#define rdCamera_SetAttenuation_ADDR (0x00443C40)
#define rdCamera_AddLight_ADDR (0x00443C80)
#define rdCamera_ClearLights_ADDR (0x00443CF0)
#define rdCamera_AdvanceFrame_ADDR (0x00443D10)

typedef void rdCamera;

static void (*rdCamera_AdvanceFrame)(void) = rdCamera_AdvanceFrame_ADDR;


#endif // _RDCAMERA_H
