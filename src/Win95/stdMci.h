#ifndef _STDMCI_H
#define _STDMCI_H

#include "types.h"
#include "globals.h"

#ifdef WIN32_BLOBS
#include <mmsystem.h>
#endif

#define stdMci_Startup_ADDR (0x004380D0)
#define stdMci_Shutdown_ADDR (0x004381C0)
#define stdMci_Play_ADDR (0x00438220)
#define stdMci_SetVolume_ADDR (0x004382A0)
#define stdMci_Stop_ADDR (0x004382E0)
#define stdMci_CheckStatus_ADDR (0x00438300)
#define stdMci_GetTrackLength_ADDR (0x00438360)

int stdMci_Startup();
void stdMci_Shutdown();
int stdMci_Play(uint8_t trackFrom, uint8_t trackTo);
void stdMci_SetVolume(float vol);
void stdMci_Stop();
int stdMci_CheckStatus();
double stdMci_GetTrackLength(int track);

#endif // _STDMCI_H
