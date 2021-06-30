#ifndef _SITHNET_H
#define _SITHNET_H

#define net_MultiModeFlags (*(int*)0x008C4BA0)
#define net_scorelimit (*(int*)0x008C4BAC)
#define net_teamScore ((int*)0x008C4BC0)
#define multiplayer_timelimit (*(int*)0x008C4BD4)
#define net_isMulti (*(int*)0x00832624)
#define net_isServer (*(int*)0x00832628)
#define net_dword_832638 (*(int*)0x00832638)
#define net_dword_8C4BA4 (*(int*)0x008C4BA4)

#define net_things_idx (*(int*)0x008330F0)
#define net_things ((int*)0x008326AC)

#define sithNet_thingsIdx (*(int*)0x008330F0)

#define sithNet_syncIdx (*(int*)0x008330F4)
#define sithNet_aSyncFlags ((int*)0x008330B0)
#define sithNet_aSyncThings ((sithThing**)0x00832668)

#endif // _SITHNET_H
