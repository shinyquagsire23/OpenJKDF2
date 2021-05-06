#include "WinIdk.h"

void WinIdk_SetDplayGuid(int *guid)
{
    WinIdk_aDplayGuid[0] = *guid;
    WinIdk_aDplayGuid[1] = guid[1];
    WinIdk_aDplayGuid[2] = guid[2];
    WinIdk_aDplayGuid[3] = guid[3];
}

uint32_t* WinIdk_GetDplayGuid()
{
    return WinIdk_aDplayGuid;
}

//TODO this is move involved but it's never checked?
int WinIdk_detect_cpu(char *a1)
{
    strcpy(a1, "AuthenticAMD");
}
