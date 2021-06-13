#include "stdSound.h"

#include "jk.h"

#ifdef LINUX
int stdSound_Initialize()
{
    return 1;
}

uint32_t stdSound_ParseWav(int sound_file, int *nSamplesPerSec, int *bitsPerSample, int *bStereo, int *seekOffset)
{
    return 0;
}
#endif
