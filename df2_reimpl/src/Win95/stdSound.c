#include "stdSound.h"

#include "jk.h"

#ifdef LINUX
int stdSound_Initialize()
{
    return 1;
}

void* stdSound_ParseWav(int sound_file, int *nSamplesPerSec, int *bitsPerSample, int *bStereo, int *seekOffset)
{
    return NULL;
}
#endif
