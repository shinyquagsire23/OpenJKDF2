#include "smackw32.h"

#include "vm.h"
#include "kernel32.h"

void SmackW32::SmackSoundUseDirectSound(void* lpDSound)
{

}

void SmackW32::SmackNextFrame(void *smackInst)
{
    
}

void SmackW32::SmackClose(void *smackInst)
{
    
}

uint32_t SmackW32::SmackOpen(char* fname, uint32_t b, uint32_t c)
{
    printf("STUB: SmackOpen(\"%s\", %x, %x)\n", fname, b, c);

    uint32_t ptr = kernel32->VirtualAlloc(0, 0x1000, 0, 0);
    return ptr;
}

void SmackW32::SmackGetTrackData(void *smackInst, uint32_t a, uint32_t b)
{
    
}

void SmackW32::SmackDoFrame(void *smackInst)
{
    
}

void SmackW32::SmackToBuffer(void *smackInst, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f)
{
    
}

uint32_t SmackW32::SmackWait(void *smackInst)
{
    //HACK: Set frames processed to end
    
    *(uint32_t*)(smackInst + 0xC) = 1;
    *(uint32_t*)(smackInst + 0x374) = 0;
    
    return 0;
}

void SmackW32::SmackSoundOnOff(void *smackInst, bool on)
{
    
}
