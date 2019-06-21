#include "dlls/dsound/IDirectSoundBuffer.h"

#include <array>

std::array<Mix_Chunk*, NUM_CHANNELS> active_channels;

void channel_done(int channel)
{
    if (channel < 0 || channel >= NUM_CHANNELS) return;

    if (active_channels[channel])
    {
        free(active_channels[channel]->abuf);
        Mix_FreeChunk(active_channels[channel]);
    }
    
    active_channels[channel] = nullptr;
}
