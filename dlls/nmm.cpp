#include "nmm.h"

int trackTo;
int trackFrom;
int trackCurrent;
Mix_Music *music;

void trackStart(int track)
{
    std::string path = "MUSIC/Track" + std::to_string(track) + ".ogg";
    if (music)
        Mix_FreeMusic(music);

    music = Mix_LoadMUS(path.c_str());
            
    if (!music) return;

    Mix_PlayMusic(music, 0);
    Mix_HookMusicFinished(trackFinished);
    printf("INFO: Playing music `%s'\n", path.c_str());
}

void trackStop()
{
    Mix_HaltMusic();
    Mix_FreeMusic(music);
    music = nullptr;
}

void trackFinished()
{
    trackCurrent++;
    if (trackCurrent >= trackTo)
        trackCurrent = trackFrom;
    
    trackStart(trackCurrent);
}
