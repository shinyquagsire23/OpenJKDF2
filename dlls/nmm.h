#ifndef NMM_H
#define NMM_H

#include <QObject>
#include <chrono>
#include <string>
#include "vm.h"

#include <SDL2/SDL_mixer.h>

#define MCI_OPEN_DRIVER			        0x0801
#define MCI_CLOSE_DRIVER		        0x0802
#define MCI_OPEN			            0x0803
#define MCI_CLOSE			            0x0804
#define MCI_ESCAPE                      0x0805
#define MCI_PLAY                        0x0806
#define MCI_SEEK                        0x0807
#define MCI_STOP                        0x0808
#define MCI_PAUSE                       0x0809
#define MCI_INFO                        0x080A
#define MCI_GETDEVCAPS                  0x080B
#define MCI_SPIN                        0x080C
#define MCI_SET                         0x080D
#define MCI_STEP                        0x080E
#define MCI_RECORD                      0x080F
#define MCI_SYSINFO                     0x0810
#define MCI_BREAK                       0x0811
#define MCI_SOUND                       0x0812
#define MCI_SAVE                        0x0813
#define MCI_STATUS                      0x0814
#define MCI_CUE                         0x0830
#define MCI_REALIZE                     0x0840
#define MCI_WINDOW                      0x0841
#define MCI_PUT                         0x0842
#define MCI_WHERE                       0x0843
#define MCI_FREEZE                      0x0844
#define MCI_UNFREEZE                    0x0845
#define MCI_LOAD                        0x0850
#define MCI_CUT                         0x0851
#define MCI_COPY                        0x0852
#define MCI_PASTE                       0x0853
#define MCI_UPDATE                      0x0854
#define MCI_RESUME                      0x0855
#define MCI_DELETE                      0x0856

typedef struct 
{
  uint32_t dwCallback;
  uint32_t dwFrom;
  uint32_t dwTo;
} MCI_PLAY_PARMS;

typedef struct 
{
  uint32_t dwCallback;
  uint32_t dwReturn;
  uint32_t dwItem;
  uint32_t dwTrack;
} MCI_STATUS_PARMS;

extern int trackFrom;
extern int trackTo;
extern int trackCurrent;
extern Mix_Music *music;
extern void trackStart(int track);
extern void trackStop();
extern void trackFinished();

class Nmm : public QObject
{
Q_OBJECT

public:

    Q_INVOKABLE Nmm()
    {
        trackTo = 0;
        trackFrom = 0;
        trackCurrent = 0;
        music = nullptr;
    }
    
    Q_INVOKABLE uint32_t mciSendCommandA(uint32_t devId, uint32_t uMsg, uint32_t dwParam1, uint32_t dwParam2)
    {
        printf("STUB: WINMM.dll::mciSendCommandA(%x, %x, %x, %x)\n", devId, uMsg, dwParam1, dwParam2);
        
        if (uMsg == MCI_OPEN)
        {
        }
        else if (uMsg == MCI_SET)
        {
            
        }
        else if (uMsg == MCI_STATUS)
        {
            MCI_STATUS_PARMS* params = (MCI_STATUS_PARMS*)vm_ptr_to_real_ptr(dwParam2);
            
            if (!music)
                params->dwReturn = 0x20D;
            else
                params->dwReturn = 0;
        }
        else if (uMsg == MCI_PLAY)
        {
            MCI_PLAY_PARMS* params = (MCI_PLAY_PARMS*)vm_ptr_to_real_ptr(dwParam2);
            printf("STUB: MCI_PLAY(%x, %x, %x)\n", params->dwCallback, params->dwFrom, params->dwTo);
            
            
            
            trackTo = params->dwTo;
            trackFrom = params->dwFrom;
            trackCurrent = trackFrom;

            trackStart(trackCurrent);
        }
        else if (uMsg == MCI_STOP)
        {
            trackStop();
        }
        
        return 0;
    }
    
    Q_INVOKABLE uint32_t auxGetNumDevs(void)
    {
        printf("STUB: WINMM.dll::auxGetNumDevs\n");
        return 0;
    }
    
    Q_INVOKABLE uint32_t joyGetNumDevs(void)
    {
        printf("STUB: WINMM.dll::joyGetNumDevs\n");
        return 0;
    }
    
    Q_INVOKABLE uint32_t timeGetTime(void)
    {
        return (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    }
    
    Q_INVOKABLE uint32_t waveOutGetNumDevs(void)
    {
        printf("STUB: WINMM.dll::waveOutGetNumDevs\n");
        return 0;
    }

//    Q_INVOKABLE uint32_t ();
};

extern Nmm *nmm;

#endif // NMM_H
