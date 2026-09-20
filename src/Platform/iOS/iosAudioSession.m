// iOS AVAudioSession setup. See iosAudioSession.h for why this exists.

#import <AVFoundation/AVFoundation.h>

#include "iosAudioSession.h"

// NB: deliberately no engine headers here. types.h does `typedef int BOOL`,
// which collides with objc.h's `typedef bool BOOL` and fails the build, so the
// one engine function this file needs is declared by hand instead.
extern int stdPlatform_Printf(const char *fmt, ...);

static int iosAudioSession_bInitted = 0;

void iosAudioSession_Initialize(void)
{
    if (iosAudioSession_bInitted) {
        return;
    }

    @autoreleasepool {
        AVAudioSession* pSession = [AVAudioSession sharedInstance];
        NSError* pError = nil;

        // Playback: the game owns audio output and keeps playing with the
        // ring/silent switch engaged.
        //
        // The category/mode/options triple here MUST match, exactly, what SDL's
        // UpdateAudioSession() derives with SDL_HINT_AUDIO_CATEGORY unset -- see
        // lib/SDL/src/audio/coreaudio/SDL_coreaudio.m. When SDL_mixer opens its
        // music device, SDL compares the live session against its own computed
        // config and, on ANY difference, calls `[session setActive:NO]` before
        // reconfiguring. That deactivation permanently stops OpenAL's RemoteIO
        // unit -- its render callback is never pulled again, so music (SDL's own
        // device) keeps playing while every OpenAL sound effect goes silent.
        //
        // SDL's unhinted derivation for a playback-only device is
        // MixWithOthers|DuckOthers (0x3), so that is what we install. Do not
        // "simplify" this to DuckOthers alone: iOS implicitly adds MixWithOthers
        // whenever DuckOthers is set, so the session would still report 0x3 while
        // SDL wanted 0x2, and the mismatch branch would fire on every call.
        if (![pSession setCategory:AVAudioSessionCategoryPlayback
                              mode:AVAudioSessionModeDefault
                           options:AVAudioSessionCategoryOptionMixWithOthers
                                   | AVAudioSessionCategoryOptionDuckOthers
                             error:&pError]) {
            stdPlatform_Printf("iosAudioSession: setCategory failed: %s\n",
                               [[pError localizedDescription] UTF8String]);
        }

        // OpenAL Soft's CoreAudio backend asks for a small buffer; a short
        // preferred duration keeps its latency sane. Failure here is non-fatal --
        // iOS just keeps whatever it had.
        pError = nil;
        if (![pSession setPreferredIOBufferDuration:0.01 error:&pError]) {
            stdPlatform_Printf("iosAudioSession: setPreferredIOBufferDuration failed: %s\n",
                               [[pError localizedDescription] UTF8String]);
        }

        pError = nil;
        if (![pSession setActive:YES error:&pError]) {
            stdPlatform_Printf("iosAudioSession: setActive failed: %s\n",
                               [[pError localizedDescription] UTF8String]);
        }
        else {
            stdPlatform_Printf("iosAudioSession: active, category=Playback, sampleRate=%g\n",
                               [pSession sampleRate]);
        }
    }

    iosAudioSession_bInitted = 1;
}

void iosAudioSession_Reactivate(void)
{
    if (!iosAudioSession_bInitted) {
        return;
    }

    @autoreleasepool {
        NSError* pError = nil;
        if (![[AVAudioSession sharedInstance] setActive:YES error:&pError]) {
            stdPlatform_Printf("iosAudioSession: re-activate failed: %s\n",
                               [[pError localizedDescription] UTF8String]);
        }
    }
}
