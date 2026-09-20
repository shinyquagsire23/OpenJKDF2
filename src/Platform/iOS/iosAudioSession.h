#ifndef _OPENJKDF2_IOS_AUDIOSESSION_H
#define _OPENJKDF2_IOS_AUDIOSESSION_H

#ifdef __cplusplus
extern "C" {
#endif

// Configures and activates the process-wide AVAudioSession.
//
// This MUST run before OpenAL's device is opened (stdSound_Startup). iOS gives a
// process that never touches AVAudioSession the implicit "SoloAmbient" category,
// which is silenced by the hardware ring/silent switch -- so the game comes up
// looking fine and completely mute on a device whose switch happens to be set to
// silent, while the Simulator (no switch) sounds correct. Playback is the right
// category for a game: it keeps sound on regardless of the switch.
void iosAudioSession_Initialize(void);

// Re-activates the session after an interruption (phone call, Siri, another app
// taking the session). SDL delivers the corresponding app events; without a
// re-activate, audio stays dead for the rest of the session.
void iosAudioSession_Reactivate(void);

#ifdef __cplusplus
}
#endif

#endif // _OPENJKDF2_IOS_AUDIOSESSION_H
