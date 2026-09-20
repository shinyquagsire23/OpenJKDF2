#ifndef _JKTOUCHCONTROLS_H
#define _JKTOUCHCONTROLS_H

#include "types.h"
#include "globals.h"

// On-screen gamepad overlay for touchscreen-only devices.
//
// The layout deliberately mimics an Xbox pad (left stick, ABXY diamond in the
// usual colors, shoulders/triggers above it) so that it reads without labels.
// It only appears when there is nothing better to play with: no gamepad
// attached and no physical keyboard/mouse in use, and only while the world is
// actually being rendered -- the JK menus are mouse-driven and already usable
// through SDL's touch-to-mouse synthesis.
//
// Every entry point below is a no-op on non-touch platforms, so callers in
// shared code do not need to guard their calls.
#if defined(TARGET_IOS) || defined(TARGET_ANDROID)
#define JK_HAS_TOUCH_CONTROLS 1
#endif

void jkTouchControls_Startup(void);
void jkTouchControls_Shutdown(void);

// Draws the overlay. Called from jkGame_Update, which is the engine's
// "the world just got rendered" path -- that call site is what implements the
// "in-game only, never in menus" rule, so there is no separate menu check.
void jkTouchControls_Render(void);

// Pushes the current touch state into stdControl's key/axis arrays. Must run
// inside stdControl_ReadControls, after it clears those arrays and before
// stdControl_ReadMouse consumes the look deltas.
void jkTouchControls_ReadControls(void);

// True when the overlay is currently being drawn and is eating touches.
// Window.c uses this to decide whether SDL should keep synthesizing mouse
// events from touches (menus) or not (gameplay).
int jkTouchControls_IsShown(void);

// Called when real hardware input arrives (a physical key, a non-synthesized
// mouse event, or any gamepad activity). Hides the overlay: someone with a
// keyboard or controller does not want a thumbstick covering their screen.
void jkTouchControls_NotifyPhysicalInput(void);

// pEvent is an SDL_Event*, typed as void* so this header stays includable from
// the non-SDL retro targets. Returns 1 if the event was consumed by the
// overlay and should not be processed further.
int jkTouchControls_HandleSdlEvent(void* pEvent);

#endif // _JKTOUCHCONTROLS_H
