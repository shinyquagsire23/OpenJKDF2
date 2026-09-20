#include "jkTouchControls.h"

#ifndef JK_HAS_TOUCH_CONTROLS

// Non-touch platforms: everything compiles away to nothing so that the call
// sites in jkGame.c / stdControl.c / Window.c stay free of #ifdefs.
void jkTouchControls_Startup(void) {}
void jkTouchControls_Shutdown(void) {}
void jkTouchControls_Render(void) {}
void jkTouchControls_ReadControls(void) {}
int  jkTouchControls_IsShown(void) { return 0; }
void jkTouchControls_NotifyPhysicalInput(void) {}
int  jkTouchControls_HandleSdlEvent(void* pEvent) { (void)pEvent; return 0; }

#else

#include "SDL2_helper.h"

#include "Platform/std3D.h"
#include "Platform/stdControl.h"
#include "Devices/sithControl.h"
#include "World/sithWeapon.h"
#include "General/stdMath.h"
#include "Win95/Window.h"
#include "Engine/rdMaterial.h"
#include "stdPlatform.h"
#include "jk.h"

// The pad presents itself as joystick 0: it emits the same KEY_JOY1_* codes and
// AXIS_JOY1_* values that stdControl_ReadGamepad() produces for a real Xbox
// controller. Going through the joystick path rather than synthesizing DIK
// keystrokes means the on-screen pad inherits sithControl_MapDefaultsJoystick()'s
// mapping for free, and follows the player's own rebindings -- a virtual A
// button does whatever A does, not whatever happens to be bound to some key.
//
// The pad DOES claim stdControl_aJoystickExists[0] (see the touch block in
// stdControl_InitSdlJoysticks) so the controls menu can list and rebind it --
// which is why HasGamepad() below must ask stdControl_bHasPhysicalJoystick
// rather than that array, or the overlay would hide the instant it appeared.

#define JKTOUCH_MAX_FINGERS     10
#define JKTOUCH_MAX_BUTTONS     14

// Full-scale value for a synthesized stick axis, matching SDL's -0x7FFF..0x7FFF.
#define JKTOUCH_AXIS_MAX        (0x7FFF)

#define JKTOUCH_DEAD_ZONE       (0.18f)

// The pad counts as active only while the world is actually being drawn. Render()
// stamps a timestamp every frame; if nothing has drawn for this long we are in a
// menu, a cutscene or a load screen, and the pad must stop both rendering and
// eating touches so SDL's touch-to-mouse synthesis can drive the UI again.
#define JKTOUCH_ACTIVE_TIMEOUT_MS (250)

// Finger slot assignments.
#define JKTOUCH_ASSIGN_NONE     (-1)
#define JKTOUCH_ASSIGN_LSTICK   (-2)
#define JKTOUCH_ASSIGN_RSTICK   (-3)
// >= 0 means "holding button N".

typedef struct jkTouchButton
{
    // Centre and radius, normalized: x against screen width, y and r against
    // screen height, so the layout keeps its proportions on any aspect ratio.
    flex_t nx;
    flex_t ny;
    flex_t nr;
    int controlId;      // KEY_JOY1_* code this button reports
    uint8_t r, g, b;
} jkTouchButton;

// Laid out like an actual Xbox pad stretched to the screen edges: sticks at the
// bottom corners, d-pad above the left stick, ABXY above the right stick, and
// the shoulders/triggers along the top edge. Nothing is labelled, so that
// arrangement plus the familiar ABXY colours is the whole affordance.
static const jkTouchButton jkTouchControls_aButtons[JKTOUCH_MAX_BUTTONS] = {
    // ABXY diamond, upper right, above the right stick.
    { 0.895f, 0.400f, 0.060f, KEY_JOY1_B1,     0x6C, 0xC2, 0x4A }, // A  green   use last selected
    { 0.948f, 0.290f, 0.060f, KEY_JOY1_B2,     0xE0, 0x2B, 0x2B }, // B  red     duck
    { 0.842f, 0.290f, 0.060f, KEY_JOY1_B3,     0x3A, 0x7B, 0xD5 }, // X  blue    activate
    { 0.895f, 0.180f, 0.060f, KEY_JOY1_B4,     0xF2, 0xC5, 0x11 }, // Y  yellow  jump

    // D-pad, upper left, above the left stick: inventory and Force cycling.
    { 0.105f, 0.180f, 0.048f, KEY_JOY1_HUP,    0x78, 0x78, 0x78 }, // up     next inv
    { 0.105f, 0.400f, 0.048f, KEY_JOY1_HDOWN,  0x78, 0x78, 0x78 }, // down   prev inv
    { 0.052f, 0.290f, 0.048f, KEY_JOY1_HLEFT,  0x78, 0x78, 0x78 }, // left   prev skill
    { 0.158f, 0.290f, 0.048f, KEY_JOY1_HRIGHT, 0x78, 0x78, 0x78 }, // right  next skill

    // Triggers and shoulders along the top edge. The right trigger is primary
    // fire and gets the biggest target, being the most used control in the game.
    { 0.957f, 0.075f, 0.058f, KEY_JOY1_B17,    0xC8, 0xC8, 0xC8 }, // RT  fire 1
    { 0.858f, 0.075f, 0.044f, KEY_JOY1_B11,    0x90, 0x90, 0x90 }, // RB  next weapon
    { 0.043f, 0.075f, 0.058f, KEY_JOY1_B16,    0xC8, 0xC8, 0xC8 }, // LT  fire 2
    { 0.142f, 0.075f, 0.044f, KEY_JOY1_B10,    0x90, 0x90, 0x90 }, // LB  prev weapon

    // Back/Start, tucked inboard of the sticks along the bottom so they clear
    // both the level title at the top centre and the home indicator.
    { 0.255f, 0.900f, 0.038f, KEY_JOY1_B5,     0x88, 0x88, 0x88 }, // Back
    { 0.745f, 0.900f, 0.038f, KEY_JOY1_B7,     0x88, 0x88, 0x88 }, // Start (menu)
};

// Index of Start in the table above; it additionally drives the shared
// "controller pressed escape" hack rather than a binding, exactly as a real
// pad's Start/Back do in Window.c.
#define JKTOUCH_BTN_START       (13)

// Sticks, same normalization as the buttons.
#define JKTOUCH_LSTICK_NX       (0.105f)
#define JKTOUCH_LSTICK_NY       (0.700f)
#define JKTOUCH_RSTICK_NX       (0.895f)
#define JKTOUCH_RSTICK_NY       (0.700f)
#define JKTOUCH_STICK_NR        (0.185f)

typedef struct jkTouchFinger
{
    SDL_FingerID id;
    int bActive;
    int assign;
    flex_t x, y;        // current position, in overlay space
} jkTouchFinger;

// Defined in the SDL stdControl backend; Window.c turns a rising edge of this
// into a VK_ESCAPE message once per frame.
extern int stdControl_bControllerEscapeKey;

static jkTouchFinger jkTouchControls_aFingers[JKTOUCH_MAX_FINGERS];
static int jkTouchControls_bInitted = 0;

// Stamped by Render() every drawn world frame; see JKTOUCH_ACTIVE_TIMEOUT_MS.
static uint32_t jkTouchControls_lastRenderMs = 0;
static int jkTouchControls_bShown = 0;

// Latched when real hardware input shows up. Cleared by a fresh touch, so the
// overlay can come back if the user puts the keyboard down again.
static int jkTouchControls_bHiddenByPhysical = 0;

// Current stick deflections, -1..1.
static flex_t jkTouchControls_lStickX = 0.0f;
static flex_t jkTouchControls_lStickY = 0.0f;
static flex_t jkTouchControls_rStickX = 0.0f;
static flex_t jkTouchControls_rStickY = 0.0f;

static int jkTouchControls_aButtonHeld[JKTOUCH_MAX_BUTTONS];

static flex_t jkTouchControls_screenW = 0.0f;
static flex_t jkTouchControls_screenH = 0.0f;

static int jkTouchControls_HasGamepad(void)
{
    // Real hardware only. stdControl_aJoystickExists[0] is claimed by this very
    // overlay on touch builds, so testing it here would always report a pad.
    return stdControl_bHasPhysicalJoystick;
}

// "The pad is up and owns the screen right now." Both the overlay's own event
// handling and Window.c's touch-to-mouse hint key off this, so that the instant
// the world stops being drawn -- menu, cutscene, load screen -- taps go back to
// driving the cursor.
static int jkTouchControls_IsActive(void)
{
    if (!jkTouchControls_bInitted || !jkTouchControls_bShown) {
        return 0;
    }
    if (!jkTouchControls_lastRenderMs) {
        return 0;
    }
    return (stdPlatform_GetTimeMsec() - jkTouchControls_lastRenderMs) <= JKTOUCH_ACTIVE_TIMEOUT_MS;
}

int jkTouchControls_IsShown(void)
{
    return jkTouchControls_IsActive();
}

// The overlay's own coordinate space is whatever std3D's UI layer uses, which
// is also what touch coordinates get scaled into below.
static void jkTouchControls_UpdateScreenSize(void)
{
    jkTouchControls_screenW = (flex_t)Video_menuBuffer.format.width;
    jkTouchControls_screenH = (flex_t)Video_menuBuffer.format.height;

    if (jkTouchControls_screenW <= 0.0f) jkTouchControls_screenW = 640.0f;
    if (jkTouchControls_screenH <= 0.0f) jkTouchControls_screenH = 480.0f;
}

static void jkTouchControls_ButtonRect(const jkTouchButton* pBtn, flex_t* pCx, flex_t* pCy, flex_t* pR)
{
    *pCx = pBtn->nx * jkTouchControls_screenW;
    *pCy = pBtn->ny * jkTouchControls_screenH;
    *pR  = pBtn->nr * jkTouchControls_screenH;
}

static void jkTouchControls_StickRect(int bRight, flex_t* pCx, flex_t* pCy, flex_t* pR)
{
    *pCx = (bRight ? JKTOUCH_RSTICK_NX : JKTOUCH_LSTICK_NX) * jkTouchControls_screenW;
    *pCy = (bRight ? JKTOUCH_RSTICK_NY : JKTOUCH_LSTICK_NY) * jkTouchControls_screenH;
    *pR  = JKTOUCH_STICK_NR * jkTouchControls_screenH;
}

// Filled disc, rasterized as contiguous horizontal bands. std3D's UI layer only
// offers axis-aligned rects, so the disc is scanned out in strips; each strip
// starts exactly where the previous one ended (integer y throughout) because
// computing the strips in float and truncating independently leaves visible
// 1px seams through the middle of every button.
static void jkTouchControls_FillCircle(flex_t cx, flex_t cy, flex_t r,
                                       uint8_t cr, uint8_t cg, uint8_t cb, uint8_t ca)
{
    if (r <= 1.0f) {
        return;
    }

    int top = (int)(cy - r);
    int bot = (int)(cy + r);
    if (bot <= top) {
        return;
    }

    // ~3px strips keep even the large stick base looking round, with an upper
    // bound on strip count so a huge radius cannot spam the UI batch.
    int step = (bot - top) / 64;
    if (step < 3) {
        step = 3;
    }

    for (int y = top; y < bot; y += step)
    {
        int yEnd = y + step;
        if (yEnd > bot) {
            yEnd = bot;
        }

        // Half-width is taken at whichever edge of the strip is further from the
        // centre line, so strips stay inscribed rather than bulging out.
        flex_t dTop = (flex_t)y - cy;
        flex_t dBot = (flex_t)yEnd - cy;
        flex_t d = (stdMath_Fabs(dTop) > stdMath_Fabs(dBot)) ? dTop : dBot;

        flex_t inner = (r * r) - (d * d);
        if (inner <= 0.0f) {
            continue;
        }

        flex_t halfWidth = stdMath_Sqrt(inner);
        rdRect rect;
        rect.x      = (int)(cx - halfWidth);
        rect.y      = y;
        rect.width  = (int)(halfWidth * 2.0f);
        rect.height = yEnd - y;

        if (rect.width <= 0 || rect.height <= 0) {
            continue;
        }
        std3D_DrawUIClearedRectRGBA(cr, cg, cb, ca, &rect);
    }
}

static void jkTouchControls_DrawStick(int bRight, flex_t deflectX, flex_t deflectY)
{
    flex_t cx, cy, r;
    jkTouchControls_StickRect(bRight, &cx, &cy, &r);

    jkTouchControls_FillCircle(cx, cy, r, 0x20, 0x20, 0x20, 0x50);

    flex_t knobR = r * 0.42f;
    flex_t knobX = cx + (deflectX * (r - knobR));
    flex_t knobY = cy + (deflectY * (r - knobR));

    jkTouchControls_FillCircle(knobX, knobY, knobR, 0xD0, 0xD0, 0xD0, 0xA0);
}

static void jkTouchControls_ReleaseAll(void)
{
    for (int i = 0; i < JKTOUCH_MAX_FINGERS; i++) {
        jkTouchControls_aFingers[i].bActive = 0;
        jkTouchControls_aFingers[i].assign = JKTOUCH_ASSIGN_NONE;
    }
    for (int i = 0; i < JKTOUCH_MAX_BUTTONS; i++) {
        jkTouchControls_aButtonHeld[i] = 0;
    }
    jkTouchControls_lStickX = 0.0f;
    jkTouchControls_lStickY = 0.0f;
    jkTouchControls_rStickX = 0.0f;
    jkTouchControls_rStickY = 0.0f;
    stdControl_bControllerEscapeKey = 0;
}

void jkTouchControls_Startup(void)
{
    jkTouchControls_ReleaseAll();

    jkTouchControls_lastRenderMs = 0;
    jkTouchControls_bShown = 0;
    jkTouchControls_bHiddenByPhysical = 0;

    jkTouchControls_bInitted = 1;
}

void jkTouchControls_Shutdown(void)
{
    jkTouchControls_bInitted = 0;
    jkTouchControls_bShown = 0;
    jkTouchControls_lastRenderMs = 0;
}

void jkTouchControls_NotifyPhysicalInput(void)
{
    if (!jkTouchControls_bInitted) {
        return;
    }

    if (!jkTouchControls_bHiddenByPhysical) {
        // Drop anything mid-press so a held virtual button does not stick down
        // once the overlay stops being drawn.
        jkTouchControls_ReleaseAll();
    }

    jkTouchControls_bHiddenByPhysical = 1;
}

static jkTouchFinger* jkTouchControls_FindFinger(SDL_FingerID id)
{
    for (int i = 0; i < JKTOUCH_MAX_FINGERS; i++) {
        if (jkTouchControls_aFingers[i].bActive && jkTouchControls_aFingers[i].id == id) {
            return &jkTouchControls_aFingers[i];
        }
    }
    return NULL;
}

static jkTouchFinger* jkTouchControls_AllocFinger(void)
{
    for (int i = 0; i < JKTOUCH_MAX_FINGERS; i++) {
        if (!jkTouchControls_aFingers[i].bActive) {
            return &jkTouchControls_aFingers[i];
        }
    }
    return NULL;
}

// Decides what a newly-landed finger drives. Buttons win over sticks; the stick
// regions are generous because a thumb lands imprecisely.
static int jkTouchControls_ClassifyTouch(flex_t x, flex_t y)
{
    for (int i = 0; i < JKTOUCH_MAX_BUTTONS; i++)
    {
        flex_t cx, cy, r;
        jkTouchControls_ButtonRect(&jkTouchControls_aButtons[i], &cx, &cy, &r);

        flex_t dx = x - cx;
        flex_t dy = y - cy;
        flex_t hit = r * 1.25f;
        if ((dx * dx) + (dy * dy) <= (hit * hit)) {
            return i;
        }
    }

    for (int bRight = 0; bRight < 2; bRight++)
    {
        flex_t cx, cy, r;
        jkTouchControls_StickRect(bRight, &cx, &cy, &r);

        flex_t dx = x - cx;
        flex_t dy = y - cy;
        flex_t hit = r * 1.30f;
        if ((dx * dx) + (dy * dy) <= (hit * hit)) {
            return bRight ? JKTOUCH_ASSIGN_RSTICK : JKTOUCH_ASSIGN_LSTICK;
        }
    }

    return JKTOUCH_ASSIGN_NONE;
}

static void jkTouchControls_UpdateStickFromFinger(const jkTouchFinger* pFinger)
{
    int bRight = (pFinger->assign == JKTOUCH_ASSIGN_RSTICK);

    flex_t cx, cy, r;
    jkTouchControls_StickRect(bRight, &cx, &cy, &r);

    flex_t dx = (pFinger->x - cx) / r;
    flex_t dy = (pFinger->y - cy) / r;

    flex_t mag = stdMath_Sqrt((dx * dx) + (dy * dy));
    if (mag > 1.0f) {
        dx /= mag;
        dy /= mag;
    }

    if (bRight) {
        jkTouchControls_rStickX = dx;
        jkTouchControls_rStickY = dy;
    }
    else {
        jkTouchControls_lStickX = dx;
        jkTouchControls_lStickY = dy;
    }
}

static void jkTouchControls_ReleaseFinger(jkTouchFinger* pFinger)
{
    if (pFinger->assign >= 0) {
        jkTouchControls_aButtonHeld[pFinger->assign] = 0;
        if (pFinger->assign == JKTOUCH_BTN_START) {
            stdControl_bControllerEscapeKey = 0;
        }
    }
    else if (pFinger->assign == JKTOUCH_ASSIGN_LSTICK) {
        jkTouchControls_lStickX = 0.0f;
        jkTouchControls_lStickY = 0.0f;
    }
    else if (pFinger->assign == JKTOUCH_ASSIGN_RSTICK) {
        jkTouchControls_rStickX = 0.0f;
        jkTouchControls_rStickY = 0.0f;
    }

    pFinger->bActive = 0;
    pFinger->assign = JKTOUCH_ASSIGN_NONE;
}

int jkTouchControls_HandleSdlEvent(void* pEventRaw)
{
    SDL_Event* pEvent = (SDL_Event*)pEventRaw;

    if (!jkTouchControls_bInitted || !pEvent) {
        return 0;
    }

    if (pEvent->type != SDL_EVENT_FINGER_DOWN
        && pEvent->type != SDL_EVENT_FINGER_UP
        && pEvent->type != SDL_EVENT_FINGER_MOTION
        && pEvent->type != SDL_EVENT_FINGER_CANCELED) {
        return 0;
    }

    // Releases are processed unconditionally, even once the pad has gone
    // inactive. Dropping them on the inactive path is what leaves a button
    // latched down -- lift a finger during the frame the world stops being
    // drawn and the player keeps firing forever.
    if (pEvent->type == SDL_EVENT_FINGER_UP || pEvent->type == SDL_EVENT_FINGER_CANCELED)
    {
        jkTouchFinger* pFinger = jkTouchControls_FindFinger(pEvent->tfinger.fingerID);
        if (pFinger) {
            jkTouchControls_ReleaseFinger(pFinger);
            return 1;
        }
        return 0;
    }

    // A touch means the player is back on the screen; let the overlay return
    // even if a keyboard was used earlier. A gamepad still suppresses it --
    // that is a deliberate choice, not an oversight.
    if (pEvent->type == SDL_EVENT_FINGER_DOWN && jkTouchControls_bHiddenByPhysical
        && !jkTouchControls_HasGamepad()) {
        jkTouchControls_bHiddenByPhysical = 0;
    }

    if (!jkTouchControls_IsActive()) {
        return 0;
    }

    jkTouchControls_UpdateScreenSize();

    // SDL reports fingers in 0..1 of the window; the overlay lives in std3D's
    // UI space, so scale rather than using the raw pixel fields.
    flex_t x = pEvent->tfinger.x * jkTouchControls_screenW;
    flex_t y = pEvent->tfinger.y * jkTouchControls_screenH;

    if (pEvent->type == SDL_EVENT_FINGER_DOWN)
    {
        int assign = jkTouchControls_ClassifyTouch(x, y);
        if (assign == JKTOUCH_ASSIGN_NONE) {
            // Bare screen: not ours. Let it fall through to the normal handlers
            // so taps still dismiss things the pad does not own.
            return 0;
        }

        jkTouchFinger* pFinger = jkTouchControls_AllocFinger();
        if (!pFinger) {
            return 1;
        }

        pFinger->bActive = 1;
        pFinger->id = pEvent->tfinger.fingerID;
        pFinger->x = x;
        pFinger->y = y;
        pFinger->assign = assign;

        if (assign >= 0) {
            jkTouchControls_aButtonHeld[assign] = 1;
            if (assign == JKTOUCH_BTN_START) {
                // Start/Back are not bound to an INPUT_FUNC_*; on a real pad
                // Window.c turns them into an Escape keypress. Mirror that so
                // the virtual Start opens the menu.
                stdControl_bControllerEscapeKey = 1;
            }
        }
        else {
            jkTouchControls_UpdateStickFromFinger(pFinger);
        }
        return 1;
    }

    // SDL_EVENT_FINGER_MOTION
    jkTouchFinger* pFinger = jkTouchControls_FindFinger(pEvent->tfinger.fingerID);
    if (!pFinger) {
        return 0;
    }

    pFinger->x = x;
    pFinger->y = y;

    if (pFinger->assign < 0) {
        jkTouchControls_UpdateStickFromFinger(pFinger);
    }
    else {
        // Let a finger slide off its button to release it, the way a real touch
        // UI behaves.
        flex_t cx, cy, r;
        jkTouchControls_ButtonRect(&jkTouchControls_aButtons[pFinger->assign], &cx, &cy, &r);
        flex_t dx = x - cx;
        flex_t dy = y - cy;
        flex_t hit = r * 1.60f;
        int bHeld = ((dx * dx) + (dy * dy) <= (hit * hit)) ? 1 : 0;

        jkTouchControls_aButtonHeld[pFinger->assign] = bHeld;
        if (pFinger->assign == JKTOUCH_BTN_START) {
            stdControl_bControllerEscapeKey = bHeld;
        }
    }
    return 1;
}

// Maps one stick's -1..1 deflection onto a pair of joystick axes, applying the
// dead zone and rescaling what is left so the first movement outside the dead
// zone is a small push rather than a jump straight to dead-zone speed.
static void jkTouchControls_EmitStick(int axisX, int axisY, flex_t sx, flex_t sy)
{
    // Register and flag the axes on every read, not once at startup.
    // stdControl_Startup() memsets the whole stdControl_aAxes table, and
    // sithControl_DefaultInit() -> stdControl_Reset() clears the "has data" bit,
    // both of which can run after us (and again on every level load). A
    // registration done once is silently wiped, leaving fRangeConversion at 0 so
    // stdControl_ReadAxis() multiplies every deflection by zero -- sticks read as
    // dead while the buttons, which live in a different array, keep working.
    //
    // Dead zone multiplier is 0.0 rather than the 0.2 a real pad gets: the
    // rescale below already applies JKTOUCH_DEAD_ZONE, and stacking the engine's
    // dead zone on top of it would eat most of the usable travel.
    stdControl_RegisterAxis(axisX, -JKTOUCH_AXIS_MAX, JKTOUCH_AXIS_MAX, 0.0);
    stdControl_RegisterAxis(axisY, -JKTOUCH_AXIS_MAX, JKTOUCH_AXIS_MAX, 0.0);
    stdControl_aAxes[axisX].flags |= 2;
    stdControl_aAxes[axisY].flags |= 2;

    flex_t mag = stdMath_Sqrt((sx * sx) + (sy * sy));
    if (mag <= JKTOUCH_DEAD_ZONE) {
        stdControl_aAxisStates[axisX] = 0;
        stdControl_aAxisStates[axisY] = 0;
        return;
    }

    flex_t scaled = (mag - JKTOUCH_DEAD_ZONE) / (1.0f - JKTOUCH_DEAD_ZONE);
    if (scaled > 1.0f) {
        scaled = 1.0f;
    }
    flex_t norm = scaled / mag;

    stdControl_aAxisStates[axisX] = (int)(sx * norm * (flex_t)JKTOUCH_AXIS_MAX);
    stdControl_aAxisStates[axisY] = (int)(sy * norm * (flex_t)JKTOUCH_AXIS_MAX);
    stdControl_bControlsIdle = 0;
}

void jkTouchControls_ReadControls(void)
{
    if (!jkTouchControls_IsActive()) {
        return;
    }

    // Force the "disable joystick" option off while the pad is driving.
    //
    // sithWeapon_controlOptions bit 0x20 is the Joystick menu's "disable
    // joystick" checkbox, and sithControl_ReadControls() uses it to drop every
    // binding whose control id is >= JK_EXTENDED_KEY_START (sithControl.c:734)
    // and every non-mouse axis (:775). A profile carried over from a desktop
    // install very often has it set -- ours arrived as flags=24 -- which
    // silently discards everything the on-screen pad reports while leaving
    // keyboard bindings working, so the pad looks completely dead.
    //
    // On a touch-only device the virtual pad IS the input device, so the option
    // cannot be allowed to switch it off. Re-applied every read because
    // sithControl_ReadConf() can reload the profile at any level load.
    sithWeapon_controlOptions &= ~0x20;

    // Report every button's CURRENT state, including the released ones.
    // stdControl_ReadControls() clears aKeyPressed/aKeyIdleTimes each frame but
    // deliberately does NOT clear aKeyInfo -- that is the "still held" latch,
    // and it is only cleared by an explicit UpdateKeyState(..., 0, ...). Only
    // reporting presses therefore latches a button down permanently, so it
    // fires once and then appears stuck forever. stdControl_ReadGamepad() does
    // the same unconditional per-frame report for real pads.
    for (int i = 0; i < JKTOUCH_MAX_BUTTONS; i++)
    {
        stdControl_UpdateKeyState(jkTouchControls_aButtons[i].controlId,
                                  jkTouchControls_aButtonHeld[i], stdControl_curReadTime);
        if (jkTouchControls_aButtonHeld[i]) {
            stdControl_bControlsIdle = 0;
        }
    }

    // Left stick -> strafe/forward, right stick -> turn/pitch, matching
    // sithControl_MapDefaultsJoystick(). SDL's sign convention (+Y is down) is
    // preserved so the stock bindings and inversion settings apply unchanged.
    jkTouchControls_EmitStick(AXIS_JOY1_X, AXIS_JOY1_Y,
                              jkTouchControls_lStickX, jkTouchControls_lStickY);
    jkTouchControls_EmitStick(AXIS_JOY1_Z, AXIS_JOY1_R,
                              jkTouchControls_rStickX, jkTouchControls_rStickY);
}

void jkTouchControls_Render(void)
{
    if (!jkTouchControls_bInitted) {
        return;
    }

    // Recomputed every frame: a gamepad can be plugged in or pulled at any
    // point, and the answer has to survive a level load either way.
    int bShouldShow = !jkTouchControls_HasGamepad() && !jkTouchControls_bHiddenByPhysical;

    if (jkTouchControls_bShown && !bShouldShow) {
        jkTouchControls_ReleaseAll();
    }

    jkTouchControls_bShown = bShouldShow;

    // Stamped even when hidden: this is the "the world is being drawn" signal
    // that IsActive() keys off, and it must not be confused with being in a menu.
    jkTouchControls_lastRenderMs = stdPlatform_GetTimeMsec();

    if (!bShouldShow) {
        return;
    }

    jkTouchControls_UpdateScreenSize();

    jkTouchControls_DrawStick(0, jkTouchControls_lStickX, jkTouchControls_lStickY);
    jkTouchControls_DrawStick(1, jkTouchControls_rStickX, jkTouchControls_rStickY);

    for (int i = 0; i < JKTOUCH_MAX_BUTTONS; i++)
    {
        flex_t cx, cy, r;
        jkTouchControls_ButtonRect(&jkTouchControls_aButtons[i], &cx, &cy, &r);

        const jkTouchButton* pBtn = &jkTouchControls_aButtons[i];
        uint8_t alpha = jkTouchControls_aButtonHeld[i] ? 0xE0 : 0x88;

        jkTouchControls_FillCircle(cx, cy, r, pBtn->r, pBtn->g, pBtn->b, alpha);
    }
}

#endif // JK_HAS_TOUCH_CONTROLS
