#include "SDL_fix.h"

#import <Cocoa/Cocoa.h>
#include <SDL.h>

// This is all lifted from SDL headers for now
// In short, there's a bug on macOS where the cursor jumps to the top-left corner
// on clicking the window, and the fix is setting pendingWindowWarpX/Y to INT_MAX.
//
// This code is just here until a PR gets merged

typedef struct SDL_WindowData SDL_WindowData;

typedef enum
{
    PENDING_OPERATION_NONE,
    PENDING_OPERATION_ENTER_FULLSCREEN,
    PENDING_OPERATION_LEAVE_FULLSCREEN,
    PENDING_OPERATION_MINIMIZE
} PendingWindowOperation;

@interface Cocoa_WindowListener : NSResponder <NSWindowDelegate> {
    SDL_WindowData *_data;
    BOOL observingVisible;
    BOOL wasCtrlLeft;
    BOOL wasVisible;
    BOOL isFullscreenSpace;
    BOOL inFullscreenTransition;
    PendingWindowOperation pendingWindowOperation;
    BOOL isMoving;
    NSInteger focusClickPending;
    int pendingWindowWarpX, pendingWindowWarpY;
    BOOL isDragAreaRunning;
}
-(void) listen:(SDL_WindowData *) data;
-(void) pauseVisibleObservation;
-(void) resumeVisibleObservation;
-(BOOL) setFullscreenSpace:(BOOL) state;
-(BOOL) isInFullscreenSpace;
-(BOOL) isInFullscreenSpaceTransition;
-(void) addPendingWindowOperation:(PendingWindowOperation) operation;
-(void) close;

-(BOOL) isMoving;
-(BOOL) isMovingOrFocusClickPending;
-(void) setFocusClickPending:(NSInteger) button;
-(void) clearFocusClickPending:(NSInteger) button;
-(void) setPendingMoveX:(int)x Y:(int)y;
-(void) windowDidFinishMoving;
-(void) onMovingOrFocusClickPendingStateCleared;

/* Window delegate functionality */
-(BOOL) windowShouldClose:(id) sender;
-(void) windowDidExpose:(NSNotification *) aNotification;
-(void) windowDidMove:(NSNotification *) aNotification;
-(void) windowDidResize:(NSNotification *) aNotification;
-(void) windowDidMiniaturize:(NSNotification *) aNotification;
-(void) windowDidDeminiaturize:(NSNotification *) aNotification;
-(void) windowDidBecomeKey:(NSNotification *) aNotification;
-(void) windowDidResignKey:(NSNotification *) aNotification;
-(void) windowDidChangeBackingProperties:(NSNotification *) aNotification;
-(void) windowDidChangeScreenProfile:(NSNotification *) aNotification;
-(void) windowWillEnterFullScreen:(NSNotification *) aNotification;
-(void) windowDidEnterFullScreen:(NSNotification *) aNotification;
-(void) windowWillExitFullScreen:(NSNotification *) aNotification;
-(void) windowDidExitFullScreen:(NSNotification *) aNotification;
-(NSApplicationPresentationOptions)window:(NSWindow *)window willUseFullScreenPresentationOptions:(NSApplicationPresentationOptions)proposedOptions;

/* See if event is in a drag area, toggle on window dragging. */
-(BOOL) processHitTest:(NSEvent *)theEvent;

/* Window event handling */
-(void) mouseDown:(NSEvent *) theEvent;
-(void) rightMouseDown:(NSEvent *) theEvent;
-(void) otherMouseDown:(NSEvent *) theEvent;
-(void) mouseUp:(NSEvent *) theEvent;
-(void) rightMouseUp:(NSEvent *) theEvent;
-(void) otherMouseUp:(NSEvent *) theEvent;
-(void) mouseMoved:(NSEvent *) theEvent;
-(void) mouseDragged:(NSEvent *) theEvent;
-(void) rightMouseDragged:(NSEvent *) theEvent;
-(void) otherMouseDragged:(NSEvent *) theEvent;
-(void) scrollWheel:(NSEvent *) theEvent;
-(void) touchesBeganWithEvent:(NSEvent *) theEvent;
-(void) touchesMovedWithEvent:(NSEvent *) theEvent;
-(void) touchesEndedWithEvent:(NSEvent *) theEvent;
-(void) touchesCancelledWithEvent:(NSEvent *) theEvent;

/* Touch event handling */
-(void) handleTouches:(NSTouchPhase) phase withEvent:(NSEvent*) theEvent;

@end

struct SDL_WindowData
{
    SDL_Window *window;
    NSWindow *nswindow;
    NSView *sdlContentView;
    NSMutableArray *nscontexts;
    SDL_bool created;
    SDL_bool inWindowFullscreenTransition;
    NSInteger flash_request;
    Cocoa_WindowListener *listener;
    struct SDL_VideoData *videodata;
};

/* Define the SDL window structure, corresponding to toplevel windows */
struct SDL_Window
{
    const void *magic;
    Uint32 id;
    char *title;
    SDL_Surface *icon;
    int x, y;
    int w, h;
    int min_w, min_h;
    int max_w, max_h;
    Uint32 flags;
    Uint32 last_fullscreen_flags;
    Uint32 display_index;

    /* Stored position and size for windowed mode */
    SDL_Rect windowed;

    SDL_DisplayMode fullscreen_mode;

    float opacity;

    float brightness;
    Uint16 *gamma;
    Uint16 *saved_gamma;        /* (just offset into gamma) */

    SDL_Surface *surface;
    SDL_bool surface_valid;

    SDL_bool is_hiding;
    SDL_bool is_destroying;
    SDL_bool is_dropping;       /* drag/drop in progress, expecting SDL_SendDropComplete(). */

    SDL_Rect mouse_rect;

    void *shaper;

    SDL_HitTest hit_test;
    void *hit_test_data;

    void *data;

    void *driverdata;

    SDL_Window *prev;
    SDL_Window *next;
};

void SDL_FixWindowMacOS(SDL_Window* window)
{
    SDL_WindowData *data = (SDL_WindowData *) window->driverdata;
    Cocoa_WindowListener *listener = data->listener;
    [data->listener setPendingMoveX:INT_MAX Y:INT_MAX];
}