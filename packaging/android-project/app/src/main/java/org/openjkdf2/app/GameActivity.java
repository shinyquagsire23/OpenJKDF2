package org.openjkdf2.app;

import android.app.Activity;
import android.content.Intent;
import android.view.MotionEvent;

import org.libsdl.app.SDLControllerManager;

import java.util.Hashtable;
import java.util.Locale;
import org.libsdl.app.SDLActivity;

/**
    SDL Activity
*/
public class GameActivity extends SDLActivity {

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (InstallHelperSAF.onActivityResult(requestCode, resultCode, data)) {
            return;
        }
        super.onActivityResult(requestCode, resultCode, data);
    }

    // Added: fallback joystick-motion dispatch. SDL's generic-motion listener lives on
    // SDLSurface only; while the text-input dummy view (SDLDummyEdit) holds window focus
    // (every on-screen keyboard session, e.g. the save-game name box), motion events are
    // delivered to that view instead and die there -- gamepad axes freeze at their last
    // value while button key-events (activity-dispatched) keep working. This fallback
    // only runs when the view chain did not consume the event.
    @Override
    public boolean onGenericMotionEvent(MotionEvent event) {
        if (event.getSource() == android.view.InputDevice.SOURCE_JOYSTICK) {
            if (SDLControllerManager.handleJoystickMotionEvent(event)) {
                return true;
            }
        }
        return super.onGenericMotionEvent(event);
    }
}
