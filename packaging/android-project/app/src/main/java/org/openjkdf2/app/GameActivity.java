package org.openjkdf2.app;

import android.app.Activity;
import android.content.Intent;

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
}

