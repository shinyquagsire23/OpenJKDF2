package org.openjkdf2.app;

/**
    SDL Activity for MoTS. Runs in its own process (":mots", see
    AndroidManifest.xml) because SDL only supports one instance per
    process, and with its own taskAffinity so it appears as a separate
    entry in the recents picker that can be closed independently.
*/
public class MotsActivity extends GameActivity {

    @Override
    protected String[] getArguments() {
        return new String[] { "-motsCompat" };
    }
}
