package org.openjkdf2.app;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.provider.DocumentsContract;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

/**
 * SAF-based folder picker + asset copier for the native install helper.
 * Android has no SDL3 folder dialog, so InstallHelper_AttemptInstallViaSAF()
 * (native) calls startInstall(), which lets the user pick a folder via
 * ACTION_OPEN_DOCUMENT_TREE; the given assets are then copied out of the
 * picked tree (content URIs can't be fopen()'d natively) into the app's
 * data dir. For each asset, the existing-install path is tried first, then
 * the install-disk (GAMEDATA/) path.
 */
public class InstallHelperSAF {
    private static final int REQUEST_CODE = 0x4A4B; // "JK"

    private static Activity pendingActivity;
    private static String pendingDestRoot;
    private static String[] pendingDst;
    private static String[] pendingSrcExisting;
    private static String[] pendingSrcDisk;
    private static ProgressDialog progress;

    // status: 1 = ok, -1 = cancel/error
    private static native void nativeInstallDone(int status);

    // Called from the native thread via JNI.
    public static void startInstall(final Activity activity, String destRoot, String[] dst, String[] srcExisting, String[] srcDisk) {
        pendingActivity = activity;
        pendingDestRoot = destRoot;
        pendingDst = dst;
        pendingSrcExisting = srcExisting;
        pendingSrcDisk = srcDisk;

        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
                intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                intent.addFlags(Intent.FLAG_GRANT_PREFIX_URI_PERMISSION);
                activity.startActivityForResult(intent, REQUEST_CODE);
            }
        });
    }

    // Returns true if the result was meant for us.
    public static boolean onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode != REQUEST_CODE) {
            return false;
        }

        final String destRoot = pendingDestRoot;
        final String[] dst = pendingDst;
        final String[] srcExisting = pendingSrcExisting;
        final String[] srcDisk = pendingSrcDisk;
        final Context ctx = pendingActivity;
        pendingActivity = null;
        pendingDestRoot = null;
        pendingDst = null;
        pendingSrcExisting = null;
        pendingSrcDisk = null;

        if (resultCode != Activity.RESULT_OK || data == null || data.getData() == null || dst == null) {
            nativeInstallDone(-1);
            return true;
        }

        final Uri treeUri = data.getData();

        progress = ProgressDialog.show(ctx, "OpenJKDF2 Install Helper", "Copying game assets...", true, false);

        new Thread(new Runnable() {
            @Override
            public void run() {
                int status = 1;
                try {
                    copyAssets(ctx, treeUri, destRoot, dst, srcExisting, srcDisk);
                } catch (Exception e) {
                    e.printStackTrace();
                    status = -1;
                }
                final int finalStatus = status;
                if (ctx instanceof Activity) {
                    ((Activity) ctx).runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            if (progress != null) {
                                progress.dismiss();
                                progress = null;
                            }
                        }
                    });
                }
                nativeInstallDone(finalStatus);
            }
        }).start();
        return true;
    }

    private static void copyAssets(Context ctx, Uri treeUri, String destRoot, String[] dst, String[] srcExisting, String[] srcDisk) throws Exception {
        ContentResolver resolver = ctx.getContentResolver();
        byte[] buf = new byte[65536];
        for (int i = 0; i < dst.length; i++) {
            Uri src = findInTree(resolver, treeUri, srcExisting[i]);
            if (src == null) {
                src = findInTree(resolver, treeUri, srcDisk[i]);
            }
            if (src == null) {
                continue; // missing assets are reported by the native side
            }

            File outFile = new File(destRoot, dst[i]);
            File parent = outFile.getParentFile();
            if (parent != null) {
                parent.mkdirs();
            }

            InputStream in = resolver.openInputStream(src);
            if (in == null) {
                continue;
            }
            FileOutputStream out = new FileOutputStream(outFile);
            try {
                int n;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                }
            } finally {
                try { in.close(); } catch (Exception ignored) {}
                try { out.close(); } catch (Exception ignored) {}
            }
        }
    }

    // Case-insensitive segment walk within a document tree.
    private static Uri findInTree(ContentResolver resolver, Uri treeUri, String relPath) {
        String[] segments = relPath.split("/");
        String docId = DocumentsContract.getTreeDocumentId(treeUri);
        for (int s = 0; s < segments.length; s++) {
            boolean wantDir = (s < segments.length - 1);
            docId = findChild(resolver, treeUri, docId, segments[s], wantDir);
            if (docId == null) {
                return null;
            }
        }
        return DocumentsContract.buildDocumentUriUsingTree(treeUri, docId);
    }

    private static String findChild(ContentResolver resolver, Uri treeUri, String parentDocId, String name, boolean wantDir) {
        Uri childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, parentDocId);
        Cursor c = null;
        try {
            c = resolver.query(childrenUri,
                    new String[]{
                            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                            DocumentsContract.Document.COLUMN_MIME_TYPE},
                    null, null, null);
            if (c == null) {
                return null;
            }
            while (c.moveToNext()) {
                if (!name.equalsIgnoreCase(c.getString(1))) {
                    continue;
                }
                boolean isDir = DocumentsContract.Document.MIME_TYPE_DIR.equals(c.getString(2));
                if (wantDir == isDir) {
                    return c.getString(0);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (c != null) {
                c.close();
            }
        }
        return null;
    }
}
