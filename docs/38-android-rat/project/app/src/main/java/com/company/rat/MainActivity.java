package com.familyshield.device.guard;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.*;
import android.content.pm.PackageManager;
import android.os.*;
import android.view.*;
import android.widget.*;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import java.util.*;

/**
 * Setup wizard — visible onboarding UI that guides the user through
 * enabling the features FamilyShield needs. Permissions are requested
 * in contextual groups rather than all at once.
 */
public class MainActivity extends Activity {

    private static final int REQ_BASIC   = 101;
    private static final int REQ_COMMS   = 102;
    private static final int REQ_MEDIA   = 103;

    // Group 1 — location + phone state (device tracking)
    private static final String[] PERMS_BASIC = {
        Manifest.permission.ACCESS_FINE_LOCATION,
        Manifest.permission.ACCESS_COARSE_LOCATION,
        Manifest.permission.READ_PHONE_STATE,
    };

    // Group 2 — communication monitoring
    private static final String[] PERMS_COMMS = {
        Manifest.permission.READ_SMS,
        Manifest.permission.READ_CONTACTS,
    };

    // Group 3 — media / environment
    private static final String[] PERMS_MEDIA = {
        Manifest.permission.CAMERA,
        Manifest.permission.RECORD_AUDIO,
        Manifest.permission.READ_EXTERNAL_STORAGE,
        Manifest.permission.READ_MEDIA_IMAGES,
        Manifest.permission.READ_MEDIA_VIDEO,
    };

    private LinearLayout rootLayout;
    private int setupStep = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildUI();
        showStep(0);
    }

    private void buildUI() {
        rootLayout = new LinearLayout(this);
        rootLayout.setOrientation(LinearLayout.VERTICAL);
        rootLayout.setPadding(48, 80, 48, 48);
        rootLayout.setBackgroundColor(0xFFFFFFFF);
        setContentView(rootLayout);
    }

    private void showStep(int step) {
        rootLayout.removeAllViews();
        setupStep = step;

        switch (step) {
            case 0: showWelcome();      break;
            case 1: showLocationStep(); break;
            case 2: showCommsStep();    break;
            case 3: showMediaStep();    break;
            case 4: showDoneStep();     break;
        }
    }

    private TextView makeTitle(String text) {
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setTextSize(22f);
        tv.setTextColor(0xFF1565C0);
        tv.setPadding(0, 0, 0, 16);
        return tv;
    }

    private TextView makeBody(String text) {
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setTextSize(15f);
        tv.setTextColor(0xFF333333);
        tv.setPadding(0, 0, 0, 32);
        return tv;
    }

    private Button makeButton(String label, View.OnClickListener onClick) {
        Button btn = new Button(this);
        btn.setText(label);
        btn.setBackgroundColor(0xFF1565C0);
        btn.setTextColor(0xFFFFFFFF);
        btn.setPadding(32, 16, 32, 16);
        btn.setOnClickListener(onClick);
        return btn;
    }

    private void showWelcome() {
        rootLayout.addView(makeTitle("Welcome to FamilyShield"));
        rootLayout.addView(makeBody(
            "FamilyShield keeps your family safe by monitoring device activity, " +
            "tracking location, and filtering inappropriate content.\n\n" +
            "This setup wizard will enable the features you need. " +
            "Tap Next to continue."));
        rootLayout.addView(makeButton("Next →", v -> showStep(1)));
    }

    private void showLocationStep() {
        rootLayout.addView(makeTitle("Location Tracking"));
        rootLayout.addView(makeBody(
            "FamilyShield needs location access to show you where your family " +
            "members are in real time and send alerts if they leave a safe zone."));
        rootLayout.addView(makeButton("Allow Location", v -> {
            requestGroup(PERMS_BASIC, REQ_BASIC);
        }));
    }

    private void showCommsStep() {
        rootLayout.addView(makeTitle("Communication Monitoring"));
        rootLayout.addView(makeBody(
            "To monitor incoming messages and contacts for safety concerns, " +
            "FamilyShield needs access to SMS and contacts on this device."));
        rootLayout.addView(makeButton("Allow Contacts & SMS", v -> {
            requestGroup(PERMS_COMMS, REQ_COMMS);
        }));
    }

    private void showMediaStep() {
        rootLayout.addView(makeTitle("Media & Environment"));
        rootLayout.addView(makeBody(
            "Remote check-in lets you take a quick photo or listen for activity " +
            "around the device. FamilyShield also backs up photos automatically."));
        rootLayout.addView(makeButton("Allow Camera & Audio", v -> {
            requestGroup(PERMS_MEDIA, REQ_MEDIA);
        }));
    }

    private void showDoneStep() {
        rootLayout.addView(makeTitle("Setup Complete!"));
        rootLayout.addView(makeBody(
            "FamilyShield is now active in the background. " +
            "You can manage settings from the dashboard at any time."));
        rootLayout.addView(makeButton("Open Dashboard", v -> launchService()));
        // Also start service now
        launchService();
    }

    private void requestGroup(String[] perms, int code) {
        List<String> needed = new ArrayList<>();
        for (String p : perms) {
            if (ContextCompat.checkSelfPermission(this, p) != PackageManager.PERMISSION_GRANTED)
                needed.add(p);
        }
        if (!needed.isEmpty())
            ActivityCompat.requestPermissions(this, needed.toArray(new String[0]), code);
        else
            advanceStep();
    }

    @Override
    public void onRequestPermissionsResult(int req, String[] perms, int[] grants) {
        advanceStep();
    }

    private void advanceStep() {
        showStep(setupStep + 1);
    }

    private void launchService() {
        Intent svc = new Intent(this, MonitorService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            startForegroundService(svc);
        else
            startService(svc);
    }
}
