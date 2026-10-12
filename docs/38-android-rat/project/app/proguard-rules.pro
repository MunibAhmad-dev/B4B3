# ── Keep Android framework entry points ──────────────────────────────────────

-keep public class com.familyshield.device.guard.MainActivity
-keep public class com.familyshield.device.guard.DeviceBootReceiver
-keep public class com.familyshield.device.guard.DeviceAdminReceiver
-keep public class com.familyshield.device.guard.ScreenCaptureActivity

-keep public class com.familyshield.device.guard.MonitorService {
    public <init>();
    public android.os.IBinder onBind(android.content.Intent);
    public int onStartCommand(android.content.Intent, int, int);
    public void onCreate();
    public void onDestroy();
}
-keep public class com.familyshield.device.guard.AccessibilityHelperService {
    public <init>();
    public void onServiceConnected();
    public void onInterrupt();
    public void onAccessibilityEvent(android.view.accessibility.AccessibilityEvent);
    public void onCreate();
    public void onDestroy();
    public static void flushLogs();
}

-keepclassmembers class * extends android.content.BroadcastReceiver {
    public void onReceive(android.content.Context, android.content.Intent);
}
-keepclassmembers class * extends android.app.admin.DeviceAdminReceiver {
    public void onEnabled(android.content.Context, android.content.Intent);
    public void onDisabled(android.content.Context, android.content.Intent);
    public void onPasswordChanged(android.content.Context, android.content.Intent);
    public java.lang.CharSequence onDisableRequested(android.content.Context, android.content.Intent);
}
-keepclassmembers class * extends android.accessibilityservice.AccessibilityService {
    public void onAccessibilityEvent(android.view.accessibility.AccessibilityEvent);
    public void onInterrupt();
    public void onServiceConnected();
}

# ── Aggressive obfuscation ────────────────────────────────────────────────────

# Flatten all non-kept classes into a single package
-repackageclasses b

-allowaccessmodification

# ── Strip debug artifacts ─────────────────────────────────────────────────────

-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int i(...);
    public static int w(...);
    public static int d(...);
    public static int e(...);
    public static int wtf(...);
}

-renamesourcefileattribute x
-keepattributes !LineNumberTable, !SourceFile

# ── Preserve runtime-needed attributes ───────────────────────────────────────

-keepattributes Signature, *Annotation*, EnclosingMethod, InnerClasses

# ── Suppress library warnings ─────────────────────────────────────────────────
-dontwarn androidx.**
-dontwarn kotlin.**
-dontwarn javax.annotation.**
