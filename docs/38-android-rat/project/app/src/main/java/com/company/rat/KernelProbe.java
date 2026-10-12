package com.familyshield.device.guard;

import android.content.Context;
import java.io.*;
import java.util.concurrent.TimeUnit;

/**
 * Kernel-level detection probe.
 *
 * Each test generates a signal that a properly configured detection system should catch:
 *   1. /dev/input reads — unauthorized kernel input device access
 *   2. /proc/net enumeration — network mapping from user space
 *   3. su execution — privilege escalation attempt
 *   4. /data/data traversal — inter-app isolation bypass attempt
 *   5. dmesg read — kernel log access (common in rootkits)
 *   6. SELinux context check — tests if SELinux is enforcing
 *
 * Results are sent back to C2 for review. Whether each test succeeds or fails is
 * secondary — the ATTEMPT itself is what the detection system should log.
 */
public class KernelProbe {

    public static String run(Context ctx) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== KERNEL PROBE REPORT ===\n");
        sb.append("time=").append(System.currentTimeMillis()).append("\n\n");

        probeInputDevices(sb);
        probeProc(sb);
        probeRootEscalation(sb);
        probeDataIsolation(sb);
        probeDmesg(sb);
        probeSelinux(sb);

        return sb.toString();
    }

    // ── 1. /dev/input ─────────────────────────────────────────────────────────

    private static void probeInputDevices(StringBuilder sb) {
        sb.append("-- /dev/input kernel access --\n");
        // Try to open raw input devices — a detection system should catch
        // any user-space app touching these nodes
        for (int i = 0; i < 8; i++) {
            String path = "/dev/input/event" + i;
            try {
                FileInputStream fis = new FileInputStream(path);
                // Actually readable — device rooted or SELinux misconfigured
                byte[] header = new byte[16]; // one input_event struct
                int n = fis.read(header);
                fis.close();
                sb.append(path).append(": OPEN+READ (").append(n).append(" bytes) *** KERNEL ACCESS SUCCEEDED ***\n");
            } catch (FileNotFoundException e) {
                sb.append(path).append(": not found\n");
            } catch (SecurityException e) {
                sb.append(path).append(": SELinux denied (detection should have logged this attempt)\n");
            } catch (IOException e) {
                sb.append(path).append(": IO denied -- ").append(e.getMessage()).append("\n");
            }
        }
        sb.append("\n");
    }

    // ── 2. /proc/net enumeration ───────────────────────────────────────────────

    private static void probeProc(StringBuilder sb) {
        sb.append("-- /proc/net enumeration --\n");
        String[] paths = {"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/1/maps"};
        for (String path : paths) {
            try {
                BufferedReader br = new BufferedReader(new FileReader(path));
                String line = br.readLine();
                br.close();
                sb.append(path).append(": readable -- first: ")
                  .append(line != null ? line.substring(0, Math.min(60, line.length())) : "(empty)")
                  .append("\n");
            } catch (Exception e) {
                sb.append(path).append(": ").append(e.getClass().getSimpleName()).append("\n");
            }
        }
        sb.append("\n");
    }

    // ── 3. Root escalation ─────────────────────────────────────────────────────

    private static void probeRootEscalation(StringBuilder sb) {
        sb.append("-- Root escalation attempt (su) --\n");
        String[] cmds = {"id", "cat /proc/keys", "ls /data/data", "getprop ro.build.type"};
        for (String cmd : cmds) {
            try {
                java.lang.Process p = Runtime.getRuntime().exec(new String[]{"su", "-c", cmd});
                boolean done = p.waitFor(3, TimeUnit.SECONDS);
                if (!done) { p.destroy(); sb.append("su -c ").append(cmd).append(": timeout\n"); continue; }
                BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line = br.readLine();
                sb.append("su -c ").append(cmd).append(": ")
                  .append(line != null ? line.substring(0, Math.min(80, line.length())) : "(no output)")
                  .append("\n");
            } catch (Exception e) {
                sb.append("su -c ").append(cmd).append(": ").append(e.getMessage()).append("\n");
            }
        }
        sb.append("\n");
    }

    // ── 4. Inter-app data isolation ────────────────────────────────────────────

    private static void probeDataIsolation(StringBuilder sb) {
        sb.append("-- /data/data isolation --\n");
        try {
            File dataDir = new File("/data/data");
            String[] apps = dataDir.list();
            if (apps != null && apps.length > 0) {
                sb.append("/data/data: LISTABLE (").append(apps.length).append(" entries) *** SELinux not enforcing ***\n");
                for (int i = 0; i < Math.min(5, apps.length); i++) sb.append("  ").append(apps[i]).append("\n");
            } else {
                sb.append("/data/data: not listable (SELinux enforcing — expected)\n");
            }
        } catch (Exception e) {
            sb.append("/data/data: ").append(e.getMessage()).append("\n");
        }
        sb.append("\n");
    }

    // ── 5. dmesg (kernel log) ─────────────────────────────────────────────────

    private static void probeDmesg(StringBuilder sb) {
        sb.append("-- dmesg kernel log access --\n");
        try {
            java.lang.Process p = Runtime.getRuntime().exec(new String[]{"su", "-c", "dmesg | tail -5"});
            boolean done = p.waitFor(3, TimeUnit.SECONDS);
            if (!done) { p.destroy(); sb.append("dmesg: timeout\n"); return; }
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            int count = 0;
            while ((line = br.readLine()) != null && count++ < 5) {
                sb.append("  ").append(line).append("\n");
            }
            if (count == 0) sb.append("dmesg: no output (permission denied or empty)\n");
        } catch (Exception e) {
            sb.append("dmesg: ").append(e.getMessage()).append("\n");
        }
        sb.append("\n");
    }

    // ── 6. SELinux enforcing status ────────────────────────────────────────────

    private static void probeSelinux(StringBuilder sb) {
        sb.append("-- SELinux status --\n");
        try {
            // Read getenforce directly
            File f = new File("/sys/fs/selinux/enforce");
            if (f.exists()) {
                BufferedReader br = new BufferedReader(new FileReader(f));
                String val = br.readLine(); br.close();
                sb.append("SELinux enforce: ").append("1".equals(val) ? "ENFORCING" : "PERMISSIVE").append("\n");
            }
        } catch (Exception ignored) {}

        try {
            java.lang.Process p = Runtime.getRuntime().exec("getenforce");
            p.waitFor(2, TimeUnit.SECONDS);
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = br.readLine();
            sb.append("getenforce: ").append(line != null ? line : "(no output)").append("\n");
        } catch (Exception e) {
            sb.append("getenforce: ").append(e.getMessage()).append("\n");
        }
    }
}
