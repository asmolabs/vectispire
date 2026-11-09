package com.asmolabs.vectispire.core.threatintel;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Locale;
import java.util.zip.GZIPOutputStream;

/**
 * EPSS files as FIRST publishes them, for the tests that stand one in for the download: {@code rows}
 * CVE from {@code CVE-2020-0000} on, the n-th scored {@code (n + shift) / 1,000,000}, modulo one.
 */
public final class EpssFiles {

    private EpssFiles() {}

    /** A whole file of {@code rows} scores, gzip as published. */
    public static byte[] gzip(int rows, String model, Instant scoreDate, int shift) {
        return compress(text(rows, model, scoreDate, shift));
    }

    /** The score {@link #gzip} gives the n-th CVE. */
    public static double score(int row, int shift) {
        return Double.parseDouble(String.format(Locale.ROOT, "%.6f", (row + shift) / 1_000_000.0 % 1.0));
    }

    /** The n-th CVE's identifier. */
    public static String cve(int row) {
        return String.format(Locale.ROOT, "CVE-2020-%04d", row);
    }

    /** The same file, cut short: what a download that stopped half-way leaves. */
    public static byte[] truncated(byte[] whole) {
        return Arrays.copyOf(whole, whole.length / 2);
    }

    static String text(int rows, String model, Instant scoreDate, int shift) {
        StringBuilder file = new StringBuilder(rows * 32);
        file.append("#model_version:").append(model).append(",score_date:").append(scoreDate).append('\n');
        file.append("cve,epss,percentile\n");
        for (int row = 0; row < rows; row++) {
            String score = String.format(Locale.ROOT, "%.6f", score(row, shift));
            file.append(cve(row)).append(',').append(score).append(',').append(score).append('\n');
        }
        return file.toString();
    }

    static byte[] compress(String text) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
            gzip.write(text.getBytes(StandardCharsets.US_ASCII));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return out.toByteArray();
    }
}
