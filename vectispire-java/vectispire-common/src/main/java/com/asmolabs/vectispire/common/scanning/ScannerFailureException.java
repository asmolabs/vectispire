package com.asmolabs.vectispire.common.scanning;

import java.time.Duration;

/** A scanner that did not produce a usable result. */
public class ScannerFailureException extends RuntimeException {

    private final String label;

    ScannerFailureException(String label, String message) {
        super(message);
        this.label = label;
    }

    public String label() {
        return label;
    }

    /** A failure the scanner's own output does not explain. */
    public static ScannerFailureException of(String label, String message) {
        return new ScannerFailureException(label, message);
    }

    /** The scanner ran too long and was stopped. */
    public static ScannerFailureException timedOut(String label, Duration timeout) {
        return new ScannerFailureException(
                label, "Scanner \"" + label + "\" exceeded " + timeout.toSeconds() + "s and was stopped.");
    }

    /**
     * The scanner exited on an unexpected code.
     *
     * <p>Its own output is included: without it the operator reads "the scanner failed" and has
     * to guess. Truncated, because a verbose checker produces thousands of lines of which only
     * the first carry the cause.
     */
    public static ScannerFailureException exited(String label, int exitCode, String stderr) {
        String output = stderr == null ? "" : stderr.strip();
        return new ScannerFailureException(
                label,
                "Scanner \"" + label + "\" exited with " + exitCode + ". "
                        + (output.length() <= 2000 ? output : output.substring(0, 2000)));
    }
}
