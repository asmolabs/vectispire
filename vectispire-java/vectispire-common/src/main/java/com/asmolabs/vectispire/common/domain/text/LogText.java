package com.asmolabs.vectispire.common.domain.text;

/**
 * A value from outside, made fit for one line of a log.
 *
 * <p>A log line is read by people and by parsers that split on line breaks. A value an external party
 * chose — a tracker's ticket key, a header — written as it is can carry a line break and a forged
 * second entry after it ({@code 2026-09-26 … INFO … admin signed in}), or terminal escape sequences
 * that rewrite what an operator's console shows. Control characters and the Unicode line and
 * paragraph separators are written as {@code \\uXXXX}, visibly, rather than dropped: the entry still
 * says something odd was sent, and it cannot say anything else. Bounded, because a log is not where a
 * megabyte of somebody's payload should land.
 */
public final class LogText {

    private LogText() {}

    /** Longer than any identifier worth logging, and short enough to keep a line a line. */
    public static final int MAX = 200;

    public static String of(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder safe = new StringBuilder(Math.min(value.length(), MAX) + 16);
        for (int index = 0; index < value.length(); index++) {
            if (safe.length() >= MAX) {
                safe.append("…(").append(value.length()).append(" chars)");
                break;
            }
            char c = value.charAt(index);
            if (Character.isISOControl(c) || c == '\u2028' || c == '\u2029') {
                safe.append(String.format("\\u%04x", (int) c));
            } else {
                safe.append(c);
            }
        }
        return safe.toString();
    }
}
