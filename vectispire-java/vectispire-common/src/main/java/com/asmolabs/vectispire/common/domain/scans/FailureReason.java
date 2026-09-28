package com.asmolabs.vectispire.common.domain.scans;

import java.util.Collection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Why a scan could not run, made fit to leave the machine that ran it and to be shown on the scans
 * screen.
 *
 * <p><b>Written by an agent, stored by the control plane, read by every account that sees the
 * target.</b> The text is an exception's message — a clone refused, a workspace that could not be
 * made, a sealed credential that would not open — and such a message may quote what the failing code
 * held: a URL with a token in its user part, a line of a private key JGit could not parse, the
 * bearer token of a request that failed. The built-in worker's reason never leaves the control plane
 * and reaches only the scan's own row; an agent's crosses a network and lands in the same column, so
 * it is scrubbed on both sides — by the agent, which knows the secrets it was handed and removes them
 * by value, and by the control plane, which knows none of them and removes what has their shape.
 *
 * <p><b>Scrubbed, never refused.</b> A report is the only way the operator learns why the scan did
 * not run; refusing one over its wording would put back the silence it exists to end.
 */
public final class FailureReason {

    /**
     * Past this the reason is cut. Well under the scan's {@code error} column, which leaves room for
     * the sentence the control plane puts round it (which attempt, which agent, what happens next).
     */
    public static final int MAX_LENGTH = 1_000;

    /** What a secret is replaced with — the mask {@code RepositoryUrl.redact} already shows. */
    static final String MASK = "***";

    /** Shorter than this, a "secret" would mask ordinary words of the message. */
    private static final int MIN_SECRET_LENGTH = 6;

    private static final Pattern PEM_BLOCK = Pattern.compile(
            "-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|\\z)", Pattern.DOTALL);

    private static final Pattern USER_INFO = Pattern.compile("(?i)\\b([a-z][a-z0-9+.-]*://)([^\\s/@]+)@");

    private static final Pattern SEALED = Pattern.compile("sealed:v1:[A-Za-z0-9+/=]+");

    private static final Pattern BEARER = Pattern.compile("(?i)\\b(bearer\\s+)[A-Za-z0-9._~+/=-]+");

    private static final Pattern ASSIGNMENT = Pattern.compile(
            "(?i)\\b(token|password|passwd|secret|api[_-]?key|private[_-]?key)(\\s*[=:]\\s*)[^\\s,;&\"']+");

    private FailureReason() {}

    /**
     * The reason, scrubbed and bounded.
     *
     * @param secrets values this side knows to be secret — a task's deployment key or HTTPS token,
     *     the agent's own API key — removed wherever they appear, a multi-line key line by line too
     * @return never null; empty when there was nothing to say
     */
    public static String scrub(String raw, Collection<String> secrets) {
        if (raw == null || raw.isBlank()) {
            return "";
        }
        String text = raw;
        for (String secret : secrets) {
            text = without(text, secret);
        }
        text = PEM_BLOCK.matcher(text).replaceAll("[private key removed]");
        text = SEALED.matcher(text).replaceAll("sealed:v1:" + MASK);
        text = BEARER.matcher(text).replaceAll("$1" + MASK);
        text = ASSIGNMENT.matcher(text).replaceAll("$1$2" + MASK);
        text = maskUserInfo(text);
        // Last, so a secret spread over lines was removed while its lines still were lines. A line
        // break in a reason is a forged second line on the screen and in the agent's log alike.
        text = text.replaceAll("[\\p{Cntrl}\\u2028\\u2029]+", " ").replaceAll(" {2,}", " ").trim();
        return bounded(text);
    }

    /** The same, for a side that holds no secret of its own — the control plane reading a report. */
    public static String scrub(String raw) {
        return scrub(raw, java.util.List.of());
    }

    private static String without(String text, String secret) {
        if (secret == null || secret.isBlank()) {
            return text;
        }
        String trimmed = secret.trim();
        String result = trimmed.length() >= MIN_SECRET_LENGTH ? text.replace(trimmed, MASK) : text;
        // A key is quoted a line at a time as often as whole: a parser names the line it choked on.
        for (String line : trimmed.split("\\R")) {
            String part = line.trim();
            if (part.length() >= MIN_SECRET_LENGTH && !part.startsWith("-----")) {
                result = result.replace(part, MASK);
            }
        }
        return result;
    }

    /**
     * Masks the user part of every URL in the text, as {@code RepositoryUrl.redact} does for one:
     * over HTTPS any user part may be a token, while {@code ssh://git@host} names a login and keeps
     * it.
     */
    private static String maskUserInfo(String text) {
        Matcher matcher = USER_INFO.matcher(text);
        StringBuilder out = new StringBuilder();
        while (matcher.find()) {
            boolean sshLogin = matcher.group(1).equalsIgnoreCase("ssh://") && !matcher.group(2).contains(":");
            String replacement = sshLogin ? matcher.group() : matcher.group(1) + MASK + "@";
            matcher.appendReplacement(out, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(out);
        return out.toString();
    }

    private static String bounded(String text) {
        if (text.length() <= MAX_LENGTH) {
            return text;
        }
        int end = MAX_LENGTH - 1;
        if (Character.isHighSurrogate(text.charAt(end - 1))) {
            end--;
        }
        return text.substring(0, end) + "…";
    }
}
