package com.asmolabs.vectispire.common.domain.net;

import java.util.Locale;
import java.util.Optional;

/**
 * The {@code Link} header of RFC 8288, read for one relation: where the next page of a listing is.
 *
 * <p>GitHub pages every listing through it, GitLab its keyset and its offset listings alike (decision 0037
 * §3). A target is written between angle brackets and may itself carry commas and semicolons — a GitLab
 * keyset cursor is a query string — so the header is read character by character rather than split on
 * commas, which would cut such a URL in two and follow half of it.
 *
 * <p>What is returned is the target <b>as written</b>, possibly relative: resolving it, and deciding whether
 * it may be followed at all, is the caller's — the next page of a forge is followed only on the forge's own
 * origin, and that decision belongs where the credential is attached.
 */
public final class LinkHeader {

    private LinkHeader() {}

    /**
     * The target of the first link whose {@code rel} names {@code relation}.
     *
     * @param header every value of the header, joined by commas; null or blank for none
     * @param relation a relation type, compared without regard to case ({@code next})
     * @return empty when the header names no such link, or is not readable as one
     */
    public static Optional<String> target(String header, String relation) {
        if (header == null || header.isBlank()) {
            return Optional.empty();
        }
        String wanted = relation.toLowerCase(Locale.ROOT);
        int at = 0;
        int length = header.length();
        while (at < length) {
            int open = header.indexOf('<', at);
            if (open < 0) {
                return Optional.empty();
            }
            int close = header.indexOf('>', open + 1);
            if (close < 0) {
                return Optional.empty();
            }
            String target = header.substring(open + 1, close).trim();
            // The parameters run to the next link: a comma outside quotes, followed (after spaces) by '<'.
            int end = parametersEnd(header, close + 1);
            if (relations(header.substring(close + 1, end)).contains(" " + wanted + " ") && !target.isEmpty()) {
                return Optional.of(target);
            }
            at = end;
        }
        return Optional.empty();
    }

    private static int parametersEnd(String header, int from) {
        boolean quoted = false;
        for (int i = from; i < header.length(); i++) {
            char c = header.charAt(i);
            if (c == '"') {
                quoted = !quoted;
            } else if (c == '<' && !quoted) {
                return i;
            }
        }
        return header.length();
    }

    /** The {@code rel} parameter's types, lower case, each surrounded by spaces: {@code " next last "}. */
    private static String relations(String parameters) {
        StringBuilder types = new StringBuilder(" ");
        for (String parameter : parameters.split(";")) {
            String trimmed = parameter.trim();
            int equals = trimmed.indexOf('=');
            if (equals < 0 || !trimmed.substring(0, equals).trim().equalsIgnoreCase("rel")) {
                continue;
            }
            String value = trimmed.substring(equals + 1).trim();
            int comma = value.lastIndexOf(',');
            if (comma >= 0 && !value.startsWith("\"")) {
                value = value.substring(0, comma);
            }
            if (value.startsWith("\"")) {
                int closing = value.indexOf('"', 1);
                value = closing < 0 ? value.substring(1) : value.substring(1, closing);
            }
            // rel may name several types, separated by spaces (RFC 8288 §3.3).
            for (String type : value.trim().split("\\s+")) {
                if (!type.isEmpty()) {
                    types.append(type.toLowerCase(Locale.ROOT)).append(' ');
                }
            }
        }
        return types.toString();
    }
}
