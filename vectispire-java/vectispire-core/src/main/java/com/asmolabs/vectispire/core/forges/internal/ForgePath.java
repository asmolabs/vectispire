package com.asmolabs.vectispire.core.forges.internal;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * One segment of a forge API path, built from a value the forge or a person supplied — a project's id or full
 * path, an owner, a repository's name, a branch, a merge request's number.
 *
 * <p><b>Every adapter builds its URLs through this</b>, because a value concatenated as it came changes which
 * endpoint is called: a {@code /} adds a segment, a {@code ?} or a {@code #} ends the path, a {@code %} is decoded
 * by the server into whatever follows it. The pager keeps a request on the API's origin and under its root, not on
 * the endpoint the adapter meant: {@code /projects/../user} stays under {@code /api/v4}.
 *
 * <p><b>Everything but RFC 3986's unreserved characters is percent-encoded</b>, the slash included — GitLab takes a
 * project's full path as one segment, {@code group%2Fproject}. {@link java.net.URLEncoder} was used before; it is a
 * form encoder, writes a space as {@code +} and leaves {@code *} alone, which a path does not read that way.
 *
 * <p><b>A segment that is only dots is refused, not encoded.</b> {@code .} and {@code ..} are dot segments a server
 * or a proxy in front of it removes, and {@code %2E%2E} is decoded into one by enough of them that encoding is no
 * defence (the pager refuses an encoded dot in a page it is pointed at, for the same reason). No forge names
 * anything that way — Git forbids {@code ..} in a ref, GitHub and GitLab in a name — so a value of that shape is
 * one the caller cannot use, and says so; an empty one too, which would join its neighbours.
 */
final class ForgePath {

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private ForgePath() {}

    /** {@code value} as one path segment, or empty when no segment can carry it: null, empty, {@code .}, {@code ..}. */
    static Optional<String> segment(String value) {
        if (value == null || value.isEmpty() || value.chars().allMatch(c -> c == '.')) {
            return Optional.empty();
        }
        StringBuilder encoded = new StringBuilder(value.length() + 8);
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '.' || c == '_' || c == '~') {
                encoded.append((char) c);
            } else {
                encoded.append('%').append(HEX[c >> 4]).append(HEX[c & 0xF]);
            }
        }
        return Optional.of(encoded.toString());
    }
}
