package com.asmolabs.vectispire.common.domain.auth;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * A page of this application to come back to after signing in, and nothing else.
 *
 * <p><b>The value arrives in a URL anybody can write</b> — a link mailed to a colleague — and ends
 * in a {@code Location} header, so every form a browser would follow off this origin is an open
 * redirect with Vectispire's name on the sign-in page before it. A browser reads {@code //host}
 * and {@code /\host} as protocol-relative, strips tabs and newlines before parsing, and a server
 * or proxy on the way may decode {@code %2F%2Fhost} into {@code //host}. Hence an allow-list of
 * shape rather than a deny-list of hosts: one leading slash, printable ASCII, no backslash, no dot
 * segment, bounded — and every percent-decoding of it held to the same rules, so an encoding
 * cannot smuggle through what the plain form would have been refused for.
 *
 * <p>The sign-in page itself and {@code /} are refused too: returning to the first loops, and the
 * second has nothing to remember. This mirrors {@code safeReturnUrl} in the interface's guard, which
 * applies the same rule to the password sign-in, the one path that never reaches the server.
 */
public record ReturnPath(String value) {

    /** Far above any route of the interface with its query, far below a header a proxy refuses. */
    public static final int MAX_LENGTH = 1024;

    /** Beyond this many layers of percent-encoding nobody legitimate is writing the link. */
    private static final int MAX_DECODINGS = 3;

    public ReturnPath {
        if (!acceptable(value)) {
            throw new InvalidInputException("not a return path of this application");
        }
    }

    /** The candidate when it is one of this application's pages, empty for anything else. */
    public static Optional<ReturnPath> parse(String candidate) {
        return acceptable(candidate) ? Optional.of(new ReturnPath(candidate)) : Optional.empty();
    }

    private static boolean acceptable(String candidate) {
        if (candidate == null || candidate.isEmpty() || candidate.length() > MAX_LENGTH) {
            return false;
        }
        for (int i = 0; i < candidate.length(); i++) {
            char c = candidate.charAt(i);
            // Printable ASCII only: whitespace and control characters are removed by a browser
            // before it parses (`/\t/evil` is `//evil`), and non-ASCII has no place in a route.
            if (c <= 0x20 || c >= 0x7f) {
                return false;
            }
        }
        String form = candidate;
        for (int round = 0; ; round++) {
            if (!sameOriginPath(form)) {
                return false;
            }
            Optional<String> decoded = percentDecoded(form);
            if (decoded.isEmpty()) {
                return false;
            }
            if (decoded.get().equals(form)) {
                break;
            }
            if (round == MAX_DECODINGS) {
                return false;
            }
            form = decoded.get();
        }
        return true;
    }

    private static boolean sameOriginPath(String form) {
        if (form.length() < 2 || form.charAt(0) != '/' || form.charAt(1) == '/') {
            return false;
        }
        for (int i = 0; i < form.length(); i++) {
            char c = form.charAt(i);
            if (c == '\\' || c < 0x20 || c == 0x7f) {
                return false;
            }
        }
        int end = form.length();
        for (char stop : new char[] {'?', '#'}) {
            int at = form.indexOf(stop);
            if (at >= 0 && at < end) {
                end = at;
            }
        }
        String path = form.substring(0, end);
        if (path.equals("/") || path.equals("/login") || path.startsWith("/login/")) {
            return false;
        }
        // A dot segment is resolved by the browser before the router sees it — `/a/..//evil`
        // becomes `//evil` — so a path that needs one is not a path anybody bookmarked.
        for (String segment : path.substring(1).split("/", -1)) {
            if (segment.equals(".") || segment.equals("..")) {
                return false;
            }
        }
        return true;
    }

    /** One round of percent-decoding, empty when an escape is malformed. {@code +} stays itself. */
    private static Optional<String> percentDecoded(String form) {
        if (form.indexOf('%') < 0) {
            return Optional.of(form);
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(form.length());
        for (int i = 0; i < form.length(); i++) {
            char c = form.charAt(i);
            if (c != '%') {
                bytes.write(c);
                continue;
            }
            if (i + 2 >= form.length()) {
                return Optional.empty();
            }
            int high = Character.digit(form.charAt(i + 1), 16);
            int low = Character.digit(form.charAt(i + 2), 16);
            if (high < 0 || low < 0) {
                return Optional.empty();
            }
            bytes.write(high << 4 | low);
            i += 2;
        }
        return Optional.of(bytes.toString(StandardCharsets.UTF_8));
    }
}
