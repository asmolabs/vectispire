package com.asmolabs.vectispire.common.domain.sarif;

import java.io.ByteArrayOutputStream;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * A SARIF artifact location, as the path an issue is fingerprinted on.
 *
 * <h2>This is a data contract</h2>
 *
 * <p>The path this returns enters the fingerprint of every plugin and imported issue. Changing any
 * rule below resolves every such issue and recreates it, triage lost, across every target. The
 * rules, in order:
 *
 * <ol>
 *   <li>{@code %XX} escapes are decoded as UTF-8 — SARIF carries URI references, and
 *       {@code src/My%20File.java} is the file {@code src/My File.java}. {@code +} is a plus;
 *   <li>a backslash is a separator, since Windows tools emit them;
 *   <li>{@code file:} is stripped; any other scheme is refused ({@link #REFUSED_LINK});
 *   <li>an absolute path must lie under one of the roots the caller knows — the container's
 *       {@code /repo/source} for a plugin, none for an import — and the root is removed;
 *   <li>empty and {@code .} segments are dropped; the segments are joined with {@code /}, with no
 *       leading or trailing slash.
 * </ol>
 *
 * <h2>No link leaves the analysed tree</h2>
 *
 * <p>A location naming {@code https://…}, a {@code file:} path outside the known roots, or a
 * {@code ..} segment is refused, and with it the whole document: the finding would describe
 * something that is not in the tree Vectispire knows, under a name somebody chose. Refusing one
 * result and keeping the rest would make "the rest" read as the complete report, which is the
 * shorter list decision 0007 is about. A NUL or any other control character is refused too — NUL
 * is the fingerprint's field separator.
 */
public final class SarifPaths {

    static final String REFUSED_LINK = "names a location outside the analysed tree";

    private SarifPaths() {}

    /**
     * The location as a path inside the analysed tree.
     *
     * <p>A relative {@code uri} is relative to the analysed tree, with or without a {@code uriBaseId}:
     * the base's own value is where the producer's checkout was, which is exactly the part that
     * differs between producers, so it is never read.
     *
     * @param uri the artifact location's {@code uri}
     * @param absoluteRoots the absolute directories that stand for the analysed tree, without a
     *     trailing slash
     * @return the normalised relative path, or {@code null} for a location that names no file
     */
    public static String normalize(String uri, List<String> absoluteRoots) {
        if (uri == null || uri.isBlank()) {
            return null;
        }
        String decoded = decode(uri.strip()).replace('\\', '/');
        refuseControls(decoded);

        String path = decoded;
        int colon = schemeEnd(path);
        if (colon > 0) {
            String scheme = path.substring(0, colon).toLowerCase(java.util.Locale.ROOT);
            if (!scheme.equals("file")) {
                throw new InvalidSarifException("A result " + REFUSED_LINK + ": " + shorten(uri) + ".");
            }
            path = path.substring(colon + 1);
            if (path.startsWith("//")) {
                // `file://host/path`: only an empty host names this machine's path.
                int slash = path.indexOf('/', 2);
                String host = slash < 0 ? path.substring(2) : path.substring(2, slash);
                if (!host.isEmpty() && !host.equalsIgnoreCase("localhost")) {
                    throw new InvalidSarifException("A result " + REFUSED_LINK + ": " + shorten(uri) + ".");
                }
                path = slash < 0 ? "/" : path.substring(slash);
            }
        }

        if (path.startsWith("/")) {
            path = underARoot(path, absoluteRoots, uri);
        }

        List<String> kept = new ArrayList<>();
        for (String segment : path.split("/", -1)) {
            if (segment.isEmpty() || segment.equals(".")) {
                continue;
            }
            if (segment.equals("..")) {
                throw new InvalidSarifException("A result " + REFUSED_LINK + " (a \"..\" segment): " + shorten(uri) + ".");
            }
            kept.add(segment);
        }
        return kept.isEmpty() ? null : String.join("/", kept);
    }

    private static String underARoot(String absolute, List<String> roots, String uri) {
        for (String root : roots == null ? List.<String>of() : roots) {
            if (absolute.equals(root)) {
                return "";
            }
            if (absolute.startsWith(root + "/")) {
                return absolute.substring(root.length() + 1);
            }
        }
        throw new InvalidSarifException("A result " + REFUSED_LINK + " (an absolute path): " + shorten(uri)
                + ". Report paths relative to the analysed directory.");
    }

    /** The index of a URI scheme's colon, or -1: letters first, then letters, digits, {@code + - .}. */
    private static int schemeEnd(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == ':') {
                return i;
            }
            boolean letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
            boolean allowed = letter || (i > 0 && ((c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.'));
            if (!allowed) {
                return -1;
            }
        }
        return -1;
    }

    private static void refuseControls(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (Character.isISOControl(value.charAt(i))) {
                throw new InvalidSarifException("A result location carries a control character.");
            }
        }
    }

    /** {@code %XX} escapes as UTF-8, strictly: a broken escape or invalid UTF-8 is refused, not guessed. */
    private static String decode(String value) {
        if (value.indexOf('%') < 0) {
            return value;
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(value.length());
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '%') {
                if (i + 2 >= value.length()) {
                    throw new InvalidSarifException("A result location carries a broken %-escape.");
                }
                int high = Character.digit(value.charAt(i + 1), 16);
                int low = Character.digit(value.charAt(i + 2), 16);
                if (high < 0 || low < 0) {
                    throw new InvalidSarifException("A result location carries a broken %-escape.");
                }
                bytes.write(high * 16 + low);
                i += 2;
            } else {
                flush(bytes, out);
                out.append(c);
            }
        }
        flush(bytes, out);
        return out.toString();
    }

    private static void flush(ByteArrayOutputStream bytes, StringBuilder out) {
        if (bytes.size() == 0) {
            return;
        }
        try {
            out.append(StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes.toByteArray())));
        } catch (CharacterCodingException invalid) {
            throw new InvalidSarifException("A result location's %-escapes are not UTF-8.");
        }
        bytes.reset();
    }

    private static String shorten(String value) {
        return value.length() <= 120 ? value : value.substring(0, 120) + "…";
    }
}
