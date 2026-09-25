package com.asmolabs.vectispire.common.domain.targets;

import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The directory inside a repository that a scan is limited to.
 *
 * <p><b>A path the server resolves against a clone, so it is a security control like the URL.</b>
 * It was stored as typed and handed to {@code Path.resolve}: an absolute value replaces the base
 * outright, and {@code ..} is never normalised. {@code /} made the in-JVM analysers walk the
 * scanning host; {@code ../..} walked the temporary directory where other teams' repositories are
 * cloned at the same moment, and recorded their endpoints under the attacker's repository.
 *
 * <p>Checked at entry and again before each scan, because rows predate the rule. Only relative
 * segments of ordinary characters pass; {@code .} and {@code ..} are refused as segments rather
 * than normalised away, since a value that needs normalising was not written by someone pointing
 * at a directory of their own repository.
 */
public final class RepositorySubPath {

    private RepositorySubPath() {}

    private static final int MAX_LENGTH = 255;
    private static final Pattern SEGMENT = Pattern.compile("[A-Za-z0-9._@+-]+");

    /** Empty if the value is acceptable, otherwise the message to show. Blank means the root. */
    public static Optional<String> validate(String subPath) {
        String value = subPath == null ? "" : subPath.trim();
        if (value.isEmpty()) {
            return Optional.empty();
        }
        if (value.length() > MAX_LENGTH) {
            return Optional.of("The sub-path is longer than " + MAX_LENGTH + " characters.");
        }
        if (value.startsWith("/") || value.contains("\\") || value.contains(":")) {
            return Optional.of("The sub-path must be relative to the repository root, like services/api.");
        }
        for (String segment : strip(value).split("/", -1)) {
            if (segment.isEmpty() || segment.equals(".") || segment.equals("..") || !SEGMENT.matcher(segment).matches()) {
                return Optional.of("The sub-path may only name directories inside the repository: letters, digits "
                        + "and . _ - @ + — no empty, \".\" or \"..\" segment.");
            }
        }
        return Optional.empty();
    }

    /**
     * The value as stored and used: trimmed, without a trailing slash, empty for the root.
     *
     * @throws IllegalArgumentException when {@link #validate} refuses it
     */
    public static String normalize(String subPath) {
        validate(subPath).ifPresent(problem -> {
            throw new IllegalArgumentException(problem);
        });
        return subPath == null ? "" : strip(subPath.trim());
    }

    private static String strip(String value) {
        String stripped = value;
        while (stripped.endsWith("/")) {
            stripped = stripped.substring(0, stripped.length() - 1);
        }
        return stripped;
    }
}
