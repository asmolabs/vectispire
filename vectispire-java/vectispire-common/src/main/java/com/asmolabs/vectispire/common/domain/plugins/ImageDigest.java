package com.asmolabs.vectispire.common.domain.plugins;

/**
 * An image reference pinned by its content: {@code repository@sha256:<64 hex>}, and nothing else.
 *
 * <p><b>No tag, not even beside the digest.</b> {@code acme/lint:4.2@sha256:…} is valid Docker syntax
 * and the daemon pulls the digest — but the tag then reads as the version on every screen while
 * saying nothing true about it. A plugin is identified by what runs, so the reference says only that.
 *
 * <p><b>Relocated, never replaced.</b> An estate pulling from an internal registry points
 * {@code VECTISPIRE_PLUGIN_REGISTRY} at its mirror; {@link #relocate} swaps the registry host and
 * keeps the repository path and the digest, so the mirror can serve the image but cannot substitute
 * another one. That is stricter than the scanner images' override, which accepts any reference,
 * because a plugin is third-party code that reads every file it is given.
 *
 * @param repository the registry host, if any, and the path — without tag or digest
 * @param digest {@code sha256:} and 64 lowercase hexadecimal digits
 */
public record ImageDigest(String repository, String digest) {

    private static final String SHA256 = "sha256:";

    /** @throws InvalidPluginException naming what is wrong with the reference */
    public static ImageDigest parse(String reference) {
        if (reference == null || reference.isBlank()) {
            throw new InvalidPluginException("A plugin's image is required, pinned by digest: repository@sha256:….");
        }
        int at = reference.indexOf('@');
        if (at <= 0 || at != reference.lastIndexOf('@')) {
            throw new InvalidPluginException("A plugin's image is pinned by digest — repository@sha256:… — never by "
                    + "a tag, which moves: \"" + reference + "\".");
        }
        String repository = reference.substring(0, at);
        String digest = reference.substring(at + 1);
        if (!digest.startsWith(SHA256) || digest.length() != SHA256.length() + 64 || !lowercaseHex(digest.substring(SHA256.length()))) {
            throw new InvalidPluginException("The image digest is sha256: and 64 lowercase hexadecimal digits.");
        }
        if (repository.length() > 255) {
            throw new InvalidPluginException("The image repository is at most 255 characters.");
        }
        int lastSlash = repository.lastIndexOf('/');
        if (repository.indexOf(':', lastSlash + 1) >= 0) {
            throw new InvalidPluginException("The image names a tag beside its digest; the digest alone says what runs.");
        }
        for (int i = 0; i < repository.length(); i++) {
            char c = repository.charAt(i);
            boolean allowed = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '-' || c == '_' || c == '/' || c == ':';
            if (!allowed) {
                throw new InvalidPluginException("The image repository is lowercase letters, digits and . - _ / : only.");
            }
        }
        if (repository.startsWith("/") || repository.endsWith("/") || repository.contains("//")) {
            throw new InvalidPluginException("The image repository has an empty path segment.");
        }
        return new ImageDigest(repository, digest);
    }

    /**
     * The same image, pulled from {@code mirror} — or unchanged when no mirror is set.
     *
     * <p>The first path segment is a registry host when it contains a dot or a colon or is
     * {@code localhost}, as Docker reads it; otherwise the image is Docker Hub's, and a single-segment
     * name is Hub's {@code library/}.
     */
    public static String relocate(String reference, String mirror) {
        ImageDigest image = parse(reference);
        if (mirror == null || mirror.isBlank()) {
            return reference;
        }
        String host = requireMirror(mirror);
        String path = image.repository();
        int slash = path.indexOf('/');
        if (slash > 0) {
            String first = path.substring(0, slash);
            if (first.contains(".") || first.contains(":") || first.equals("localhost")) {
                path = path.substring(slash + 1);
            }
        } else {
            path = "library/" + path;
        }
        return host + "/" + path + "@" + image.digest();
    }

    /** A mirror is a registry host, a port and a path prefix at most: no scheme, no credential. */
    public static String requireMirror(String mirror) {
        String trimmed = mirror.strip();
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        if (trimmed.isEmpty() || trimmed.contains("://") || trimmed.contains("@") || trimmed.startsWith("/")) {
            throw new InvalidPluginException("The plugin registry mirror is a host, optionally with a port and a path "
                    + "(registry.example.internal:5000/mirror) — no scheme and no credential.");
        }
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            boolean allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '-' || c == '_' || c == '/' || c == ':';
            if (!allowed) {
                throw new InvalidPluginException("The plugin registry mirror carries a character a registry host cannot.");
            }
        }
        return trimmed.toLowerCase(java.util.Locale.ROOT);
    }

    private static boolean lowercaseHex(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }
}
