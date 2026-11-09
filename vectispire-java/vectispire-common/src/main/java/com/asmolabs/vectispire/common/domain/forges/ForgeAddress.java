package com.asmolabs.vectispire.common.domain.forges;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Where a forge connection's requests go: the web address an administrator copied from the browser,
 * and the API root derived from it (decision 0037 §1).
 *
 * <p><b>The web address, not the API's.</b> Asking for {@code …/api/v4} would be the first thing an
 * administrator gets wrong, so the address typed is the one in the address bar, and an API path typed
 * anyway is refused with the address to type instead rather than doubled into {@code /api/v4/api/v4}.
 *
 * <p><b>{@code https} only.</b> A token sent over {@code http} on an internal network is still a token
 * on the wire, readable by every host on the path. A URL carrying credentials, a query or a fragment is
 * refused: the first would be a second, unencrypted copy of a secret, the others would be appended to
 * every API path.
 *
 * @param baseUrl the web address, trailing slashes trimmed, the host in lower case, a path prefix kept
 *     ({@code https://example.org/gitlab})
 * @param apiRoot the REST API's root, no trailing slash
 */
public record ForgeAddress(ForgeEdition edition, String baseUrl, String apiRoot) {

    /** The column's width; a forge's address is a host and a short prefix, far below it. */
    public static final int MAX_LENGTH = 512;

    private static final Pattern DATA_RESIDENCY = Pattern.compile("^(?:api\\.)?([a-z0-9][a-z0-9-]{0,62})\\.ghe\\.com$");

    /**
     * Reads the address an administrator typed for a forge.
     *
     * @param typed blank for the vendor's cloud ({@code github.com}, {@code gitlab.com})
     * @throws InvalidInputException in words the administrator can act on
     */
    public static ForgeAddress of(ForgeKind kind, String typed) {
        String value = typed == null ? "" : typed.trim();
        if (value.isEmpty()) {
            return switch (kind) {
                case GITHUB -> new ForgeAddress(ForgeEdition.GITHUB_COM, "https://github.com", "https://api.github.com");
                case GITLAB -> new ForgeAddress(ForgeEdition.GITLAB_COM, "https://gitlab.com", "https://gitlab.com/api/v4");
            };
        }
        if (value.length() > MAX_LENGTH) {
            throw new InvalidInputException("The address is longer than " + MAX_LENGTH + " characters.");
        }
        if (RepositoryUrl.carriesCredential(value)) {
            throw new InvalidInputException(
                    "The address carries a user name or a token: type the address alone, the token has a field of its own.");
        }
        URI uri;
        try {
            uri = new URI(value);
        } catch (URISyntaxException unreadable) {
            throw new InvalidInputException("The address is not a readable URL.");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("https")) {
            throw new InvalidInputException("The address must start with https:// — the token would otherwise cross "
                    + "the network in the clear.");
        }
        if (uri.getRawUserInfo() != null) {
            throw new InvalidInputException(
                    "The address carries a user name or a token: type the address alone, the token has a field of its own.");
        }
        if (uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw new InvalidInputException("The address carries a query or a fragment: type the forge's web address alone.");
        }
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        while (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        if (host.isEmpty()) {
            throw new InvalidInputException("The address has no host.");
        }
        String path = uri.getRawPath() == null ? "" : uri.getRawPath();
        while (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        String lowerPath = path.toLowerCase(Locale.ROOT);
        if (lowerPath.endsWith("/api/v3") || lowerPath.endsWith("/api/v4") || lowerPath.contains("/api/v3/")
                || lowerPath.contains("/api/v4/")) {
            throw new InvalidInputException("Type the forge's web address — what the browser shows — not its API's: "
                    + "the API path is added here.");
        }
        String origin = "https://" + (host.contains(":") ? "[" + host + "]" : host) + (uri.getPort() > 0 ? ":" + uri.getPort() : "");

        return switch (kind) {
            case GITHUB -> github(host, origin, path);
            case GITLAB -> gitlab(host, origin, path);
        };
    }

    private static ForgeAddress github(String host, String origin, String path) {
        if (host.equals("github.com") || host.equals("www.github.com") || host.equals("api.github.com")) {
            return of(ForgeKind.GITHUB, "");
        }
        Matcher residency = DATA_RESIDENCY.matcher(host);
        if (residency.matches()) {
            String subdomain = residency.group(1);
            return new ForgeAddress(ForgeEdition.GITHUB_DATA_RESIDENCY,
                    "https://" + subdomain + ".ghe.com", "https://api." + subdomain + ".ghe.com");
        }
        // Enterprise Server answers its API under the web address, at /api/v3.
        return new ForgeAddress(ForgeEdition.GITHUB_ENTERPRISE_SERVER, origin + path, origin + path + "/api/v3");
    }

    private static ForgeAddress gitlab(String host, String origin, String path) {
        if (host.equals("gitlab.com") || host.equals("www.gitlab.com")) {
            return of(ForgeKind.GITLAB, "");
        }
        // Self-managed GitLab may live under a relative URL root; the API is under it.
        return new ForgeAddress(ForgeEdition.GITLAB_SELF_MANAGED, origin + path, origin + path + "/api/v4");
    }
}
