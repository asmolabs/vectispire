package com.asmolabs.vectispire.common.domain.targets;

import java.net.URI;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Validation of a repository URL.
 *
 * <p><b>This is not input validation, it is a security control.</b> The URL lands in a
 * {@code git clone} run by an agent: an uncontrolled value there is arbitrary code execution
 * on the machine doing the scanning, not a badly filled field. It is therefore checked at
 * entry <em>and</em> before every clone — rows can predate any validation.
 *
 * <p>Two forms accepted and nothing else: a URL with an explicit scheme among
 * {@code https}/{@code ssh}/{@code git}, or the short SCP form {@code git@host:path} everyone
 * copies out of GitHub.
 */
public final class RepositoryUrl {

    private RepositoryUrl() {}

    private static final Set<String> ALLOWED_SCHEMES = Set.of("https", "ssh", "git");

    private static final Pattern SCP_FORM = Pattern.compile("^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[A-Za-z0-9._/-]+$");

    /** Empty if the URL is acceptable, otherwise the message to show. */
    public static Optional<String> validate(String url) {
        if (url == null || url.isBlank()) {
            return Optional.of("The repository URL is required.");
        }
        if (SCP_FORM.matcher(url).matches()) {
            return Optional.empty();
        }

        URI parsed;
        try {
            parsed = new URI(url);
        } catch (Exception unreadable) {
            return Optional.of("Invalid URL. Expected \"https://…\", \"ssh://…\" or \"git@host:path\".");
        }

        String scheme = parsed.getScheme() == null ? "" : parsed.getScheme().toLowerCase(Locale.ROOT);
        if (!ALLOWED_SCHEMES.contains(scheme)) {
            // `file://` would clone a local path on the agent; `ext::` makes git itself run an
            // arbitrary command. An allowlist is the only safe shape here — a denylist has to
            // anticipate every transport git will ever gain.
            return Optional.of("Scheme \"" + scheme + "\" is not allowed. Expected https, ssh or git.");
        }
        if (parsed.getHost() == null || parsed.getHost().isEmpty()) {
            return Optional.of("The URL must name a host.");
        }
        return Optional.empty();
    }

    /**
     * {@code org/project} from a git URL, whatever its form.
     *
     * <p>The display name belongs to the server. One screen shortened the URL client-side
     * while another showed it whole, so the same repository carried two names depending on the
     * page and nothing told the user they were the same thing.
     */
    public static String shortName(String url) {
        String withoutSuffix = url.replaceAll("\\.git$", "").replaceAll("/+$", "");
        String[] segments = withoutSuffix.split("[/:]");

        // The last two segments: `org/project`, including on an SCP form
        // (`git@host:team/subgroup/project`) where the first ":" is not a port.
        java.util.List<String> parts =
                java.util.Arrays.stream(segments).filter(segment -> !segment.isEmpty()).toList();
        if (parts.size() < 2) {
            return parts.isEmpty() ? withoutSuffix : parts.getLast();
        }
        return String.join("/", parts.subList(parts.size() - 2, parts.size()));
    }

    /** The name the operator chose if they gave one, otherwise the short form. */
    public static String displayName(String chosenName, String url) {
        return chosenName == null || chosenName.isBlank() ? shortName(url) : chosenName.trim();
    }
}
