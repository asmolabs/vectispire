package com.asmolabs.vectispire.common.domain.targets;

import com.asmolabs.vectispire.common.domain.net.LinkLocalHosts;
import java.net.URI;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
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

    private static final Pattern SCP_FORM = Pattern.compile("^[A-Za-z0-9._-]+@([A-Za-z0-9.-]+):[A-Za-z0-9._/-]+$");

    private static final String LINK_LOCAL_REFUSED =
            "The URL points at a link-local address, where the instance metadata lives. Clone from the forge's own address.";

    /** Empty if the URL is acceptable, otherwise the message to show. */
    public static Optional<String> validate(String url) {
        if (url == null || url.isBlank()) {
            return Optional.of("The repository URL is required.");
        }
        Matcher scp = SCP_FORM.matcher(url);
        if (scp.matches()) {
            return LinkLocalHosts.isLinkLocalLiteral(scp.group(1)) ? Optional.of(LINK_LOCAL_REFUSED) : Optional.empty();
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
        // **The clone is the one outbound request the SSRF guard never saw.** JGit issues it
        // itself, so `https://169.254.169.254/…` reached the metadata endpoint from the agent and
        // the error text came back to the operator. Private ranges stay allowed — a self-hosted
        // forge is the ordinary case — and a name resolving there is checked at clone time.
        if (LinkLocalHosts.isLinkLocalLiteral(parsed.getHost())) {
            return Optional.of(LINK_LOCAL_REFUSED);
        }
        return Optional.empty();
    }

    /** The host a URL names, in either accepted form; empty when there is none to read. */
    public static Optional<String> host(String url) {
        if (url == null) {
            return Optional.empty();
        }
        Matcher scp = SCP_FORM.matcher(url);
        if (scp.matches()) {
            return Optional.of(scp.group(1));
        }
        try {
            return Optional.ofNullable(new URI(url).getHost()).filter(host -> !host.isEmpty());
        } catch (Exception unreadable) {
            return Optional.empty();
        }
    }

    private static final Pattern USER_INFO = Pattern.compile("^([A-Za-z][A-Za-z0-9+.-]*://)([^/@?#]*)@");

    /**
     * The URL with any credential it carries replaced by {@code ***}, for everything but the clone.
     *
     * <p><b>Accepted, then masked everywhere it is shown.</b> A token in the URL is the only way to
     * clone a private repository over HTTPS today — only SSH keys are managed — so refusing it
     * would remove the capability. But the URL was returned as stored by the repository list, to
     * every account that sees the repository, and written into the audit log, which is chained and
     * cannot be rewritten: "Repository added: https://user:token@…" stays there for good. Every
     * display, message and log line goes through this; only the clone reads the stored value.
     *
     * <p>{@code ssh://git@host} keeps its user: over SSH that is a login name, never the secret —
     * the key is. Over HTTPS any user part is masked, since a token is commonly passed as the
     * user name alone.
     */
    public static String redact(String url) {
        if (url == null) {
            return null;
        }
        Matcher userInfo = USER_INFO.matcher(url);
        if (!userInfo.find()) {
            return url;
        }
        boolean sshLogin = userInfo.group(1).equalsIgnoreCase("ssh://") && !userInfo.group(2).contains(":");
        return sshLogin ? url : userInfo.group(1) + "***@" + url.substring(userInfo.end());
    }

    /**
     * Whether {@code submitted} is the masked form of {@code stored}, sent back unchanged.
     *
     * <p>An edit form shows the masked URL; saving it untouched must not replace a working URL
     * with one whose credential is three asterisks.
     */
    public static boolean isMaskedFormOf(String submitted, String stored) {
        return submitted != null && stored != null && !submitted.equals(stored) && submitted.equals(redact(stored));
    }

    /**
     * {@code org/project} from a git URL, whatever its form.
     *
     * <p>The display name belongs to the server. One screen shortened the URL client-side
     * while another showed it whole, so the same repository carried two names depending on the
     * page and nothing told the user they were the same thing.
     */
    public static String shortName(String url) {
        // Masked first: with a single path segment, `https://token@host/project` would otherwise
        // come out as `token@host/project`.
        String withoutSuffix = redact(url).replaceAll("\\.git$", "").replaceAll("/+$", "");
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
