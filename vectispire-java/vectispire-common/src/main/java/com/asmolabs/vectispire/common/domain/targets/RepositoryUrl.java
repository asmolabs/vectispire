package com.asmolabs.vectispire.common.domain.targets;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
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

    /**
     * {@code user@host:path}. The path may not open with {@code //}: JGit reads that string as a
     * local path, not as a remote on {@code host}.
     */
    private static final Pattern SCP_FORM =
            Pattern.compile("^[A-Za-z0-9._-]+@([A-Za-z0-9.-]+):(?!//)([A-Za-z0-9._/-]+)$");

    private static final String LINK_LOCAL_REFUSED =
            "The URL points at a link-local or cloud metadata address, where the instance metadata lives. Clone from the "
                    + "forge's own address.";

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
        Optional<String> ambiguous = ambiguity(url, parsed);
        if (ambiguous.isPresent()) {
            return ambiguous;
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

    /**
     * The host a URL names, in either accepted form; empty when there is none to read, or when the
     * URL could be read as naming two — see {@link #ambiguity}.
     *
     * <p>Empty rather than {@code java.net.URI}'s answer, for every caller: the host allowlist, the
     * binding of an HTTPS token to its host and the link-local refusal all decide on this, and each
     * would otherwise decide on a host the clone does not connect to.
     */
    public static Optional<String> host(String url) {
        if (url == null) {
            return Optional.empty();
        }
        Matcher scp = SCP_FORM.matcher(url);
        if (scp.matches()) {
            return Optional.of(scp.group(1));
        }
        try {
            URI parsed = new URI(url);
            if (parsed.getHost() == null || parsed.getHost().isEmpty() || ambiguity(url, parsed).isPresent()) {
                return Optional.empty();
            }
            return Optional.of(parsed.getHost());
        } catch (Exception unreadable) {
            return Optional.empty();
        }
    }

    /**
     * Why a URL that {@code java.net.URI} reads could be read differently by the clone, or empty.
     *
     * <p><b>Two parsers read every repository URL, and they disagree.</b> This class validates with
     * {@code java.net.URI}; the clone connects where JGit's {@code URIish} says, and {@code URIish}
     * is a set of regular expressions of its own. A {@code #} or a {@code ?} starts a fragment or a
     * query for the first and is an ordinary character of a user name for the second, so a URL can
     * name one host for the allowlist, the token binding and the link-local refusal, and another for
     * the connection. An upper-case scheme is a scheme for the first and, for the second, a local
     * path. Rather than predicting {@code URIish} — a moving target across JGit releases — this
     * refuses what no git remote needs: the characters on which the two readings part, a second
     * {@code @} or an escape in the authority, and any host the authority does not spell literally.
     * {@code GitClone} then checks the host {@code URIish} actually reads before connecting.
     */
    private static Optional<String> ambiguity(String url, URI parsed) {
        for (int index = 0; index < url.length(); index++) {
            char c = url.charAt(index);
            if (c <= 0x20 || c == 0x7f || c == '#' || c == '?' || c == '\\') {
                return Optional.of("The URL contains a character a repository address does not need"
                        + " (a space, '#', '?' or '\\'). Use the address the forge gives for cloning.");
            }
        }
        int schemeEnd = url.indexOf("://");
        if (schemeEnd < 0) {
            return Optional.of("The URL must name a host.");
        }
        String scheme = url.substring(0, schemeEnd);
        if (!scheme.equals(scheme.toLowerCase(Locale.ROOT))) {
            return Optional.of("Write the scheme in lower case: \"" + scheme.toLowerCase(Locale.ROOT) + "://\".");
        }
        int authorityEnd = url.indexOf('/', schemeEnd + 3);
        String authority = url.substring(schemeEnd + 3, authorityEnd < 0 ? url.length() : authorityEnd);
        int at = authority.indexOf('@');
        if (at != authority.lastIndexOf('@') || authority.indexOf('%') >= 0) {
            return Optional.of("The URL's host part is ambiguous: at most one '@', and no escaped character.");
        }
        String hostAndPort = authority.substring(at + 1);
        String spelled;
        if (hostAndPort.startsWith("[")) {
            int close = hostAndPort.indexOf(']');
            spelled = close < 0 ? hostAndPort : hostAndPort.substring(0, close + 1);
        } else {
            int colon = hostAndPort.indexOf(':');
            spelled = colon < 0 ? hostAndPort : hostAndPort.substring(0, colon);
        }
        if (!spelled.equalsIgnoreCase(parsed.getHost())) {
            return Optional.of("The URL's host part is ambiguous. Use the address the forge gives for cloning.");
        }
        return Optional.empty();
    }

    /**
     * The user part: everything before the last {@code @} of the authority.
     *
     * <p>It stopped at the first {@code ?} or {@code #}, as {@code java.net.URI} does — and JGit, which
     * sends the credential, does not: {@code https://user:secret#@host/…} carried a password the check
     * could not see. The authority now ends at the first {@code /} only, and reads the same way for the
     * credential check and the mask.
     */
    private static final Pattern USER_INFO = Pattern.compile("^([A-Za-z][A-Za-z0-9+.-]*://)([^/]*)@");

    private static final Pattern HOST_NAME = Pattern.compile("^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$");

    /** Whether the URL clones over HTTPS — the only transport an HTTPS token is for. */
    public static boolean isHttps(String url) {
        return url != null && url.trim().toLowerCase(Locale.ROOT).startsWith("https://");
    }

    /**
     * Whether the URL carries a secret of its own: any user part over HTTPS, a password over SSH.
     *
     * <p>Refused for new URLs (decision 0022): a token there is stored in the clear and travels to
     * every agent. {@code ssh://git@host} and {@code git@host:path} carry a login, not a secret.
     */
    public static boolean carriesCredential(String url) {
        if (url == null) {
            return false;
        }
        Matcher userInfo = USER_INFO.matcher(url.trim());
        if (!userInfo.find()) {
            return false;
        }
        boolean ssh = userInfo.group(1).equalsIgnoreCase("ssh://");
        return !ssh || userInfo.group(2).contains(":");
    }

    /**
     * A host as a token is bound to it: lower case, no trailing dot, no port, no scheme.
     *
     * @throws InvalidInputException when it is not a host name or an IPv4 literal
     */
    public static String normalizeHost(String host) {
        String value = host == null ? "" : host.trim().toLowerCase(Locale.ROOT);
        while (value.endsWith(".")) {
            value = value.substring(0, value.length() - 1);
        }
        if (value.isEmpty() || value.length() > 253 || !HOST_NAME.matcher(value).matches()) {
            throw new InvalidInputException(
                    "Expected a host name such as gitlab.example.com — no scheme, port or path.");
        }
        if (LinkLocalHosts.isLinkLocalLiteral(value)) {
            throw new InvalidInputException(LINK_LOCAL_REFUSED);
        }
        return value;
    }

    /** Whether the URL's host is {@code host}, compared as {@link #normalizeHost} writes it. */
    public static boolean hasHost(String url, String host) {
        return host(url).map(found -> {
            try {
                return normalizeHost(found).equals(normalizeHost(host));
            } catch (IllegalArgumentException unusable) {
                return false;
            }
        }).orElse(false);
    }

    /**
     * What makes two URLs the same repository: {@code host/path}, whichever transport and spelling
     * names it — decision 0037, §4. Empty when no host can be read ({@link #host}), which no URL
     * {@link #validate} accepts can be.
     *
     * <p><b>The rule, exactly.</b> The host as {@link #normalizeHost} writes it — lower case, no
     * trailing dot — and nothing of the scheme, the user part (a login, or a credential an old row
     * still carries) or the port. Then the path: the SCP form's {@code git@host:group/repo} read as
     * {@code group/repo}, runs of {@code /} folded to one, leading and trailing {@code /} removed, one
     * trailing {@code .git} removed (and the slashes before it), lower case. So {@code
     * git@GitLab.example.org:Team/API.git}, {@code ssh://git@gitlab.example.org:2222/team/api} and
     * {@code https://user:token@gitlab.example.org/team/api/} are one repository, {@code
     * gitlab.example.org/team/api}.
     *
     * <p><b>The port is dropped, not only the default one.</b> SSH and HTTPS reach the same repository
     * on two ports — 22 and 443, or a forge's own {@code 2222} beside 443 — so keeping it would let the
     * SSH and HTTPS URLs of one repository be filed twice, which is the defect this rule exists to
     * prevent.
     *
     * <p><b>Its limits, accepted.</b> Lower-casing the path takes two repositories that differ only by
     * case on a case-sensitive server for one; GitHub, GitLab and Bitbucket all refuse that, and the
     * opposite — {@code Acme/API} typed as {@code acme/api} filed twice — is the common case. Dropping
     * the port takes two servers sharing a host name on two ports for one. Nothing is resolved: two
     * names of one server ({@code git.example.org} and {@code gitlab.example.org}, an IP and its name)
     * are two identities, and so is a forge that serves its transports under different paths
     * (Bitbucket Data Center's {@code /scm/} prefix over HTTPS). The path is compared as written, never
     * percent-decoded. A host in Unicode is refused by {@link #validate}, so an internationalised name
     * is compared in the punycode it has to be written in.
     *
     * <p><b>A stored value.</b> {@code t_repository.url_identity} holds it, computed by this method; a
     * change to the rule leaves every stored identity describing the old one, so it comes with a
     * recomputation of the column.
     */
    public static Optional<String> identity(String url) {
        if (url == null) {
            return Optional.empty();
        }
        String trimmed = url.trim();
        Matcher scp = SCP_FORM.matcher(trimmed);
        String path;
        if (scp.matches()) {
            path = scp.group(2);
        } else {
            if (host(trimmed).isEmpty()) {
                return Optional.empty();
            }
            try {
                path = new URI(trimmed).getRawPath();
            } catch (Exception unreadable) {
                return Optional.empty();
            }
        }
        String host = host(trimmed).orElseThrow().toLowerCase(Locale.ROOT);
        while (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        if (host.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(host + "/" + identityPath(path == null ? "" : path));
    }

    private static String identityPath(String path) {
        String folded = path.toLowerCase(Locale.ROOT).replaceAll("/{2,}", "/");
        folded = stripSlashes(folded);
        if (folded.endsWith(".git")) {
            folded = stripSlashes(folded.substring(0, folded.length() - ".git".length()));
        }
        return folded;
    }

    private static String stripSlashes(String value) {
        int start = 0;
        int end = value.length();
        while (start < end && value.charAt(start) == '/') {
            start++;
        }
        while (end > start && value.charAt(end - 1) == '/') {
            end--;
        }
        return value.substring(start, end);
    }

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
