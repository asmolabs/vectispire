package com.asmolabs.vectispire.common.scanning;

import com.asmolabs.vectispire.common.domain.net.LinkLocalHosts;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.TransportConfigCallback;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.api.errors.InvalidRemoteException;
import org.eclipse.jgit.api.errors.TransportException;
import org.eclipse.jgit.transport.CredentialItem;
import org.eclipse.jgit.transport.CredentialsProvider;
import org.eclipse.jgit.transport.SshTransport;
import org.eclipse.jgit.transport.TransportHttp;
import org.eclipse.jgit.transport.URIish;
import org.eclipse.jgit.transport.sshd.ServerKeyDatabase;
import org.eclipse.jgit.transport.sshd.SshdSessionFactory;
import org.eclipse.jgit.transport.sshd.SshdSessionFactoryBuilder;

/**
 * Cloning a repository to scan.
 *
 * <p>This is where an <b>operator-supplied URL</b> and a <b>private key</b> meet. Three
 * precautions, each for a specific reason:
 *
 * <ol>
 *   <li><b>The URL is revalidated here</b>, although it was already validated on entry. Rows
 *       predating that validation exist in the database, and an unchecked URL reaching a clone
 *       is arbitrary code execution — {@code ext::} makes git itself run a command.
 *   <li><b>No subprocess, and therefore no shell.</b> A branch name is a branch name.
 *   <li><b>The private key never touches the filesystem.</b> It is parsed into memory and
 *       handed to the SSH transport directly, so there is no 0600 file to race against, no
 *       umask to get wrong, and nothing left behind if the process is killed.
 * </ol>
 *
 * <h2>Why JGit rather than the git binary</h2>
 *
 * <p>The subprocess version had to pin {@code LC_ALL=C} because it recognized git's failures by
 * matching English text — and the need was discovered by a test on a French machine, where
 * "Remote branch not found" arrives translated and no pattern matches, leaving the operator
 * with "the clone failed" and no cause. Here the failures are <b>typed</b>, so that entire
 * class of bug is gone rather than pinned down. It also means the agent's host no longer needs
 * git installed.
 */
public final class GitClone {

    /** Clone depth. A scan looks at the current tree, not at the history. */
    private static final int DEPTH = 1;

    private GitClone() {}

    /**
     * How host keys are checked.
     *
     * <p><b>The original documented one policy and implemented another.</b> It passed
     * {@code StrictHostKeyChecking=accept-new} and explained that this "refuses a host whose key
     * has changed" — but pointed {@code UserKnownHostsFile} at a directory created fresh for
     * each clone and deleted immediately after. Every clone was therefore a first contact, every
     * host key was accepted, and the {@code Host key verification failed} branch of its error
     * translation could never fire.
     *
     * <p>The tension it was trying to resolve is real, so it is named here instead of being
     * split across two places that cancel out.
     */
    public sealed interface HostKeyPolicy {

        /**
         * Accept an unknown host on first contact, <b>refuse one whose key has changed</b>.
         *
         * <p>This is the policy that detects interception, and it only works because the file
         * outlives the clone. The cost is real and is the reason the original shied away from
         * it: a legitimately rotated host key blocks scans until an operator clears the entry.
         * That is the right way round — a blocked scan is visible, a silently intercepted one is
         * not — and {@code explain} already has the message for it.
         */
        record AcceptNew(Path knownHosts) implements HostKeyPolicy {}

        /**
         * Accept anything, every time.
         *
         * <p><b>No interception detection at all.</b> Named plainly because that is what the
         * previous implementation did, and a deployment that genuinely wants it should have to
         * write the word.
         */
        record TrustEveryHost() implements HostKeyPolicy {}
    }

    /**
     * What to do when no deployment key came with the task.
     *
     * <p>A closed choice rather than a boolean, because the two answers have very different
     * consequences and a parameter named {@code true} states neither.
     */
    public enum WithoutKey {

        /**
         * No identity at all. A public repository clones; a private one is refused.
         *
         * <p><b>The safe answer, and the reason it exists:</b> a key lying around on the host
         * could otherwise clone a repository nobody attached it to. With a key per repository,
         * a target can only be reached by the credential somebody deliberately gave it.
         */
        NONE,

        /**
         * The host's own git access — {@code ~/.ssh}, its config, its agent.
         *
         * <p>This is what {@code CredentialsMode.LOCAL} has always promised for a remote agent:
         * "the agent uses its own git access". Without it that mode cannot clone a private
         * repository at all, because the session is built with an empty identity set.
         *
         * <p><b>It removes the per-repository scoping, and that is the trade.</b> Every target
         * this executor scans is reachable with whatever the host's key can reach. On a
         * single-team installation that is the point; on a shared one it means adding a URL is
         * enough to have Vectispire clone it with an identity nobody attached to it.
         */
        HOST_SSH
    }

    /**
     * @param privateKey the key in the clear, or {@code null} for a public repository
     * @param withoutKey what to fall back on when {@code privateKey} is absent
     */
    public record Request(
            String url,
            String branch,
            Path into,
            String privateKey,
            Duration timeout,
            HostKeyPolicy hostKeys,
            WithoutKey withoutKey,
            ScanTask.Target.HttpsCredential https) {

        public Request(
                String url,
                String branch,
                Path into,
                String privateKey,
                Duration timeout,
                HostKeyPolicy hostKeys,
                WithoutKey withoutKey) {
            this(url, branch, into, privateKey, timeout, hostKeys, withoutKey, null);
        }

        public Request(String url, String branch, Path into, HostKeyPolicy hostKeys) {
            this(url, branch, into, null, Duration.ofMinutes(5), hostKeys, WithoutKey.NONE, null);
        }

        boolean hasKey() {
            return privateKey != null && !privateKey.isBlank();
        }

        boolean hasToken() {
            return https != null && https.token() != null && !https.token().isBlank();
        }
    }

    /** What a token is sent as when the forge wants no particular user name. */
    static final String TOKEN_USER = "x-access-token";

    /**
     * Answers with the token for its own host, and with nothing for any other (decision 0022).
     *
     * <p>JGit asks this provider for every URI it is about to authenticate against — the clone's,
     * and a redirect's. Answering only for the bound host is what keeps a redirect, or a URL
     * pointed elsewhere, from receiving the forge's token.
     */
    static final class HostBoundCredentials extends CredentialsProvider {
        private final String host;
        private final String username;
        private final char[] token;

        HostBoundCredentials(ScanTask.Target.HttpsCredential credential) {
            this.host = credential.host().toLowerCase(Locale.ROOT);
            this.username = credential.username() == null || credential.username().isBlank()
                    ? TOKEN_USER
                    : credential.username();
            this.token = credential.token().toCharArray();
        }

        @Override
        public boolean isInteractive() {
            return false;
        }

        @Override
        public boolean supports(CredentialItem... items) {
            for (CredentialItem item : items) {
                if (!(item instanceof CredentialItem.Username) && !(item instanceof CredentialItem.Password)) {
                    return false;
                }
            }
            return true;
        }

        @Override
        public boolean get(URIish uri, CredentialItem... items) {
            if (uri == null || uri.getHost() == null || !host.equals(uri.getHost().toLowerCase(Locale.ROOT))) {
                return false;
            }
            for (CredentialItem item : items) {
                if (item instanceof CredentialItem.Username user) {
                    user.setValue(username);
                } else if (item instanceof CredentialItem.Password password) {
                    password.setValue(token.clone());
                } else {
                    return false;
                }
            }
            return true;
        }
    }

    public static void clone(Request request) {
        Optional<String> refused = RepositoryUrl.validate(request.url());
        if (refused.isPresent()) {
            throw new CloneFailureException("Repository URL refused: " + refused.get(), "");
        }
        String host = hostJGitConnectsTo(request.url());
        // The literal was refused above; a name is only known to point there once resolved, and
        // resolving is this machine's business — the agent's network, not the control plane's.
        if (LinkLocalHosts.resolvesToLinkLocal(host)) {
            throw new CloneFailureException(
                    "Repository URL refused: its host resolves to a link-local address, where the instance metadata lives.",
                    "");
        }

        if (request.hasToken()) {
            // Refused before the network, with the reason: the credential provider would
            // otherwise just stay silent and the forge answer "authentication required".
            if (!request.url().trim().toLowerCase(Locale.ROOT).startsWith("https://")
                    || !RepositoryUrl.hasHost(request.url(), request.https().host())) {
                throw new CloneFailureException("The HTTPS token is issued for " + request.https().host()
                        + " and is sent to no other host; " + RepositoryUrl.redact(request.url()) + " names another.", "");
            }
        }

        // Parsed before anything reaches the network. The SSH factory would parse it lazily, at
        // connection time, and an unreadable key would then be indistinguishable from a refused
        // one — sending the operator to the provider's settings for a key that never parsed.
        Iterable<KeyPair> keys = request.hasKey() ? loadKey(request.privateKey()) : List.of();

        try (Git repository = Git.cloneRepository()
                .setURI(request.url())
                .setDirectory(request.into().toFile())
                .setBranch(request.branch())
                .setBranchesToClone(List.of("refs/heads/" + request.branch()))
                .setDepth(DEPTH)
                .setCloneSubmodules(false)
                .setTimeout((int) request.timeout().toSeconds())
                .setTransportConfigCallback(transportCallback(request, keys))
                .setCredentialsProvider(request.hasToken() ? new HostBoundCredentials(request.https()) : null)
                .call()) {
            // The handle is closed at once: the scanners read the working tree on disk, and
            // holding the repository open would keep its packfiles mapped for nothing.
            repository.getRepository().getDirectory();
        } catch (CloneFailureException alreadyDiagnosed) {
            // Rethrown untouched. The generic handler below would replace a message that names
            // the actual problem with "the clone failed", which is the failure mode this whole
            // class exists to avoid.
            throw alreadyDiagnosed;
        } catch (GitAPIException | RuntimeException failure) {
            // JGit's own text may quote the URL too; masked like the explanation, although nothing
            // displays it today — the day something does, it will not carry the token.
            throw new CloneFailureException(
                    explain(request, failure),
                    rootMessage(failure).replace(request.url(), RepositoryUrl.redact(request.url())));
        }
    }

    /**
     * The host the clone will connect to, as JGit reads the URL — refused unless it is the host
     * every check before this one decided on.
     *
     * <p>{@link RepositoryUrl} validates with {@code java.net.URI}, and the allowlist, the token
     * binding and the link-local refusal all read the host from there; JGit parses the same string
     * with {@code URIish}, its own regular expressions, and connects where they say. The two have
     * disagreed — a character that ends the authority for one is part of a user name for the other —
     * and a URL could then pass every check for one host and be cloned from another. {@code
     * RepositoryUrl} refuses the forms known to part them; this refuses whatever else does, on the
     * reading that actually connects, so the next JGit release cannot reopen it quietly.
     */
    static String hostJGitConnectsTo(String url) {
        URIish parsed;
        try {
            parsed = new URIish(url);
        } catch (java.net.URISyntaxException unreadable) {
            throw new CloneFailureException("Repository URL refused: it cannot be read as a git remote.", "");
        }
        boolean scp = !url.contains("://");
        String expectedScheme = scp ? null : url.substring(0, url.indexOf("://"));
        Optional<String> validated = RepositoryUrl.host(url);
        if (parsed.getHost() == null
                || validated.isEmpty()
                || !parsed.getHost().equalsIgnoreCase(validated.get())
                || !java.util.Objects.equals(parsed.getScheme(), expectedScheme)) {
            throw new CloneFailureException(
                    "Repository URL refused: its host part reads differently to the clone than to the checks."
                            + " Use the address the forge gives for cloning.", "");
        }
        return parsed.getHost();
    }

    /**
     * What each transport is configured with before its first request.
     *
     * <p>Package-private so that the redirect refusal can be exercised against a local plain-HTTP
     * server: {@link #clone} itself accepts only {@code https://}, and a test that installed the
     * refusal by hand would pass the day this callback stopped installing it.
     */
    static TransportConfigCallback transportCallback(Request request, Iterable<KeyPair> keys) {
        return transport -> {
            if (transport instanceof TransportHttp http) {
                // No redirect, to any host: the URL checked above is the only one this clone may
                // reach. See RedirectRefusingConnections for why this, not http.followRedirects.
                http.setHttpConnectionFactory(new RedirectRefusingConnections(http.getHttpConnectionFactory()));
                return;
            }
            if (transport instanceof SshTransport ssh) {
                ssh.setSshSessionFactory(sessionFactory(request, keys));
            }
        };
    }

    /**
     * The SSH session, built two very different ways.
     *
     * <p><b>With a key, nothing of the host is used.</b> No agent, no default identity, and a
     * throwaway home directory: only the key this scan was given. That is what keeps a target
     * reachable solely by the credential somebody attached to it — a key lying around on the
     * host cannot clone a repository nobody gave it to.
     *
     * <p><b>With {@link WithoutKey#HOST_SSH} and no key, the host's own configuration is used
     * whole</b> — identities, {@code config}, agent and {@code known_hosts}. Deliberately whole:
     * borrowing the identities while pointing {@code known_hosts} at an empty directory would
     * make every clone a first contact, which is the shape of a check that looks present and
     * verifies nothing.
     */
    private static SshdSessionFactory sessionFactory(Request request, Iterable<KeyPair> keys) {
        if (request.withoutKey() == WithoutKey.HOST_SSH && !request.hasKey()) {
            return new SshdSessionFactoryBuilder()
                    .setPreferredAuthentications("publickey")
                    .setHomeDirectory(new java.io.File(System.getProperty("user.home")))
                    .setSshDirectory(new java.io.File(System.getProperty("user.home"), ".ssh"))
                    .build(null);
        }

        SshdSessionFactoryBuilder builder = new SshdSessionFactoryBuilder()
                .setPreferredAuthentications("publickey")
                .setDefaultKeysProvider(ignored -> keys)
                .setServerKeyDatabase((homeDir, sshDir) -> serverKeys(request.hostKeys()));

        Path home = knownHostsHome(request.hostKeys());
        return builder.setHomeDirectory(home.toFile()).setSshDirectory(home.toFile()).build(null);
    }

    private static Iterable<KeyPair> loadKey(String privateKey) {
        // ssh refuses a private key whose last line is unterminated — the detail a copy-paste
        // out of a browser loses, whose error message talks about an invalid format rather than
        // a missing newline. Handled here rather than left to surprise somebody.
        String material = privateKey.endsWith("\n") ? privateKey : privateKey + "\n";
        Iterable<KeyPair> identities;
        try (var stream = new ByteArrayInputStream(material.getBytes(StandardCharsets.UTF_8))) {
            identities = org.apache.sshd.common.util.security.SecurityUtils.loadKeyPairIdentities(
                    null, () -> "deployment key", stream, null);
        } catch (IOException | GeneralSecurityException unreadable) {
            throw new CloneFailureException(
                    "The deployment key attached to this repository could not be read: " + unreadable.getMessage(), "");
        }

        // **An unrecognized format yields nothing rather than throwing.** Left unchecked, the
        // clone proceeds with no identity at all and fails as "Permission denied" — sending the
        // operator to the provider's settings to look for a key that never parsed here.
        if (identities == null || !identities.iterator().hasNext()) {
            throw new CloneFailureException(
                    "The deployment key attached to this repository could not be read: no key recognized in it. "
                            + "Expected an OpenSSH or PEM private key.",
                    "");
        }
        return identities;
    }

    private static ServerKeyDatabase serverKeys(HostKeyPolicy policy) {
        return switch (policy) {
            case HostKeyPolicy.TrustEveryHost ignored -> new TrustEveryHostDatabase();
            case HostKeyPolicy.AcceptNew acceptNew -> new AcceptNewDatabase(acceptNew.knownHosts());
        };
    }

    private static Path knownHostsHome(HostKeyPolicy policy) {
        return switch (policy) {
            case HostKeyPolicy.AcceptNew acceptNew -> acceptNew.knownHosts().getParent();
            case HostKeyPolicy.TrustEveryHost ignored -> Path.of(System.getProperty("java.io.tmpdir"));
        };
    }

    /**
     * Turns a failure into a sentence that says what to do.
     *
     * <p>Git's raw message is correct and unusable: "Permission denied (publickey)" says neither
     * which repository, nor that Vectispire holds a key, nor where to declare it. The error lands
     * in an agent's log, hours after the action that caused it.
     *
     * <p>Dispatched on the exception <b>type</b> where JGit provides one, and on its text only
     * where it does not — the remaining text matches are the ones JGit funnels through a generic
     * transport failure.
     */
    static String explain(Request request, Throwable failure) {
        String message = rootMessage(failure);
        // Every message below names the URL, and each one reaches the scan's error, the agent's
        // log and the screen: a credential in it would travel with it.
        String url = RepositoryUrl.redact(request.url());

        if (failure instanceof InvalidRemoteException || message.contains("not found")
                || message.contains("Remote branch")) {
            if (message.contains("Remote branch") || message.contains("branch")) {
                return "Branch \"" + request.branch() + "\" does not exist on " + url + ".";
            }
            return url + " could not be found.";
        }
        if (request.hasToken() && (message.contains("not authorized") || message.contains("401")
                || message.contains("Authentication is required") || message.contains("403"))) {
            return "Authentication refused by " + url + ". Is the HTTPS token still valid, and allowed to read "
                    + "this repository?";
        }
        if (message.contains("Auth fail") || message.contains("publickey") || message.contains("not authorized")) {
            return request.hasKey()
                    ? "Authentication refused by " + url
                            + ". Is the deployment key attached to it declared with the provider?"
                    : url + " requires authentication. Attach an SSH key to this repository.";
        }
        if (message.contains("KeyExchange") || message.contains("host key") || message.contains("HostKey")) {
            return "The host key of " + url
                    + " has changed since the last clone. Check it is the same server before running again.";
        }
        if (failure instanceof TransportException && (message.contains("timeout") || message.contains("timed out"))) {
            return "The clone of " + url + " timed out. Is the repository reachable from this machine?";
        }
        return "The clone of " + url + " failed.";
    }

    private static String rootMessage(Throwable failure) {
        Throwable cause = failure;
        StringBuilder all = new StringBuilder();
        while (cause != null) {
            if (cause.getMessage() != null) {
                all.append(cause.getMessage()).append('\n');
            }
            cause = cause.getCause();
        }
        return all.toString();
    }

    /**
     * Makes sure the file exists, <b>whoever gets there first</b>.
     *
     * <p>It used to check, then create. One scan at a time, that was the same thing; with an
     * agent running several, two clones on a fresh machine both saw no file, and the second
     * {@code createFile} failed its whole scan with "the known-hosts file could not be
     * prepared" — over a file that was, by then, sitting right there. Creating and accepting
     * "already exists" has no window. Writing the host lines is JGit's, behind its own lock
     * file.
     */
    static void prepareKnownHosts(Path knownHosts) {
        try {
            Files.createDirectories(knownHosts.getParent());
            Files.createFile(knownHosts);
        } catch (java.nio.file.FileAlreadyExistsException present) {
            // The outcome we wanted, whoever created it.
        } catch (IOException e) {
            throw new CloneFailureException("The known-hosts file could not be prepared: " + e.getMessage(), "");
        }
    }

    /** Accepts anything and remembers nothing. */
    private static final class TrustEveryHostDatabase implements ServerKeyDatabase {

        @Override
        public List<java.security.PublicKey> lookup(String connectAddress, java.net.InetSocketAddress remoteAddress,
                Configuration config) {
            return List.of();
        }

        @Override
        public boolean accept(String connectAddress, java.net.InetSocketAddress remoteAddress,
                java.security.PublicKey serverKey, Configuration config, org.eclipse.jgit.transport.CredentialsProvider provider) {
            return true;
        }
    }

    /**
     * First contact is accepted and written down; a changed key is refused.
     *
     * <p>Backed by a file that outlives the clone, which is the whole point — see
     * {@link HostKeyPolicy.AcceptNew}.
     */
    private static final class AcceptNewDatabase implements ServerKeyDatabase {

        private final org.eclipse.jgit.internal.transport.sshd.OpenSshServerKeyDatabase delegate;

        AcceptNewDatabase(Path knownHosts) {
            prepareKnownHosts(knownHosts);
            this.delegate = new org.eclipse.jgit.internal.transport.sshd.OpenSshServerKeyDatabase(
                    true, List.of(knownHosts));
        }

        @Override
        public List<java.security.PublicKey> lookup(String connectAddress, java.net.InetSocketAddress remoteAddress,
                Configuration config) {
            return delegate.lookup(connectAddress, remoteAddress, config);
        }

        @Override
        public boolean accept(String connectAddress, java.net.InetSocketAddress remoteAddress,
                java.security.PublicKey serverKey, Configuration config, org.eclipse.jgit.transport.CredentialsProvider provider) {
            return delegate.accept(connectAddress, remoteAddress, serverKey, config, provider);
        }
    }
}
