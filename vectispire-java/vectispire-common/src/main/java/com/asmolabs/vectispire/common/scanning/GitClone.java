package com.asmolabs.vectispire.common.scanning;

import com.asmolabs.vectispire.common.domain.net.LinkLocalHosts;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import com.asmolabs.vectispire.common.scanning.CloneFailureException.Kind;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.text.MessageFormat;
import java.time.Duration;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntConsumer;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.TransportConfigCallback;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.api.errors.InvalidRemoteException;
import org.eclipse.jgit.api.errors.TransportException;
import org.eclipse.jgit.errors.NoRemoteRepositoryException;
import org.eclipse.jgit.internal.JGitText;
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
         *
         * <p>A file this process cannot write is an operator's pinned list and is only matched
         * against — see {@code AcceptNewDatabase}.
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
            throw new CloneFailureException(Kind.URL_REFUSED, "Repository URL refused: " + refused.get(), "");
        }
        String host = hostJGitConnectsTo(request.url());
        // The literal was refused above; a name is only known to point there once resolved, and
        // resolving is this machine's business — the agent's network, not the control plane's.
        if (LinkLocalHosts.resolvesToLinkLocal(host)) {
            throw new CloneFailureException(
                    Kind.URL_REFUSED,
                    "Repository URL refused: its host resolves to a link-local address, where the instance metadata lives.",
                    "");
        }

        if (request.hasToken()) {
            // Refused before the network, with the reason: the credential provider would
            // otherwise just stay silent and the forge answer "authentication required".
            if (!request.url().trim().toLowerCase(Locale.ROOT).startsWith("https://")
                    || !RepositoryUrl.hasHost(request.url(), request.https().host())) {
                throw new CloneFailureException(Kind.CREDENTIAL, "The HTTPS token is issued for " + request.https().host()
                        + " and is sent to no other host; " + RepositoryUrl.redact(request.url()) + " names another.", "");
            }
        }

        // Parsed before anything reaches the network. The SSH factory would parse it lazily, at
        // connection time, and an unreadable key would then be indistinguishable from a refused
        // one — sending the operator to the provider's settings for a key that never parsed.
        Iterable<KeyPair> keys = request.hasKey() ? loadKey(request.privateKey()) : List.of();
        fetch(request, keys);
    }

    /**
     * The clone itself, once every check before the network has passed — and its failure diagnosed.
     *
     * <p>Package-private so the diagnosis can be measured against a local plain-HTTP forge, which
     * {@link #clone} refuses, through the same connection wiring this method installs rather than
     * through a copy of it.
     */
    static void fetch(Request request, Iterable<KeyPair> keys) {
        // The last HTTP status the forge answered, read off the connection: JGit turns a 401 and a 403
        // into a transport failure whose only trace of either is its English text.
        AtomicInteger lastStatus = new AtomicInteger();
        try (Git repository = Git.cloneRepository()
                .setURI(request.url())
                .setDirectory(request.into().toFile())
                .setBranch(request.branch())
                .setBranchesToClone(List.of("refs/heads/" + request.branch()))
                .setDepth(DEPTH)
                .setCloneSubmodules(false)
                .setTimeout((int) request.timeout().toSeconds())
                .setTransportConfigCallback(transportCallback(request, keys, lastStatus::set))
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
            // **A diagnosis made inside JGit comes back wrapped.** The session factory runs in the
            // transport callback, so a known-hosts file that cannot be prepared reached this line as
            // a TransportException and the scan read "the clone failed" — on the composition, every
            // SSH clone with a key, for a reason the operator could have fixed had it been named.
            Optional<CloneFailureException> diagnosed = diagnosedWithin(failure);
            if (diagnosed.isPresent()) {
                throw diagnosed.get();
            }
            // JGit's own text may quote the URL too; masked like the explanation, although nothing
            // displays it today — the day something does, it will not carry the token.
            Diagnosis diagnosis = diagnose(request, failure, lastStatus.get());
            throw new CloneFailureException(
                    diagnosis.kind(),
                    diagnosis.sentence(),
                    rootMessage(failure).replace(request.url(), RepositoryUrl.redact(request.url())));
        }
    }

    private static Optional<CloneFailureException> diagnosedWithin(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof CloneFailureException diagnosed) {
                return Optional.of(diagnosed);
            }
        }
        return Optional.empty();
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
            throw new CloneFailureException(Kind.URL_REFUSED, "Repository URL refused: it cannot be read as a git remote.", "");
        }
        boolean scp = !url.contains("://");
        String expectedScheme = scp ? null : url.substring(0, url.indexOf("://"));
        Optional<String> validated = RepositoryUrl.host(url);
        if (parsed.getHost() == null
                || validated.isEmpty()
                || !parsed.getHost().equalsIgnoreCase(validated.get())
                || !java.util.Objects.equals(parsed.getScheme(), expectedScheme)) {
            throw new CloneFailureException(
                    Kind.URL_REFUSED,
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
        return transportCallback(request, keys, status -> {});
    }

    /** @param statuses told every HTTP status the forge answers — see {@code diagnose} */
    static TransportConfigCallback transportCallback(Request request, Iterable<KeyPair> keys, IntConsumer statuses) {
        return transport -> {
            if (transport instanceof TransportHttp http) {
                // No redirect, to any host: the URL checked above is the only one this clone may
                // reach. See RedirectRefusingConnections for why this, not http.followRedirects.
                http.setHttpConnectionFactory(new RedirectRefusingConnections(http.getHttpConnectionFactory(), statuses));
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
     * <p><b>With a key, nothing of the host is used.</b> No agent, no default identity, no ssh
     * config: only the key this scan was given, and the known-hosts file of the policy. That is
     * what keeps a target reachable solely by the credential somebody attached to it — a key lying
     * around on the host cannot clone a repository nobody gave it to.
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
                // **No ssh config, not even the one beside the known-hosts file.** The session's home
                // is that file's directory, which on a host is the operator's own ~/.ssh, and JGit read
                // `config` there: a `HostName` or `Port` sent the clone somewhere the URL checks never
                // saw, an `IdentityFile` added the host's key to the one this repository was given.
                .setConfigStoreFactory((homeDir, configFile, localUserName) -> null)
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
                    Kind.CREDENTIAL,
                    "The deployment key attached to this repository could not be read: " + unreadable.getMessage(), "");
        }

        // **An unrecognized format yields nothing rather than throwing.** Left unchecked, the
        // clone proceeds with no identity at all and fails as "Permission denied" — sending the
        // operator to the provider's settings to look for a key that never parsed here.
        if (identities == null || !identities.iterator().hasNext()) {
            throw new CloneFailureException(
                    Kind.CREDENTIAL,
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
     * What stopped a clone, and the sentence that says what to do about it.
     *
     * @param kind decided from JGit's and Apache MINA's types and the forge's HTTP status — never from
     *     a message's words, save JGit's own sentence for an absent branch, which no type carries
     * @param sentence what the scan, the agent's log and the screen show
     */
    record Diagnosis(Kind kind, String sentence) {}

    /**
     * Diagnoses a failed clone: its kind from what is typed, its sentence from the kind.
     *
     * <p><b>The types choose the scan's fate, the words only the sentence.</b> Where nothing typed
     * says what happened, the sentence still reads JGit's text as it always did — a message that names
     * the cause is worth more than "the clone failed" — but the kind stays {@link Kind#UNCLASSIFIED},
     * transient: a pattern that matched the wrong message would otherwise fail a scan for good. What
     * each kind is told by, as JGit 7.8 and MINA 2.19 report it, was measured against a real SSH
     * server and a real HTTP one ({@code SshCloneTest}, {@code CloneFailureKindTest}).
     *
     * @param httpStatus the last status the forge answered over HTTP, zero when none — JGit reports a
     *     401 and a 403 as a {@code TransportException} saying "not authorized" and "not permitted",
     *     with no type and no status of its own
     */
    static Diagnosis diagnose(Request request, Throwable failure, int httpStatus) {
        Kind kind = typedKind(request, failure, httpStatus);
        Kind worded = kind == Kind.UNCLASSIFIED ? wordedKind(request, failure) : kind;
        return new Diagnosis(kind, sentence(request, worded));
    }

    /** The sentence alone, for a failure that carries no HTTP status. */
    static String explain(Request request, Throwable failure) {
        return diagnose(request, failure, 0).sentence();
    }

    private static Kind typedKind(Request request, Throwable failure, int httpStatus) {
        List<Throwable> causes = causesOf(failure);
        for (Throwable cause : causes) {
            if (cause instanceof SshException ssh) {
                // MINA sets the disconnect reason (RFC 4253 §11.1) on what it raises when the server
                // key is refused and when every authentication method has been tried; JGit keeps it
                // as the cause.
                if (ssh.getDisconnectCode() == SshConstants.SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE) {
                    return Kind.HOST_KEY;
                }
                if (ssh.getDisconnectCode() == SshConstants.SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE) {
                    return Kind.AUTHENTICATION;
                }
            }
            // JGit's answer to a 404 over HTTP and to "not found" from an SSH forge alike.
            if (cause instanceof NoRemoteRepositoryException || cause instanceof InvalidRemoteException) {
                return Kind.NOT_FOUND;
            }
        }
        if (httpStatus == 401 || httpStatus == 403) {
            return Kind.AUTHENTICATION;
        }
        if (httpStatus == 404 || httpStatus == 410) {
            return Kind.NOT_FOUND;
        }
        if (httpStatus == 429 || httpStatus >= 500) {
            return Kind.UNAVAILABLE;
        }
        if (isAbsentBranch(request, causes)) {
            return Kind.BRANCH_ABSENT;
        }
        // A timeout first: SocketTimeoutException is an InterruptedIOException, and JGit may wrap
        // it with a SocketException on the way.
        if (causes.stream().anyMatch(InterruptedIOException.class::isInstance)) {
            return Kind.TIMEOUT;
        }
        if (causes.stream().anyMatch(cause -> cause instanceof UnknownHostException || cause instanceof SocketException)) {
            return Kind.NETWORK;
        }
        return Kind.UNCLASSIFIED;
    }

    /**
     * Whether JGit said the branch is absent, <b>in its own words, formatted as it formats them</b>.
     *
     * <p>The one kind no type carries: the fetch raises a plain {@code TransportException}. Matched
     * against {@code JGitText}'s own sentence for the request's branch rather than an English literal,
     * so a JGit that rewords it — or a translation bundle on the class path — changes both sides of
     * the comparison at once, and a message about anything else never matches.
     */
    private static boolean isAbsentBranch(Request request, List<Throwable> causes) {
        String absent = MessageFormat.format(JGitText.get().remoteBranchNotFound, request.branch());
        return causes.stream().anyMatch(cause -> absent.equals(cause.getMessage()));
    }

    /**
     * The kind the words suggest, <b>for the sentence only</b> — see {@link #diagnose}.
     *
     * <p>These are the matches the explanation always made, where JGit funnels a failure through a
     * generic transport failure.
     */
    private static Kind wordedKind(Request request, Throwable failure) {
        String message = rootMessage(failure);
        if (failure instanceof InvalidRemoteException || message.contains("not found")
                || message.contains("Remote branch")) {
            return message.contains("Remote branch") || message.contains("branch") ? Kind.BRANCH_ABSENT : Kind.NOT_FOUND;
        }
        if (request.hasToken() && (message.contains("not authorized") || message.contains("401")
                || message.contains("Authentication is required") || message.contains("403"))) {
            return Kind.AUTHENTICATION;
        }
        if (message.contains("Auth fail") || message.contains("publickey") || message.contains("not authorized")) {
            return Kind.AUTHENTICATION;
        }
        // "Server key did not validate" is what JGit says when the database refuses the key, and it
        // said nothing that matched below it: a changed host key read as "the clone failed".
        if (message.contains("Server key did not validate") || message.contains("KeyExchange")
                || message.contains("host key") || message.contains("HostKey")) {
            return Kind.HOST_KEY;
        }
        if (failure instanceof TransportException && (message.contains("timeout") || message.contains("timed out"))) {
            return Kind.TIMEOUT;
        }
        return Kind.UNCLASSIFIED;
    }

    /**
     * Turns a kind into a sentence that says what to do.
     *
     * <p>Git's raw message is correct and unusable: "Permission denied (publickey)" says neither
     * which repository, nor that Vectispire holds a key, nor where to declare it. The error lands
     * in an agent's log, hours after the action that caused it.
     */
    private static String sentence(Request request, Kind kind) {
        // Every message below names the URL, and each one reaches the scan's error, the agent's
        // log and the screen: a credential in it would travel with it.
        String url = RepositoryUrl.redact(request.url());
        return switch (kind) {
            case BRANCH_ABSENT -> "Branch \"" + request.branch() + "\" does not exist on " + url + ".";
            case NOT_FOUND -> url + " could not be found.";
            case AUTHENTICATION -> {
                if (request.hasToken()) {
                    yield "Authentication refused by " + url + ". Is the HTTPS token still valid, and allowed to read "
                            + "this repository?";
                }
                yield request.hasKey()
                        ? "Authentication refused by " + url
                                + ". Is the deployment key attached to it declared with the provider?"
                        : url + " requires authentication. Attach "
                                + (request.url().trim().toLowerCase(Locale.ROOT).startsWith("https://")
                                        ? "an HTTPS token" : "an SSH key")
                                + " to this repository.";
            }
            case HOST_KEY -> {
                if (!request.hasKey() && request.withoutKey() == WithoutKey.HOST_SSH) {
                    // The host's own configuration decides here, and by default it refuses a host its
                    // known_hosts does not list: the key may be new rather than changed.
                    yield "The host key of " + url + " was refused by this machine's own known_hosts: the host is not"
                            + " listed there, or its key has changed. Check it is the right server, then add its key.";
                }
                if (request.hostKeys() instanceof HostKeyPolicy.AcceptNew pinned && isPinned(pinned.knownHosts())) {
                    yield "The host key of " + url + " is not the one listed in " + pinned.knownHosts()
                            + ", or the host is not listed there: that file is read-only, so it is matched against and"
                            + " never added to.";
                }
                yield "The host key of " + url
                        + " has changed since the last clone. Check it is the same server before running again.";
            }
            case TIMEOUT -> "The clone of " + url + " timed out. Is the repository reachable from this machine?";
            case NETWORK -> "The clone of " + url + " could not reach its host. Is the repository reachable from this"
                    + " machine?";
            case UNAVAILABLE -> "The forge answered the clone of " + url + " with an error of its own; the next attempt"
                    + " may succeed.";
            case CREDENTIAL, URL_REFUSED, SUB_PATH, UNCLASSIFIED -> "The clone of " + url + " failed.";
        };
    }

    private static List<Throwable> causesOf(Throwable failure) {
        List<Throwable> causes = new java.util.ArrayList<>();
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Throwable cause = failure; cause != null && seen.add(cause); cause = cause.getCause()) {
            causes.add(cause);
        }
        return causes;
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
            // Transient: this executor's own disk, which another executor — or a freed one — does not share.
            throw new CloneFailureException(
                    Kind.UNCLASSIFIED, "The known-hosts file could not be prepared: " + e.getMessage(), "");
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
     * Whether a known-hosts file is the operator's pin — matched against, never added to.
     *
     * <p><b>Read from the file's own bits as well as from an access check.</b> An access check alone
     * answers "writable" to root for a {@code r--r--r--} file, so an executor running as root — the
     * CI's job container is one — would treat the operator's pin as a list to learn into and accept
     * any new host. A read-only mount is still caught by the access check, which root cannot pass.
     */
    static boolean isPinned(Path knownHosts) {
        if (!Files.isWritable(knownHosts)) {
            return true;
        }
        try {
            return !Files.getPosixFilePermissions(knownHosts).contains(PosixFilePermission.OWNER_WRITE);
        } catch (UnsupportedOperationException | IOException noPosixBits) {
            return false;
        }
    }

    /**
     * First contact is accepted and written down; a changed key is refused.
     *
     * <p>Backed by a file that outlives the clone, which is the whole point — see
     * {@link HostKeyPolicy.AcceptNew}.
     *
     * <p><b>The policy is this class's, never the session's configuration.</b> JGit's database
     * decides by {@code StrictHostKeyChecking}, read from the ssh config, and when none says
     * otherwise that is {@code ask} — which, with nobody to ask, refuses. So the policy called
     * "accept new" had never accepted a new host: a first contact failed with "Server key did not
     * validate" unless the host happened to be in the file already, and an ssh config beside the
     * file saying {@code StrictHostKeyChecking no} or {@code UserKnownHostsFile /dev/null} would
     * have turned the check off. What the database is handed is {@link #acceptingNew}, whatever the
     * session read.
     *
     * <p><b>A file this process cannot write is matched against, never added to.</b> Accept-new on
     * it would accept a first contact and fail to record it, quietly — JGit logs a warning and lets
     * the session through — so every clone would be a first contact again, which is the defect this
     * policy was written to end. A read-only file is an operator's pinned list: a host it does not
     * name is refused.
     */
    private static final class AcceptNewDatabase implements ServerKeyDatabase {

        private final Path knownHosts;
        private final boolean recording;
        private final org.eclipse.jgit.internal.transport.sshd.OpenSshServerKeyDatabase delegate;

        AcceptNewDatabase(Path knownHosts) {
            prepareKnownHosts(knownHosts);
            this.knownHosts = knownHosts;
            this.recording = !isPinned(knownHosts);
            this.delegate = new org.eclipse.jgit.internal.transport.sshd.OpenSshServerKeyDatabase(
                    true, List.of(knownHosts));
        }

        @Override
        public List<java.security.PublicKey> lookup(String connectAddress, java.net.InetSocketAddress remoteAddress,
                Configuration config) {
            return delegate.lookup(connectAddress, remoteAddress, acceptingNew(config));
        }

        @Override
        public boolean accept(String connectAddress, java.net.InetSocketAddress remoteAddress,
                java.security.PublicKey serverKey, Configuration config, org.eclipse.jgit.transport.CredentialsProvider provider) {
            return delegate.accept(connectAddress, remoteAddress, serverKey, acceptingNew(config), provider);
        }

        /** Only this file, accept-new while it can be written, and lines an operator can compare by eye. */
        private Configuration acceptingNew(Configuration session) {
            String user = session.getUsername();
            return new Configuration() {
                @Override
                public List<String> getUserKnownHostsFiles() {
                    return List.of(knownHosts.toString());
                }

                @Override
                public List<String> getGlobalKnownHostsFiles() {
                    return List.of();
                }

                @Override
                public StrictHostKeyChecking getStrictHostKeyChecking() {
                    return recording ? StrictHostKeyChecking.ACCEPT_NEW : StrictHostKeyChecking.REQUIRE_MATCH;
                }

                @Override
                public boolean getHashKnownHosts() {
                    return false;
                }

                @Override
                public String getUsername() {
                    return user;
                }
            };
        }
    }
}
