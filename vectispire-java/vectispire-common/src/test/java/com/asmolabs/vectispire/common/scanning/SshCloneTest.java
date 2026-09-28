package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyPairResourceWriter;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.transport.UploadPack;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * An SSH clone with a deployment key, against a real SSH server — the path no test had taken.
 *
 * <p>Every other clone test runs over HTTP or stops before the network, and so nothing ever saw that
 * the policy called "accept new" accepted no new host: JGit decided by the ssh config's {@code
 * StrictHostKeyChecking}, whose default {@code ask} refuses when nobody can be asked, and every
 * first contact failed with "Server key did not validate" (found on the composition, 2026-09-28).
 * The server is Apache MINA's, already on the classpath under JGit's transport, answering {@code
 * git-upload-pack} with JGit's own {@link UploadPack}: an SSH forge in a few lines, on loopback, with
 * no daemon and no image.
 */
@DisplayName("an SSH clone with a deployment key, and the host key it meets")
class SshCloneTest {

    @TempDir
    Path dir;

    private SshServer server;
    private KeyPair hostKey;
    private KeyPair deployKey;
    private final AtomicInteger uploads = new AtomicInteger();

    @BeforeEach
    void startForge() throws Exception {
        try (Git source = Git.init().setDirectory(dir.resolve("forge/fixture").toFile()).setInitialBranch("main").call()) {
            Files.writeString(dir.resolve("forge/fixture/README"), "fixture\n");
            source.add().addFilepattern("README").call();
            source.commit().setMessage("fixture").setAuthor("check", "check@example.invalid")
                    .setCommitter("check", "check@example.invalid").setSign(false).call();
        }
        hostKey = KeyUtils.generateKeyPair(KeyPairProvider.ECDSA_SHA2_NISTP256, 256);
        deployKey = KeyUtils.generateKeyPair(KeyPairProvider.ECDSA_SHA2_NISTP256, 256);

        server = SshServer.setUpDefaultServer();
        server.setHost("127.0.0.1");
        server.setPort(0);
        server.setKeyPairProvider(KeyPairProvider.wrap(hostKey));
        server.setPublickeyAuthenticator((user, key, session) -> KeyUtils.compareKeys(key, deployKey.getPublic()));
        server.setCommandFactory((channel, command) -> new UploadCommand(command));
        server.start();
    }

    @AfterEach
    void stopForge() throws Exception {
        server.stop(true);
    }

    @Test
    @DisplayName("a first contact is accepted and written down, and the next clone is checked against it")
    void aFirstContactIsRecorded() throws Exception {
        Path knownHosts = dir.resolve("home/.ssh/known_hosts");

        GitClone.clone(request(knownHosts, "first"));

        assertThat(dir.resolve("first/README")).hasContent("fixture");
        assertThat(Files.readString(knownHosts)).contains("[127.0.0.1]:" + port()).contains(line(hostKey.getPublic()));

        GitClone.clone(request(knownHosts, "second"));
        assertThat(dir.resolve("second/README")).exists();
        assertThat(uploads).hasValue(2);
    }

    @Test
    @DisplayName("a host whose key has changed is refused, in words, before anything is fetched")
    void aChangedHostKeyIsRefused() throws Exception {
        Path knownHosts = seeded("[127.0.0.1]:" + port() + " " + line(otherKey()));
        String before = Files.readString(knownHosts);

        Throwable refused = catchThrowable(() -> GitClone.clone(request(knownHosts, "clone")));

        assertThat(refused)
                .isInstanceOf(CloneFailureException.class)
                .hasMessageContaining("has changed since the last clone");
        assertThat(((CloneFailureException) refused).kind())
                .as("told by MINA's disconnect reason, and permanent")
                .isEqualTo(CloneFailureException.Kind.HOST_KEY);
        assertThat(uploads).as("nothing was fetched from the impostor").hasValue(0);
        assertThat(knownHosts).as("the recorded key was not replaced").hasContent(before.strip());
    }

    @Test
    @DisplayName("an ssh config beside the file is not read: it can neither turn the check off nor steer the session")
    void anSshConfigBesideTheFileIsNotRead() throws Exception {
        // The file's directory is the session's home, and on a host that is the operator's own
        // ~/.ssh: JGit read `config` there. The algorithm line is the witness — this server offers
        // no such host key, so a session that read the file could not even agree on one.
        String config = """
                Host *
                  HostKeyAlgorithms ssh-ed25519
                  StrictHostKeyChecking no
                  UserKnownHostsFile /dev/null
                """;
        Path fresh = seeded("");
        Files.writeString(fresh.resolveSibling("config"), config);

        GitClone.clone(request(fresh, "clone"));
        assertThat(dir.resolve("clone/README")).exists();
        assertThat(Files.readString(fresh)).as("recorded in the policy's file, not in /dev/null")
                .contains(line(hostKey.getPublic()));

        Path changed = seeded("[127.0.0.1]:" + port() + " " + line(otherKey()));
        Files.writeString(changed.resolveSibling("config"), config.replace("  HostKeyAlgorithms ssh-ed25519\n", ""));

        assertThat(catchThrowable(() -> GitClone.clone(request(changed, "impostor"))))
                .isInstanceOf(CloneFailureException.class)
                .hasMessageContaining("has changed since the last clone");
    }

    @Test
    @DisplayName("a read-only file is an operator's pin: listed hosts clone, an unlisted one is refused")
    void aReadOnlyFileIsMatchedAgainstNeverAddedTo() throws Exception {
        // Accept-new on a file it cannot write would accept the first contact and record nothing —
        // JGit only logs that — so every clone would be a first contact, indefinitely.
        Path unlisted = seeded("");
        Files.setPosixFilePermissions(unlisted, PosixFilePermissions.fromString("r--r--r--"));

        Throwable refused = catchThrowable(() -> GitClone.clone(request(unlisted, "unlisted")));

        assertThat(refused).isInstanceOf(CloneFailureException.class).hasMessageContaining("read-only");
        assertThat(uploads).hasValue(0);

        Path pinned = dir.resolve("pinned/.ssh/known_hosts");
        Files.createDirectories(pinned.getParent());
        Files.writeString(pinned, "[127.0.0.1]:" + port() + " " + line(hostKey.getPublic()) + "\n");
        Files.setPosixFilePermissions(pinned, PosixFilePermissions.fromString("r--r--r--"));

        GitClone.clone(request(pinned, "pinned-clone"));
        assertThat(dir.resolve("pinned-clone/README")).exists();
    }

    @Test
    @DisplayName("a known-hosts file that cannot be prepared says so, rather than \"the clone failed\"")
    void anUnpreparableFileIsNamed() throws Exception {
        // On the composition's image there is no passwd entry, user.home is `/`, and `/.ssh` cannot
        // be created: every keyed clone failed there, and the scan said only "the clone failed" —
        // the diagnosis was made inside JGit's transport callback and came back wrapped.
        Files.writeString(dir.resolve("not-a-directory"), "");
        Path knownHosts = dir.resolve("not-a-directory/.ssh/known_hosts");

        Throwable refused = catchThrowable(() -> GitClone.clone(request(knownHosts, "clone")));

        assertThat(refused)
                .isInstanceOf(CloneFailureException.class)
                .hasMessageContaining("The known-hosts file could not be prepared");
        assertThat(((CloneFailureException) refused).failureKind())
                .as("this executor's own disk: another attempt, elsewhere or later, may pass")
                .isEqualTo(com.asmolabs.vectispire.common.domain.scans.FailureKind.TRANSIENT);
    }

    @Test
    @DisplayName("a deployment key the forge does not know is an authentication refused, permanent")
    void anUnknownKeyIsRefused() throws Exception {
        GitClone.Request stranger = new GitClone.Request(
                "ssh://git@127.0.0.1:" + port() + "/fixture", "main", dir.resolve("stranger"),
                openSsh(KeyUtils.generateKeyPair(KeyPairProvider.ECDSA_SHA2_NISTP256, 256)), Duration.ofSeconds(30),
                new GitClone.HostKeyPolicy.AcceptNew(dir.resolve("home/.ssh/known_hosts")), GitClone.WithoutKey.NONE);

        CloneFailureException refused = catchThrowableOfType(CloneFailureException.class, () -> GitClone.clone(stranger));

        assertThat(refused.kind()).isEqualTo(CloneFailureException.Kind.AUTHENTICATION);
        assertThat(refused).hasMessageContaining("declared with the provider");
    }

    @Test
    @DisplayName("a repository the forge does not have is not found, permanent")
    void anAbsentRepositoryIsNotFound() throws Exception {
        GitClone.Request absent = new GitClone.Request(
                "ssh://git@127.0.0.1:" + port() + "/missing", "main", dir.resolve("missing"), openSsh(deployKey),
                Duration.ofSeconds(30), new GitClone.HostKeyPolicy.AcceptNew(dir.resolve("home/.ssh/known_hosts")),
                GitClone.WithoutKey.NONE);

        CloneFailureException refused = catchThrowableOfType(CloneFailureException.class, () -> GitClone.clone(absent));

        assertThat(refused.kind()).isEqualTo(CloneFailureException.Kind.NOT_FOUND);
        assertThat(refused).hasMessageContaining("could not be found");
    }

    @Test
    @DisplayName("a branch the repository does not have is absent, permanent, and named")
    void anAbsentBranchIsNamed() throws Exception {
        GitClone.Request absent = new GitClone.Request(
                "ssh://git@127.0.0.1:" + port() + "/fixture", "release", dir.resolve("release"), openSsh(deployKey),
                Duration.ofSeconds(30), new GitClone.HostKeyPolicy.AcceptNew(dir.resolve("home/.ssh/known_hosts")),
                GitClone.WithoutKey.NONE);

        CloneFailureException refused = catchThrowableOfType(CloneFailureException.class, () -> GitClone.clone(absent));

        assertThat(refused.kind()).isEqualTo(CloneFailureException.Kind.BRANCH_ABSENT);
        assertThat(refused).hasMessageContaining("Branch \"release\" does not exist");
    }

    @Test
    @DisplayName("a scan whose sub-path the clone does not hold fails before any scanner, for good")
    void aScanOfAnAbsentSubPathFails() throws Exception {
        // Through the runner, so the check is the one a scan meets: handed on, the missing directory
        // reached every analyser, each of which reported it — or an empty result over nothing.
        ContainerRunner containers = org.mockito.Mockito.mock(ContainerRunner.class);
        ScanRunner runner = new ScanRunner(containers, com.asmolabs.vectispire.common.scanning.scanners.ScannerImages.PINNED,
                dir.resolve("rules"), hash -> java.util.List.of(),
                new GitClone.HostKeyPolicy.AcceptNew(dir.resolve("home/.ssh/known_hosts")), GitClone.WithoutKey.NONE,
                java.time.Clock.systemUTC());
        ScanTask task = new ScanTask(
                new ScanTask.Target.Repository("ssh://git@127.0.0.1:" + port() + "/fixture", "main", "services/api",
                        openSsh(deployKey)),
                null, java.util.Set.of(ScanTask.Step.DEPENDENCIES));

        CloneFailureException refused = catchThrowableOfType(CloneFailureException.class, () -> runner.run(task));

        assertThat(refused.kind()).isEqualTo(CloneFailureException.Kind.SUB_PATH);
        assertThat(uploads).as("the clone ran").hasValue(1);
        org.mockito.Mockito.verifyNoInteractions(containers);
    }

    @Test
    @DisplayName("a forge that is down is the network, transient")
    void aForgeThatIsDownIsTheNetwork() throws Exception {
        Path knownHosts = dir.resolve("home/.ssh/known_hosts");
        GitClone.Request request = request(knownHosts, "down");
        server.stop(true);

        CloneFailureException refused = catchThrowableOfType(CloneFailureException.class, () -> GitClone.clone(request));

        assertThat(refused.kind()).isEqualTo(CloneFailureException.Kind.NETWORK);
        assertThat(refused.failureKind()).isEqualTo(com.asmolabs.vectispire.common.domain.scans.FailureKind.TRANSIENT);
    }

    private GitClone.Request request(Path knownHosts, String into) throws Exception {
        return new GitClone.Request(
                "ssh://git@127.0.0.1:" + port() + "/fixture",
                "main",
                dir.resolve(into),
                openSsh(deployKey),
                Duration.ofSeconds(30),
                new GitClone.HostKeyPolicy.AcceptNew(knownHosts),
                GitClone.WithoutKey.NONE);
    }

    private Path seeded(String content) throws Exception {
        Path knownHosts = dir.resolve("home-" + System.nanoTime() + "/.ssh/known_hosts");
        Files.createDirectories(knownHosts.getParent());
        Files.writeString(knownHosts, content.isEmpty() ? "" : content + "\n");
        return knownHosts;
    }

    private int port() {
        return server.getPort();
    }

    private static PublicKey otherKey() throws Exception {
        return KeyUtils.generateKeyPair(KeyPairProvider.ECDSA_SHA2_NISTP256, 256).getPublic();
    }

    private static String line(PublicKey key) {
        return PublicKeyEntry.toString(key);
    }

    private static String openSsh(KeyPair pair) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        OpenSSHKeyPairResourceWriter.INSTANCE.writePrivateKey(pair, "deploy", null, out);
        return out.toString(StandardCharsets.UTF_8);
    }

    /** {@code git-upload-pack '/fixture'}, served from the forge directory by JGit itself. */
    private final class UploadCommand implements Command {
        private final String command;
        private InputStream in;
        private OutputStream out;
        private OutputStream err;
        private ExitCallback exit;

        UploadCommand(String command) {
            this.command = command;
        }

        @Override
        public void setInputStream(InputStream in) {
            this.in = in;
        }

        @Override
        public void setOutputStream(OutputStream out) {
            this.out = out;
        }

        @Override
        public void setErrorStream(OutputStream err) {
            this.err = err;
        }

        @Override
        public void setExitCallback(ExitCallback exit) {
            this.exit = exit;
        }

        @Override
        public void start(ChannelSession channel, Environment env) {
            Thread.ofVirtual().start(() -> {
                String name = command.replaceFirst("^git-upload-pack '/?(.*)'$", "$1");
                try (Git forge = Git.open(dir.resolve("forge").resolve(name).toFile())) {
                    Repository repository = forge.getRepository();
                    uploads.incrementAndGet();
                    new UploadPack(repository).upload(in, out, err);
                    out.flush();
                    exit.onExit(0);
                } catch (Exception failure) {
                    exit.onExit(1, String.valueOf(failure.getMessage()));
                }
            });
        }

        @Override
        public void destroy(ChannelSession channel) {}
    }
}
