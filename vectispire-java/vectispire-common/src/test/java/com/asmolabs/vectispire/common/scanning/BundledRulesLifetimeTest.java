package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.UserPrincipal;
import java.time.Instant;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The bundled rules' directory lives as long as its process, and a leftover is swept — only that.
 *
 * <p><b>Every start made a {@code vectispire-bundled-rules-*} and nothing ever deleted one.</b> In
 * the composition the temporary directory is the host's work directory, so they piled up there at
 * each restart. The sweep that cures it runs in a directory other processes use, so what it must
 * not delete is pinned as carefully as what it must.
 */
@DisplayName("the bundled rules' directory")
class BundledRulesLifetimeTest {

    private static final Instant STARTED = Instant.parse("2026-09-28T12:00:00Z");
    private static final FileTime BEFORE = FileTime.from(STARTED.minusSeconds(3600));

    @Test
    @DisplayName("a leftover of an earlier process is swept, lock file or none")
    void aLeftoverGoes(@TempDir Path tmp) throws IOException {
        Path locked = leftover(tmp, "vectispire-bundled-rules-1", true);
        Path fromBeforeTheLock = leftover(tmp, "vectispire-bundled-rules-2", false);

        BundledRules.sweep(tmp, Files.getOwner(tmp), STARTED, tmp.resolve("mine"));

        assertThat(locked).doesNotExist();
        assertThat(fromBeforeTheLock).doesNotExist();
    }

    @Test
    @DisplayName("nothing else goes: another name, a file, a link, a newer directory, this process's own")
    void nothingElseGoes(@TempDir Path tmp, @TempDir Path elsewhere) throws IOException {
        Path otherName = leftover(tmp, "vectispire-scan-1", false);
        Path file = Files.writeString(tmp.resolve("vectispire-bundled-rules-file"), "x");
        Files.setLastModifiedTime(file, BEFORE);
        Path target = Files.writeString(elsewhere.resolve("precious"), "keep");
        Path link = Files.createSymbolicLink(tmp.resolve("vectispire-bundled-rules-link"), elsewhere);
        Path newer = Files.createDirectories(tmp.resolve("vectispire-bundled-rules-newer"));
        Files.setLastModifiedTime(newer, FileTime.from(STARTED.plusSeconds(1)));
        Path mine = leftover(tmp, "vectispire-bundled-rules-mine", true);

        BundledRules.sweep(tmp, Files.getOwner(tmp), STARTED, mine);

        assertThat(otherName).isDirectory();
        assertThat(file).isRegularFile();
        assertThat(link).isSymbolicLink();
        assertThat(target).hasContent("keep");
        assertThat(newer).isDirectory();
        assertThat(mine).isDirectory();
    }

    @Test
    @DisplayName("another user's directory stays")
    void anotherUsersStays(@TempDir Path tmp) throws IOException {
        Path theirs = leftover(tmp, "vectispire-bundled-rules-theirs", false);
        var users = tmp.getFileSystem().getUserPrincipalLookupService();
        UserPrincipal root = users.lookupPrincipalByName("root");
        UserPrincipal someoneElse = Files.getOwner(theirs).equals(root) ? users.lookupPrincipalByName("nobody") : root;
        assertThat(Files.getOwner(theirs)).isNotEqualTo(someoneElse);

        // Swept as if this process ran as somebody else: the directory is not theirs, so it is not ours.
        BundledRules.sweep(tmp, someoneElse, STARTED, tmp.resolve("mine"));

        assertThat(theirs).isDirectory();
    }

    @Test
    @DisplayName("a directory whose lock is held stays, however old: a live process is scanning with it")
    void aHeldOneStays(@TempDir Path tmp) throws IOException {
        Path live = leftover(tmp, "vectispire-bundled-rules-live", true);
        try (FileChannel held = FileChannel.open(live.resolve(BundledRules.IN_USE), StandardOpenOption.WRITE)) {
            held.lock();
            Files.setLastModifiedTime(live, BEFORE);

            BundledRules.sweep(tmp, Files.getOwner(tmp), STARTED, tmp.resolve("mine"));

            assertThat(live).isDirectory();
        }
    }

    /**
     * The whole life, in real processes: the kernel's lock is what tells a live sibling from a
     * dead one, and a JVM's own lock cannot show that.
     */
    @Test
    @DisplayName("a live process's directory survives a sweep, goes when it stops, and a killed one's goes at the next sweep")
    void inRealProcesses(@TempDir Path tmp) throws Exception {
        Child running = Child.start(tmp);
        Path directory = running.directory();
        assertThat(directory.resolve(BundledRules.TREE).resolve("gitleaks/gitleaks.toml")).isRegularFile();
        assertThat(directory.resolve(BundledRules.TREE).resolve(BundledRules.IN_USE)).doesNotExist();

        // Swept by a process started after it: older, same user, and still it stays — it is held.
        BundledRules.sweep(tmp, Files.getOwner(tmp), Instant.now().plusSeconds(60), tmp.resolve("mine"));
        assertThat(directory).isDirectory();

        running.stop();
        assertThat(directory).as("a process that stops deletes its own directory").doesNotExist();

        Child killed = Child.start(tmp);
        killed.kill();
        assertThat(killed.directory()).as("a killed process deletes nothing").isDirectory();
        Child next = Child.start(tmp);
        try {
            assertThat(killed.directory()).as("and its directory is a leftover the next start sweeps").doesNotExist();
            assertThat(next.directory()).isDirectory();
        } finally {
            next.stop();
        }
    }

    private static Path leftover(Path tmp, String name, boolean withLock) throws IOException {
        Path directory = Files.createDirectories(tmp.resolve(name));
        Files.createDirectories(directory.resolve(BundledRules.TREE).resolve("gitleaks"));
        Files.writeString(directory.resolve(BundledRules.TREE).resolve("gitleaks/gitleaks.toml"), "x");
        if (withLock) {
            Files.createFile(directory.resolve(BundledRules.IN_USE));
        }
        Files.setLastModifiedTime(directory, BEFORE);
        return directory;
    }

    /** A JVM that materialises the rules in {@code tmp}, says where, and waits for its stdin to close. */
    private record Child(Process process, Path directory) {

        static Child start(Path tmp) throws IOException {
            String java = ProcessHandle.current().info().command().orElseThrow();
            Process process = new ProcessBuilder(java, "-Djava.io.tmpdir=" + tmp,
                            "-cp", System.getProperty("java.class.path"), Main.class.getName())
                    .redirectError(ProcessBuilder.Redirect.INHERIT)
                    .start();
            BufferedReader out = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
            String tree = out.readLine();
            assertThat(tree).as("the child printed its directory").isNotNull();
            return new Child(process, Path.of(tree).getParent());
        }

        void stop() throws Exception {
            process.getOutputStream().close();
            assertThat(process.waitFor(30, TimeUnit.SECONDS)).isTrue();
        }

        void kill() throws Exception {
            process.destroyForcibly();
            assertThat(process.waitFor(30, TimeUnit.SECONDS)).isTrue();
        }
    }

    /** The child's entry point. */
    public static final class Main {
        public static void main(String[] args) throws IOException {
            System.out.println(BundledRules.materialise());
            System.out.flush();
            // Until the parent closes stdin; then a normal exit, which runs the shutdown hooks.
            while (System.in.read() >= 0) {
                // Nothing to read.
            }
        }
    }
}
