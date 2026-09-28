package com.asmolabs.vectispire.common.scanning;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.UserPrincipal;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The rules Vectispire ships, materialised where a scanner can read them.
 *
 * <p><b>They live in the jar and the scanners need files.</b> Semgrep and gitleaks run as sibling
 * containers with the workspace bind-mounted, and a bind mount is resolved by the Docker
 * <em>daemon</em>: a path inside Vectispire's own jar does not exist as far as it is concerned.
 * Decision 0006 records the same conclusion for the workspace copy.
 *
 * <p><b>Before this class the path was {@code Path.of("rules")}</b> — relative to whatever
 * directory the process happened to start in. No such directory exists in the repository, in the
 * jar, or in the container image, so <em>every</em> repository scan failed at rule placement with
 * "could not place rules from rules". Container scans were unaffected, which is why it went
 * unnoticed: they run the dependency step alone and never place a rule.
 *
 * <p><b>The gitleaks configuration is the part that matters most.</b> Without it the scanner
 * falls back to a `.gitleaks.toml` inside the repository being scanned — written by whoever is
 * being audited — and an empty file with a universal allowlist switches detection off with no
 * error at all.
 */
public final class BundledRules {

    /** Kept in step with `src/main/resources/rules/` by {@code BundledRulesTest}. */
    private static final List<String> FILES =
            List.of("gitleaks/gitleaks.toml", "semgrep/python/dangerous-eval.yaml");

    private static final String ROOT = "/rules/";

    private BundledRules() {}

    /** What every process's directory is named after, and all the sweep ever looks at. */
    static final String PREFIX = "vectispire-bundled-rules-";

    /** Held for the process's life inside its directory, beside the tree and never in it. */
    static final String IN_USE = ".in-use";

    /** The tree the scanners are handed; a subdirectory, so the lock is never copied into a workspace. */
    static final String TREE = "tree";

    /**
     * The locks this process holds. A {@link FileLock} lasts as long as its channel, and a channel
     * nothing references is closed when it is collected — the directory would then look abandoned
     * to the next process that starts.
     */
    private static final List<FileChannel> HELD = new CopyOnWriteArrayList<>();

    /**
     * Copies the bundled tree to a directory of its own and returns it, after sweeping the ones
     * earlier processes left behind.
     *
     * <p>Done once at startup rather than per scan: the content never changes while the process
     * runs, and unpacking it for every scan would be work with no possible different outcome.
     *
     * <p><b>Each start made one, and nothing ever removed one.</b> In the composition the
     * temporary directory is the host's work directory, which outlives every container, so a
     * {@code vectispire-bundled-rules-*} accumulated there at each start of the control plane or
     * the agent. The directory is now deleted when the process stops, and what a process that
     * could not stop cleanly left is swept at the next start — see {@link #sweep}.
     */
    public static Path materialise() {
        Path directory;
        try {
            directory = Files.createTempDirectory(PREFIX);
            FileChannel lock = FileChannel.open(
                    directory.resolve(IN_USE), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
            lock.lock();
            HELD.add(lock);
        } catch (IOException failed) {
            throw new UncheckedIOException("Could not create a directory for the bundled rules", failed);
        }
        Runtime.getRuntime().addShutdownHook(Thread.ofPlatform().unstarted(() -> deleteTree(directory)));
        ProcessHandle.current().info().startInstant().ifPresent(started -> {
            try {
                sweep(directory.getParent(), Files.getOwner(directory), started, directory);
            } catch (IOException | UnsupportedOperationException noOwner) {
                // No owner to compare with: nothing is swept, which leaves directories behind and
                // deletes nothing that might not be ours.
            }
        });
        return materialise(directory.resolve(TREE));
    }

    /**
     * Deletes what earlier processes left in {@code parent}, and nothing else.
     *
     * <p>An entry goes only when all of these hold: its name has {@link #PREFIX}; it is a
     * directory and not a link to one (a link is never followed, so a {@code
     * vectispire-bundled-rules-x} pointing at {@code /} deletes nothing); it belongs to {@code
     * owner}, this process's user; it was last written before {@code processStarted}; and no
     * process holds the lock inside it. The last one is what the others cannot say: a control
     * plane and an agent sharing a temporary directory, or two instances on one host, each start
     * before the other's check, and "older than me" alone would have one delete the rules the
     * other is scanning with. A dead process holds no lock — the kernel releases it however the
     * process ended — so what is left unlocked is a leftover. A directory from a version before
     * the lock has none, and is swept as the leftover it is.
     *
     * <p>On Linux {@code processStarted} reads up to a second early: the JDK adds the start in
     * clock ticks to a boot time counted in whole seconds. The error only ever keeps — a
     * leftover of a process killed in the second before this one started waits for the next
     * sweep — and never deletes, so it is accepted rather than corrected with a margin that
     * would narrow what the lock does not cover.
     *
     * @param keep this process's own directory, never examined
     */
    static void sweep(Path parent, UserPrincipal owner, Instant processStarted, Path keep) {
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(parent, PREFIX + "*")) {
            for (Path entry : entries) {
                if (!entry.equals(keep) && abandoned(entry, owner, processStarted)) {
                    deleteTree(entry);
                }
            }
        } catch (IOException | UncheckedIOException unlisted) {
            // A directory that cannot be listed is left as it is; the next start tries again.
        }
    }

    private static boolean abandoned(Path entry, UserPrincipal owner, Instant processStarted) {
        try {
            BasicFileAttributes attributes =
                    Files.readAttributes(entry, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (!attributes.isDirectory()
                    || !owner.equals(Files.getOwner(entry, LinkOption.NOFOLLOW_LINKS))
                    || !attributes.lastModifiedTime().toInstant().isBefore(processStarted)) {
                return false;
            }
            return !inUse(entry.resolve(IN_USE));
        } catch (IOException | UnsupportedOperationException unreadable) {
            return false;
        }
    }

    private static boolean inUse(Path lockFile) throws IOException {
        if (!Files.isRegularFile(lockFile, LinkOption.NOFOLLOW_LINKS)) {
            return false;
        }
        try (FileChannel channel = FileChannel.open(lockFile, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
            FileLock lock = channel.tryLock();
            if (lock == null) {
                return true;
            }
            lock.release();
            return false;
        } catch (OverlappingFileLockException heldHere) {
            // This very JVM holds it: another materialisation of this process, in use.
            return true;
        }
    }

    /** Depth first, links removed as links and never followed; what fails is left for the next sweep. */
    static void deleteTree(Path root) {
        try {
            Files.walkFileTree(root, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException {
                    Files.deleteIfExists(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path directory, IOException failed) throws IOException {
                    Files.deleteIfExists(directory);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException leftBehind) {
            // Swept by the next start, which finds it unlocked.
        }
    }

    public static Path materialise(Path into) {
        try {
            for (String file : FILES) {
                Path target = into.resolve(file);
                Files.createDirectories(target.getParent());
                try (InputStream source = BundledRules.class.getResourceAsStream(ROOT + file)) {
                    if (source == null) {
                        // A packaging mistake, and one that would otherwise surface as a scan
                        // that "found nothing" — the worst possible symptom for a secrets rule.
                        throw new IllegalStateException(
                                "Bundled rule " + file + " is missing from the jar. Vectispire cannot scan a "
                                        + "repository without it: gitleaks would fall back to a configuration "
                                        + "supplied by the repository being scanned.");
                    }
                    Files.copy(source, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }
            }
            return into;
        } catch (IOException failed) {
            throw new UncheckedIOException("Could not unpack the bundled rules to " + into, failed);
        }
    }

    /** The files this jar is expected to carry, for a test that keeps the list honest. */
    public static List<String> expected() {
        return FILES;
    }

    /**
     * The content of one bundled file, as it will be handed to the scanner.
     *
     * <p>Read for the rules a scan runs with but nobody uploaded: the OWASP grid asks which
     * categories the <em>installed</em> rules declare, and on a fresh instance the installed
     * rules are exactly these. Answering "none" there would understate coverage for the same
     * reason {@link #expected()} is counted by the rule-coverage assessment.
     *
     * @throws IllegalStateException when the jar does not carry the file — a packaging mistake,
     *     and the same one {@link #materialise(Path)} refuses to paper over
     */
    public static String contentOf(String file) {
        try (InputStream source = BundledRules.class.getResourceAsStream(ROOT + file)) {
            if (source == null) {
                throw new IllegalStateException("Bundled rule " + file + " is missing from the jar.");
            }
            return new String(source.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (IOException failed) {
            throw new UncheckedIOException("Could not read the bundled rule " + file, failed);
        }
    }
}
