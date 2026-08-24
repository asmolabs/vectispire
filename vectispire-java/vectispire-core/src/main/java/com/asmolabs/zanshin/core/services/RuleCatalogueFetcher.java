package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.crypto.Digests;
import com.asmolabs.zanshin.common.domain.rules.RuleCatalogue;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.springframework.stereotype.Service;

/**
 * Fetches the upstream rule catalogue, once, on an operator's instruction.
 *
 * <p><b>Zanshin does not redistribute these rules</b> — the whole point of decision 0006. They
 * travel from their author to this installation because somebody here asked for them, and
 * nothing Zanshin ships contains them.
 *
 * <p><b>The URL is a constant, not a parameter.</b> An operator-supplied clone URL would be a
 * request this server makes to an address a caller chose, which is the definition of the hole
 * the outbound guard exists to close. Fixing the upstream removes the question instead of
 * answering it, and decision 0006 names exactly one permitted source anyway.
 *
 * <p><b>A tag, never a branch.</b> Cloned as {@code refs/tags/…} at depth 1: the same tag
 * fetched twice yields the same rules, which is what keeps a scan reproducible. The resolved
 * commit is recorded so that "which rules ran" has an answer a year later.
 */
@Service
public class RuleCatalogueFetcher {

    /** Anonymous HTTPS: these are public rules, and no credential should be anywhere near this. */
    private static final String URL = "https://github.com/" + RuleCatalogue.UPSTREAM + ".git";

    /** The only branch the upstream publishes; it carries no tags at all. */
    private static final String BRANCH = "main";

    private static final Duration TIMEOUT = Duration.ofMinutes(5);

    /**
     * A ceiling on what is read into memory.
     *
     * <p>Well above the catalogue's real size and well below what would trouble the process.
     * Without it, an upstream that grew a large binary — or a tag that is not what it claims —
     * would be read until the heap ran out, and an {@code OutOfMemoryError} says nothing about
     * the cause.
     */
    private static final long MAX_BYTES = 128L * 1024 * 1024;

    /**
     * @param commit the resolved SHA-1 of what was actually fetched
     * @param licenceSha256 what the operator's acceptance is bound to. Comparing it on the way
     *     back is what stops the accepted licence and the fetched one being two different texts
     */
    public record Fetched(String commit, RuleCatalogue.Contents contents, String licenceSha256) {}

    public Fetched fetch() {
        RuleCatalogue.requireAllowed(RuleCatalogue.UPSTREAM);

        Path checkout = temporaryDirectory();
        try {
            String commit = cloneHead(checkout);
            List<RuleCatalogue.Entry> entries = read(checkout);
            String licence = licenceOf(entries);
            return new Fetched(
                    commit,
                    RuleCatalogue.describe(entries, licence),
                    Digests.sha256Hex(licence.getBytes(StandardCharsets.UTF_8)));
        } finally {
            // Deleted whatever happened: a failed clone leaves a partial tree, and a temporary
            // directory nobody removes is how a disk fills over months without a single error.
            deleteRecursively(checkout);
        }
    }

    /**
     * Clones the default branch at depth 1 and reports what that resolved to.
     *
     * <p>Depth 1 because the history is of no interest, and the difference is not small: the
     * shallow clone is 20 MB and takes under two seconds, which is what makes reading the
     * catalogue an acceptable thing to do from a screen.
     */
    private static String cloneHead(Path into) {
        String ref = "refs/heads/" + BRANCH;
        try (Git repository = Git.cloneRepository()
                .setURI(URL)
                .setDirectory(into.toFile())
                .setBranch(ref)
                .setBranchesToClone(List.of(ref))
                .setDepth(1)
                .setCloneSubmodules(false)
                .setTimeout((int) TIMEOUT.toSeconds())
                .call()) {
            return repository.getRepository().resolve("HEAD").name();
        } catch (GitAPIException | IOException | RuntimeException failure) {
            throw new FetchFailureException(
                    "Could not reach " + RuleCatalogue.UPSTREAM + ". (" + rootMessage(failure) + ")", failure);
        }
    }

    private static List<RuleCatalogue.Entry> read(Path checkout) {
        List<RuleCatalogue.Entry> entries = new ArrayList<>();
        long[] total = {0};
        try (var paths = Files.walk(checkout)) {
            paths.filter(Files::isRegularFile)
                    .filter(path -> !checkout.relativize(path).startsWith(".git"))
                    .filter(RuleCatalogueFetcher::isInteresting)
                    .sorted(Comparator.naturalOrder())
                    .forEach(path -> {
                        try {
                            total[0] += Files.size(path);
                            if (total[0] > MAX_BYTES) {
                                throw new FetchFailureException(
                                        "The catalogue exceeds " + (MAX_BYTES / 1024 / 1024)
                                                + " MB; refusing to read it into memory.");
                            }
                            entries.add(new RuleCatalogue.Entry(
                                    checkout.relativize(path).toString().replace('\\', '/'),
                                    Files.readString(path, StandardCharsets.UTF_8)));
                        } catch (IOException unreadable) {
                            throw new UncheckedIOException(unreadable);
                        }
                    });
        } catch (IOException unreadable) {
            throw new FetchFailureException("Could not read the fetched catalogue.", unreadable);
        }
        return entries;
    }

    /** Rule files and the licence. Everything else is tests, CI and documentation. */
    private static boolean isInteresting(Path path) {
        String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
        return name.endsWith(".yaml") || name.endsWith(".yml") || name.startsWith("license");
    }

    /**
     * The licence as it stands at this tag.
     *
     * <p>Read from the checkout and never from a copy kept here: a licence can change between
     * tags, and showing a stored copy would let somebody accept a text that is not the one they
     * are about to receive. Absence is a refusal, not a default — rules with no licence in front
     * of them are rules nobody agreed to.
     */
    private static String licenceOf(List<RuleCatalogue.Entry> entries) {
        return entries.stream()
                .filter(entry -> !entry.path().contains("/"))
                .filter(entry -> entry.path().toLowerCase(Locale.ROOT).startsWith("license"))
                .map(RuleCatalogue.Entry::content)
                .findFirst()
                .orElseThrow(() -> new FetchFailureException(
                        "No LICENSE file at the root of " + RuleCatalogue.UPSTREAM
                                + " at this tag. Refusing to offer rules whose terms cannot be shown."));
    }

    private static Path temporaryDirectory() {
        try {
            return Files.createTempDirectory("zanshin-rules-");
        } catch (IOException failed) {
            throw new FetchFailureException("Could not create a working directory for the fetch.", failed);
        }
    }

    private static void deleteRecursively(Path root) {
        if (!Files.exists(root)) {
            return;
        }
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
        } catch (IOException ignored) {
            // Logged nowhere and thrown nowhere: the fetch either succeeded or already failed for
            // a reason the caller is being told about, and "could not delete a temp directory"
            // would replace that reason with a worse one.
        }
    }

    private static String rootMessage(Throwable failure) {
        Throwable cause = failure;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        return String.valueOf(cause.getMessage());
    }

    /** A fetch that did not produce a catalogue. Always carries why. */
    public static class FetchFailureException extends RuntimeException {

        private static final long serialVersionUID = 1L;

        public FetchFailureException(String message) {
            super(message);
        }

        public FetchFailureException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
