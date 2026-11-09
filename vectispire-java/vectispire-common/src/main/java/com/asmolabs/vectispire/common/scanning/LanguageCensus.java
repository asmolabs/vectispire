package com.asmolabs.vectispire.common.scanning;

import com.asmolabs.vectispire.common.domain.plugins.Language;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;
import java.util.function.LongSupplier;

/**
 * Which languages a checked-out tree is written in — enough to say whether a plugin applies.
 *
 * <h2>Why the answer has a third value</h2>
 *
 * <p>A plugin that reads Java has nothing to say about a Python repository, and running it would
 * return an empty SARIF: "analysed, found nothing", which resolves the plugin's issues on that
 * target (decision 0007). Not running it is right, and it must be <em>reported</em> as neither of
 * the other two states — not empty, which resolves, not absent, which is a failure somebody should
 * look at. That state is {@code PluginStep.NotApplicable}, and this census is what decides it.
 *
 * <p><b>So the census must never under-report.</b> A missed language turns a plugin that should
 * have run into "not applicable", which leaves its issues open where it could have resolved them —
 * the safe direction, but still a scan that did not happen. A walk that hits its bounds therefore
 * says so ({@link Census#complete()} false), and the caller runs every plugin rather than trusting a
 * partial count.
 *
 * <h2>Bounded like every read of the tree in this process</h2>
 *
 * <p>The tree is somebody else's, and in the built-in worker this runs inside the control plane.
 * No file is opened: names only, through {@link Language#ofFileName}, which is linear and has no
 * pattern to backtrack. Links are not followed and not counted — a {@code src -> /} must not walk
 * the host. The walk stops at {@link #MAX_ENTRIES} entries or at its deadline, and early when every
 * language anybody asked about has been seen.
 */
public final class LanguageCensus {

    /** More than any real repository's source files; less than a tree built to exhaust the walk. */
    public static final int MAX_ENTRIES = 200_000;

    public static final Duration DEADLINE = Duration.ofSeconds(60);

    /**
     * Directories never looked into: a clone's own metadata and the one dependency tree that routinely
     * outnumbers the code. {@code node_modules} is always accompanied by the {@code package.json} that
     * installed it, which names JavaScript on its own.
     */
    private static final Set<String> SKIPPED = Set.of(".git", "node_modules");

    private LanguageCensus() {}

    /**
     * @param found the languages seen, as far as the walk went
     * @param complete false when the walk stopped before the end of the tree — its bound, its
     *     deadline, or an unreadable directory — so an absent language proves nothing
     */
    public record Census(Set<Language> found, boolean complete) {

        public Census {
            found = found == null || found.isEmpty() ? Set.of() : Collections.unmodifiableSet(EnumSet.copyOf(found));
        }

        /**
         * Whether a plugin declaring these languages should run. An incomplete census runs it: it
         * cannot prove the plugin's languages absent, and "not applicable" is a claim.
         */
        public boolean applies(Set<Language> declared) {
            if (!complete) {
                return true;
            }
            for (Language language : declared) {
                if (found.contains(language)) {
                    return true;
                }
            }
            return false;
        }
    }

    /** The whole census, stopping early once every language in {@code wanted} has been seen. */
    public static Census of(Path root, Set<Language> wanted) {
        return of(root, wanted, MAX_ENTRIES, DEADLINE, System::nanoTime);
    }

    static Census of(Path root, Set<Language> wanted, int maxEntries, Duration deadline, LongSupplier nanoClock) {
        if (root == null || !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
            // Nothing to count is not "no language": the caller decides what a missing tree means,
            // and it is not this class's to turn into "not applicable".
            return new Census(Set.of(), false);
        }
        Set<Language> target = wanted == null || wanted.isEmpty() ? Set.of() : EnumSet.copyOf(wanted);
        Set<Language> found = EnumSet.noneOf(Language.class);
        long giveUpAt = nanoClock.getAsLong() + deadline.toNanos();

        final class Walk extends SimpleFileVisitor<Path> {
            int entries;
            boolean complete = true;

            private FileVisitResult budget() {
                entries++;
                if (entries > maxEntries || nanoClock.getAsLong() - giveUpAt > 0) {
                    complete = false;
                    return FileVisitResult.TERMINATE;
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attributes) {
                FileVisitResult spent = budget();
                if (spent != FileVisitResult.CONTINUE) {
                    return spent;
                }
                Path name = dir.getFileName();
                if (!dir.equals(root) && name != null && SKIPPED.contains(name.toString().toLowerCase(Locale.ROOT))) {
                    return FileVisitResult.SKIP_SUBTREE;
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) {
                FileVisitResult spent = budget();
                if (spent != FileVisitResult.CONTINUE) {
                    return spent;
                }
                if (attributes.isRegularFile() && !attributes.isSymbolicLink()) {
                    Path name = file.getFileName();
                    if (name != null) {
                        found.addAll(Language.ofFileName(name.toString()));
                    }
                }
                if (!target.isEmpty() && found.containsAll(target)) {
                    // Everything anybody asked about is here: the rest of the tree cannot change
                    // a single answer, so the census is complete for its purpose.
                    return FileVisitResult.TERMINATE;
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException failure) {
                // An unreadable directory hides what is under it: the count can no longer prove an
                // absence. The walk goes on for whatever else it can see.
                complete = false;
                return FileVisitResult.CONTINUE;
            }
        }

        Walk walk = new Walk();
        try {
            Files.walkFileTree(root, walk);
        } catch (IOException unwalkable) {
            return new Census(found, false);
        }
        return new Census(found, walk.complete);
    }
}
