package com.asmolabs.vectispire.common.scanning;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

/**
 * The scanners' own configuration files, taken out of the clone before any of them runs.
 *
 * <p><b>The target does not configure its own audit.</b> Three of the pinned scanners read a file
 * from the tree they are pointed at, whatever the command line says: checkov a {@code .checkov.yaml}
 * or {@code .checkov.yml} in its {@code -d} directory (skipped checks, and an external checks
 * directory whose Python it then runs), gitleaks a {@code .gitleaksignore} in its {@code --source}
 * beside the {@code --config} Vectispire forces, and semgrep every {@code .semgrepignore} of the tree
 * despite {@code --no-git-ignore}. Each was measured on the pinned image to silence what the fixture
 * planted. A silenced scanner exits 0 with a clean report, and a clean report is an empty list, which
 * resolves the target's backlog of that type and passes the gate (decision 0007) — the repository
 * under audit closed its own findings. {@code SastScanner.mostlyFailed} sees only the extreme case,
 * a tree with nothing left to read.
 *
 * <p><b>Removed from the clone, not answered by a flag.</b> None of the three offers a switch that
 * turns the file off: an explicit {@code --config-file} for checkov is merged with the one it finds
 * in the tree rather than replacing it, gitleaks reads the tree's ignore file whatever
 * {@code --gitleaks-ignore-path} names, and semgrep has no option for its ignore file at all. The
 * clone is Vectispire's own copy, made for this scan and deleted with it, so taking the files out
 * changes nothing in the repository and holds for every scanner pointed at the tree, on the built-in
 * worker and on an agent alike — both run {@link ScanRunner}.
 *
 * <p><b>The whole clone, not the scanned directory.</b> The sub-path decides where checkov and
 * gitleaks look, and semgrep reads the file at any depth; walking the clone covers every sub-path a
 * repository can be registered with, and a scanner that one day looks one level up.
 *
 * <p><b>No link is followed, and a link is removed as a link.</b> A {@code .semgrepignore} pointing
 * elsewhere is as much the target's configuration as a regular file, and following one could reach
 * outside the clone. A directory bearing one of these names goes too: read as a configuration it
 * would make the scanner fail rather than run.
 */
public final class ScannerConfigurationFiles {

    /** The names the pinned scanners read from the analysed tree. */
    static final Set<String> NAMES = Set.of(".checkov.yaml", ".checkov.yml", ".gitleaksignore", ".semgrepignore");

    private ScannerConfigurationFiles() {}

    /**
     * Removes every file, link or directory bearing one of {@link #NAMES} under {@code clone}.
     *
     * @return the removed entries, relative to the clone, for the caller to say so
     * @throws UncheckedIOException when the tree cannot be walked or an entry cannot be removed — the
     *     scan then fails rather than run scanners the target may still configure
     */
    public static List<String> removeFrom(Path clone) {
        List<String> removed = new ArrayList<>();
        try {
            // No FOLLOW_LINKS: a link to a directory is visited as a file and never entered.
            Files.walkFileTree(clone, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path directory, BasicFileAttributes attributes)
                        throws IOException {
                    if (!directory.equals(clone) && isConfiguration(directory)) {
                        deleteTree(directory);
                        removed.add(clone.relativize(directory).toString());
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException {
                    if (isConfiguration(file)) {
                        // `Files.delete` removes a link itself, never what it points to.
                        Files.delete(file);
                        removed.add(clone.relativize(file).toString());
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException failure) throws IOException {
                    // A directory that cannot be read may hold one of the files: the scan fails
                    // rather than let a scanner that can read it be configured by it.
                    throw failure;
                }
            });
        } catch (IOException failure) {
            throw new UncheckedIOException(
                    "The scanners' configuration files could not be removed from the clone.", failure);
        }
        return List.copyOf(removed);
    }

    private static boolean isConfiguration(Path path) {
        Path name = path.getFileName();
        return name != null && NAMES.contains(name.toString());
    }

    /** A subtree, deepest first, links removed as links — and failing, unlike {@link Directories}. */
    private static void deleteTree(Path root) throws IOException {
        List<Path> entries;
        try (Stream<Path> walk = Files.walk(root)) {
            entries = walk.sorted(Comparator.reverseOrder()).toList();
        }
        for (Path entry : entries) {
            Files.delete(entry);
        }
    }
}
