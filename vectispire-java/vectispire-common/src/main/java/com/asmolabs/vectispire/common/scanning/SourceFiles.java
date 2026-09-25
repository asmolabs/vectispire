package com.asmolabs.vectispire.common.scanning;

import com.asmolabs.vectispire.common.domain.targets.RepositorySubPath;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Optional;

/**
 * Reading a file of the repository under analysis, inside the JVM.
 *
 * <p><b>The content is the author's, and so is its shape.</b> The scanners in containers are
 * bounded by the container; the manifest reader and the API discovery run in this process, and
 * read with {@code Files.readString}, which follows symbolic links and has no ceiling. A committed
 * {@code a.js -> /dev/zero} never reached end of file: the {@link OutOfMemoryError} escaped every
 * {@code catch (Exception)} and took the embedded worker — the whole control plane — down with it.
 * A {@code package.json -> /etc/…} read a host file into the recorded version. A 1 GB source file
 * did the first without the link.
 *
 * <p>So a file is read only if it is a regular file <em>itself</em> — not through a link — and only
 * up to a size no source file or manifest reaches, the same order as Semgrep's own
 * {@code --max-target-bytes}. The bound is enforced while reading too: a file can grow between the
 * size check and the read.
 */
public final class SourceFiles {

    private SourceFiles() {}

    /** Larger than any manifest or source file worth parsing; smaller than any heap. */
    public static final long MAX_BYTES = 2L * 1024 * 1024;

    /** A regular file, not reached through a symbolic link. */
    public static boolean isRegularFile(Path file) {
        return Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS);
    }

    /** Whether a walk should read this entry at all — the walk's attributes do not follow links. */
    public static boolean isReadable(BasicFileAttributes attributes) {
        return attributes.isRegularFile() && !attributes.isSymbolicLink() && attributes.size() <= MAX_BYTES;
    }

    /**
     * The file as UTF-8 text, or empty when it is a link, not a regular file, or too large.
     *
     * @throws IOException when a regular file of acceptable size cannot be read
     */
    public static Optional<String> readText(Path file) throws IOException {
        return readBytes(file).map(bytes -> new String(bytes, StandardCharsets.UTF_8));
    }

    /** The same bytes, for a parser that wants a stream. */
    public static Optional<byte[]> readBytes(Path file) throws IOException {
        BasicFileAttributes attributes;
        try {
            attributes = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        } catch (java.nio.file.NoSuchFileException absent) {
            return Optional.empty();
        }
        if (!isReadable(attributes)) {
            return Optional.empty();
        }
        // NOFOLLOW_LINKS on the open as well: the entry checked above could have been replaced by
        // a link since, and O_NOFOLLOW refuses to open one.
        try (InputStream in = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) {
            byte[] bytes = in.readNBytes((int) MAX_BYTES + 1);
            return bytes.length > MAX_BYTES ? Optional.empty() : Optional.of(bytes);
        }
    }

    /**
     * The directory a scan is limited to, proven to lie inside the clone.
     *
     * <p>The syntax rule first ({@link RepositorySubPath}), then the file system's answer: a
     * directory of the repository may itself be a link — {@code docs -> /} — and only the real path
     * says where it leads.
     *
     * @throws IllegalArgumentException when the sub-path is refused, or leads out of the clone
     * @throws IOException when the clone or the sub-path cannot be resolved
     */
    public static Path within(Path source, String subPath) throws IOException {
        String relative = RepositorySubPath.normalize(subPath);
        Path root = source.toRealPath();
        Path candidate = relative.isEmpty() ? root : root.resolve(relative).normalize();
        if (!Files.exists(candidate, LinkOption.NOFOLLOW_LINKS)) {
            // Absent from this checkout: the analysers report that themselves, and it is not a
            // way out of the clone.
            return candidate;
        }
        Path real = candidate.toRealPath();
        if (!real.startsWith(root)) {
            throw new IllegalArgumentException("The sub-path \"" + relative + "\" leads outside the repository.");
        }
        return real;
    }
}
