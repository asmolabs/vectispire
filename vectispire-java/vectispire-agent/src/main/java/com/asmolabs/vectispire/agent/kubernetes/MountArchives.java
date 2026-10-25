package com.asmolabs.vectispire.agent.kubernetes;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;

/**
 * A mount's content as it crosses into a scan pod and back, over {@code exec} (decision 0045 §4) — what a
 * bind mount did on Docker.
 *
 * <p><b>Every entry goes in dated 1970.</b> What the scanner writes is then the only thing newer than a
 * day in the pod's copy, which is how {@code find -mtime -1} picks out what to bring back without a
 * marker file racing the scanner's first second. A scanner reading modification times reads a constant;
 * none of the pinned ones does.
 *
 * <p><b>Coming back, only regular files, and only inside the mount.</b> What the pod sends is written by a
 * scanner that read a hostile tree: an absolute name, a {@code ..}, a link, or a path through a link
 * already in the workspace would put a file where nobody asked for one. Each is refused, and the step
 * fails rather than half-copies.
 */
final class MountArchives {

    private static final FileTime EPOCH = FileTime.fromMillis(0);

    private MountArchives() {}

    /** The name {@code source}'s content has under its subdirectory: empty for a directory, its own name for a file. */
    static String nameOf(Path source) {
        return Files.isDirectory(source, LinkOption.NOFOLLOW_LINKS) ? "" : source.getFileName().toString();
    }

    /** Writes {@code source} — a directory's content, or one file — as a tar archive. */
    static void write(Path source, OutputStream out) throws IOException {
        try (TarArchiveOutputStream tar = new TarArchiveOutputStream(out)) {
            tar.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);
            tar.setBigNumberMode(TarArchiveOutputStream.BIGNUMBER_POSIX);
            if (!Files.isDirectory(source, LinkOption.NOFOLLOW_LINKS)) {
                add(tar, source, source.getFileName().toString());
            } else {
                try (Stream<Path> walk = Files.walk(source)) {
                    for (Path path : (Iterable<Path>) walk::iterator) {
                        if (!path.equals(source)) {
                            add(tar, path, source.relativize(path).toString().replace('\\', '/'));
                        }
                    }
                }
            }
            tar.finish();
        }
    }

    private static void add(TarArchiveOutputStream tar, Path path, String name) throws IOException {
        TarArchiveEntry entry;
        if (Files.isSymbolicLink(path)) {
            entry = new TarArchiveEntry(name, TarArchiveEntry.LF_SYMLINK);
            entry.setLinkName(Files.readSymbolicLink(path).toString());
        } else if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            entry = new TarArchiveEntry(name + "/");
        } else if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            entry = new TarArchiveEntry(name);
            entry.setSize(Files.size(path));
        } else {
            // A device or a FIFO in a workspace: git stores neither, so something else put it there.
            throw new IOException(name + " is neither a file, a directory nor a link.");
        }
        entry.setModTime(EPOCH);
        entry.setMode(mode(path, entry));
        tar.putArchiveEntry(entry);
        if (regular(entry)) {
            Files.copy(path, tar);
        }
        tar.closeArchiveEntry();
    }

    private static int mode(Path path, TarArchiveEntry entry) throws IOException {
        int type = entry.getMode() & ~0777;
        if (entry.isSymbolicLink()) {
            return type | 0777;
        }
        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS);
        int bits = 0;
        for (PosixFilePermission permission : permissions) {
            bits |= 1 << (8 - permission.ordinal());
        }
        return type | bits;
    }

    /**
     * A regular file by its type flag. Not {@link TarArchiveEntry#isFile()}: it answers true for a link, a
     * device or a FIFO whose name does not end with a slash — which let a link through, and was caught here.
     */
    private static boolean regular(TarArchiveEntry entry) {
        byte flag = entry.getLinkFlag();
        return flag == TarArchiveEntry.LF_NORMAL || flag == TarArchiveEntry.LF_OLDNORM;
    }

    /**
     * Writes into {@code destination} the regular files of {@code archive}, refusing anything else.
     *
     * @return the files written, relative to {@code destination}
     */
    static List<String> extractWritten(InputStream archive, Path destination) throws IOException {
        Path root = destination.toRealPath();
        java.util.ArrayList<String> written = new java.util.ArrayList<>();
        try (TarArchiveInputStream tar = new TarArchiveInputStream(archive)) {
            for (TarArchiveEntry entry; (entry = tar.getNextEntry()) != null; ) {
                String name = entry.getName();
                if (entry.isDirectory()) {
                    continue;
                }
                if (!regular(entry)) {
                    throw new IOException("It wrote " + name + ", which is not a regular file; nothing is brought back but files.");
                }
                Path target = root.resolve(name).normalize();
                if (name.startsWith("/") || !target.startsWith(root) || target.equals(root)) {
                    throw new IOException("It wrote " + name + ", a name outside its mount.");
                }
                // Through no link, existing or not: a link in the workspace would carry the write elsewhere.
                Path at = root;
                for (Path part : root.relativize(target.getParent())) {
                    if (part.toString().isEmpty()) {
                        continue;
                    }
                    at = at.resolve(part);
                    if (Files.isSymbolicLink(at)) {
                        throw new IOException("It wrote " + name + " through the link " + root.relativize(at) + ".");
                    }
                }
                if (Files.isSymbolicLink(target)) {
                    throw new IOException("It wrote " + name + " over a link.");
                }
                Files.createDirectories(target.getParent());
                Files.copy(tar, target, StandardCopyOption.REPLACE_EXISTING);
                written.add(root.relativize(target).toString());
            }
        }
        return written;
    }
}
