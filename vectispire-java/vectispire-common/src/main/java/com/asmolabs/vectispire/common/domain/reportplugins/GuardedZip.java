package com.asmolabs.vectispire.common.domain.reportplugins;

import com.asmolabs.vectispire.common.domain.text.BoundedText;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Predicate;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;

/**
 * A report plugin's zip-based output read through the guards of the checklist template importer ({@code
 * WorkbookReader}, decision 0032 §11), and two more a document the platform signs needs (decision 0035 §3).
 *
 * <h2>The importer's guards</h2>
 *
 * <p>Checked as the entries are inflated, never from what the archive says of itself — a zip bomb's declared
 * sizes are a lie: at most {@code maxEntries} entries, each inflated to at most {@code maxEntryBytes} and all of
 * them to {@code maxInflatedBytes}, and an entry inflating more than {@code maxRatio} times the compressed bytes
 * its inflater consumed is refused once past a grace too small to hurt. Every entry goes through the counter, the
 * ones not kept too. A name held twice is refused (two readers would each open a different one), and so is an
 * archive inside the archive, by its name or its first four bytes — an embedded workbook is a document nobody
 * checked.
 *
 * <h2>And two of its own</h2>
 *
 * <p><b>No absolute name, no {@code ..} segment, no backslash.</b> The importer writes nothing to disk and could
 * let a name be a name; a recipient's unzip tool writes where the name says.
 *
 * <p><b>The central directory names what the local headers do, in the same order.</b> This reads the local
 * headers, from the front, as {@link ZipInputStream} does; Office, LibreOffice and every unzip tool read the
 * central directory at the end. A file whose two halves disagree shows the check one package and the recipient
 * another — a macro part listed only in the directory would be invisible here. So the directory is read too, and
 * any disagreement, data after it, or a ZIP64 directory (no document under the 50 MiB ceiling needs one) is
 * refused.
 */
final class GuardedZip {

    /** Where the bounds come from: the importer's, with the ceilings a whole rendered document needs. */
    record Limits(int maxEntries, long maxEntryBytes, long maxInflatedBytes, int maxRatio, long ratioGraceBytes) {}

    /**
     * One entry: its name as the archive gives it, its compression method, and its bytes when the caller asked
     * to keep it (empty otherwise — nobody reads a discarded part).
     */
    record Entry(String name, boolean directory, int method, byte[] bytes) {}

    private static final byte[] LOCAL_HEADER = {'P', 'K', 3, 4};
    private static final int CENTRAL_HEADER = 0x02014b50;
    private static final int END_OF_DIRECTORY = 0x06054b50;
    private static final int END_OF_DIRECTORY_SIZE = 22;

    private static final Set<String> ARCHIVE_SUFFIXES = Set.of(
            ".zip", ".jar", ".gz", ".tgz", ".tar", ".7z", ".rar", ".xlsx", ".xlsm", ".xlsb", ".xltx", ".xltm", ".docx",
            ".docm", ".pptx", ".pptm", ".ods", ".odt");

    private final Limits limits;

    GuardedZip(Limits limits) {
        this.limits = limits;
    }

    /**
     * Every entry, in the archive's order.
     *
     * @param keep which entries' bytes to hand back, by their lower-cased name
     * @throws OutputRefused past a guard, or not a readable zip
     */
    List<Entry> read(byte[] file, Predicate<String> keep) {
        if (!startsWith(file, LOCAL_HEADER)) {
            throw new OutputRefused("it is not a zip archive.");
        }
        List<String> directory = centralDirectory(file);
        List<Entry> entries = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        long[] inflated = {0};
        try (CountingZip zip = new CountingZip(new ByteArrayInputStream(file))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (entries.size() == limits.maxEntries()) {
                    throw new OutputRefused("its zip holds more than " + limits.maxEntries() + " entries.");
                }
                String name = entry.getName();
                String shown = BoundedText.clip(name, 200);
                String key = name.toLowerCase(Locale.ROOT);
                if (name.startsWith("/") || name.indexOf('\\') >= 0 || name.indexOf(':') >= 0
                        || List.of(key.split("/")).contains("..")) {
                    throw new OutputRefused("its zip names an entry \"" + shown + "\" outside the archive: an "
                            + "absolute name, a \"..\" segment, a drive or a backslash.");
                }
                if (!seen.add(key)) {
                    throw new OutputRefused("its zip holds " + shown + " twice; two readers could each open a "
                            + "different one.");
                }
                if (ARCHIVE_SUFFIXES.stream().anyMatch(key::endsWith)) {
                    throw nested(shown);
                }
                if (entry.isDirectory()) {
                    entries.add(new Entry(name, true, entry.getMethod(), new byte[0]));
                    continue;
                }
                entries.add(new Entry(name, false, entry.getMethod(),
                        drain(zip, entry, shown, keep.test(key), inflated)));
            }
        } catch (ZipException malformed) {
            throw new OutputRefused("it is not a readable zip archive.");
        } catch (IOException unreadable) {
            throw new OutputRefused("its zip could not be read to its end.");
        }
        if (entries.isEmpty()) {
            throw new OutputRefused("it is an empty zip archive.");
        }
        if (!directory.equals(entries.stream().map(Entry::name).toList())) {
            throw new OutputRefused("its zip's central directory, which the recipient's program reads, does not "
                    + "name the entries its local headers do, in the same order: the check would read one package "
                    + "and the recipient another.");
        }
        return entries;
    }

    private byte[] drain(CountingZip zip, ZipEntry entry, String name, boolean keep, long[] inflated)
            throws IOException {
        ByteArrayOutputStream kept = new ByteArrayOutputStream();
        byte[] head = new byte[4];
        int headLength = 0;
        long read = 0;
        byte[] buffer = new byte[8192];
        int n;
        while ((n = zip.read(buffer, 0, buffer.length)) > 0) {
            for (int i = 0; i < n && headLength < head.length; i++) {
                head[headLength++] = buffer[i];
            }
            read += n;
            inflated[0] += n;
            if (read > limits.maxEntryBytes()) {
                throw new OutputRefused("entry " + name + " inflates past " + limits.maxEntryBytes() + " bytes.");
            }
            if (inflated[0] > limits.maxInflatedBytes()) {
                throw new OutputRefused("its zip inflates past " + limits.maxInflatedBytes() + " bytes.");
            }
            if (entry.getMethod() == ZipEntry.DEFLATED && read > limits.ratioGraceBytes()
                    && read > (long) limits.maxRatio() * Math.max(1, zip.compressedRead())) {
                throw new OutputRefused("entry " + name + " inflates more than " + limits.maxRatio()
                        + " times its compressed size, as a zip bomb does.");
            }
            if (keep) {
                kept.write(buffer, 0, n);
            }
        }
        if (headLength == 4 && startsWith(head, LOCAL_HEADER)) {
            throw nested(name);
        }
        return keep ? kept.toByteArray() : new byte[0];
    }

    private static OutputRefused nested(String name) {
        return new OutputRefused("entry " + name + " is an archive inside the document; nested archives are not "
                + "opened, and a document inside it would be one nobody checked.");
    }

    /**
     * The names the central directory lists, in its order. The end record must close the file exactly — its
     * comment included — and point at a directory that ends where it starts.
     */
    private static List<String> centralDirectory(byte[] file) {
        int end = -1;
        for (int at = file.length - END_OF_DIRECTORY_SIZE; at >= Math.max(0, file.length - END_OF_DIRECTORY_SIZE - 0xFFFF);
                at--) {
            if (int32(file, at) == END_OF_DIRECTORY && at + END_OF_DIRECTORY_SIZE + uint16(file, at + 20) == file.length) {
                end = at;
                break;
            }
        }
        if (end < 0) {
            throw new OutputRefused("its zip has no end-of-directory record closing the file: something follows "
                    + "the archive, or it was cut short.");
        }
        int disk = uint16(file, end + 4);
        int count = uint16(file, end + 10);
        long size = uint32(file, end + 12);
        long offset = uint32(file, end + 16);
        if (disk != 0 || count == 0xFFFF || size == 0xFFFFFFFFL || offset == 0xFFFFFFFFL) {
            throw new OutputRefused("its zip is split across disks or uses a ZIP64 directory, which no document "
                    + "under the output ceiling needs.");
        }
        if (offset + size != end) {
            throw new OutputRefused("its zip's central directory does not end where the end record says.");
        }
        List<String> names = new ArrayList<>();
        int at = (int) offset;
        for (int i = 0; i < count; i++) {
            if (at + 46 > end || int32(file, at) != CENTRAL_HEADER) {
                throw new OutputRefused("its zip's central directory is malformed.");
            }
            int nameLength = uint16(file, at + 28);
            int extraLength = uint16(file, at + 30);
            int commentLength = uint16(file, at + 32);
            if (at + 46 + nameLength > end) {
                throw new OutputRefused("its zip's central directory is malformed.");
            }
            // Bit 11 says UTF-8; ZipInputStream reads UTF-8 whatever the flag, and so does this, so a name
            // compares as the reader above decoded it.
            names.add(new String(file, at + 46, nameLength, StandardCharsets.UTF_8));
            at += 46 + nameLength + extraLength + commentLength;
        }
        if (at != end) {
            throw new OutputRefused("its zip's central directory holds more than the entries it counts.");
        }
        return names;
    }

    private static int uint16(byte[] bytes, int at) {
        return (bytes[at] & 0xFF) | (bytes[at + 1] & 0xFF) << 8;
    }

    private static long uint32(byte[] bytes, int at) {
        return int32(bytes, at) & 0xFFFFFFFFL;
    }

    private static int int32(byte[] bytes, int at) {
        return (bytes[at] & 0xFF) | (bytes[at + 1] & 0xFF) << 8 | (bytes[at + 2] & 0xFF) << 16
                | (bytes[at + 3] & 0xFF) << 24;
    }

    static boolean startsWith(byte[] bytes, byte[] prefix) {
        if (bytes.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (bytes[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * A zip reader that says how many compressed bytes the current entry's inflater consumed — exact, where
     * counting what was pulled from the stream would be ahead by its buffer.
     */
    private static final class CountingZip extends ZipInputStream {
        CountingZip(InputStream input) {
            super(input);
        }

        long compressedRead() {
            return inf.getBytesRead();
        }
    }
}
