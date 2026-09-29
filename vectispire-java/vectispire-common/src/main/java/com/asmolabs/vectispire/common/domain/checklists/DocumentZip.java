package com.asmolabs.vectispire.common.domain.checklists;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.LocalDateTime;
import java.util.SequencedMap;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * A zip written the same way every time: the entries in the order given, each dated {@link #ENTRY_TIME},
 * no extra field, no comment — so that one revision renders to the same bytes today and next year on this
 * JVM, and a document can be compared with a second rendering byte for byte (decision 0032 §10).
 *
 * <p>The date is set as a local date-time on purpose: {@code setTime} converts through the JVM's time
 * zone, and two hosts in two zones would write two archives. 1980-02-01 rather than the DOS epoch
 * itself, which some tools read back through their own zone as a day of 1979.
 */
public final class DocumentZip {

    public static final LocalDateTime ENTRY_TIME = LocalDateTime.of(1980, 2, 1, 0, 0);

    private DocumentZip() {}

    /** An entry to write; {@code stored} keeps it uncompressed, as its source archive had it. */
    public record Entry(byte[] bytes, boolean stored, boolean directory) {

        public static Entry of(byte[] bytes) {
            return new Entry(bytes, false, false);
        }
    }

    public static byte[] of(SequencedMap<String, Entry> entries) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            for (var named : entries.entrySet()) {
                Entry entry = named.getValue();
                ZipEntry written = new ZipEntry(named.getKey());
                written.setTimeLocal(ENTRY_TIME);
                if (entry.stored() && !entry.directory()) {
                    CRC32 crc = new CRC32();
                    crc.update(entry.bytes());
                    written.setMethod(ZipEntry.STORED);
                    written.setSize(entry.bytes().length);
                    written.setCompressedSize(entry.bytes().length);
                    written.setCrc(crc.getValue());
                }
                zip.putNextEntry(written);
                zip.write(entry.bytes());
                zip.closeEntry();
            }
        } catch (IOException impossible) {
            throw new UncheckedIOException("An archive could not be written in memory.", impossible);
        }
        return bytes.toByteArray();
    }
}
