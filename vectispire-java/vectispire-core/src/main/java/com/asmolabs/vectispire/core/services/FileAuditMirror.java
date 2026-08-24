package com.asmolabs.vectispire.core.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The audit mirror as a file: one JSON object per line, appended, never rewritten.
 *
 * <p><b>Why NDJSON and not a JSON array.</b> An array has to be closed, so every append means
 * rewriting the end of the file — and a process killed mid-write leaves a document no parser
 * will read, which is to say an audit copy destroyed by a restart. One object per line is
 * append-only in the literal sense: the previous bytes are never touched, a truncated last line
 * costs one entry, and every log collector already knows how to ship it.
 *
 * <p><b>Opened per append, and that is deliberate.</b> A long-lived handle would keep writing
 * into a file that log rotation has already moved, so entries would land in a file nobody reads
 * while the current one stays empty. Opening costs a syscall on a path that sees a handful of
 * writes a minute.
 *
 * <p><b>What is written is what is hashed, plus the two hashes.</b> Not a rendering for humans:
 * the point of the copy is to be comparable with the table, and a field formatted differently
 * here would make the comparison report differences that are not ones.
 */
public class FileAuditMirror implements AuditMirror {

    private static final Logger log = LoggerFactory.getLogger(FileAuditMirror.class);

    private final Path path;
    private final ObjectMapper json;

    public FileAuditMirror(Path path, ObjectMapper json) {
        this.path = path;
        this.json = json;
    }

    @Override
    public boolean append(Entry entry) {
        try {
            Path parent = path.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            // One write call for the line and its terminator: two calls could interleave with
            // another instance's write and produce a line no parser can read — and a corrupted
            // line in an integrity copy is indistinguishable from tampering.
            byte[] line = (json.writeValueAsString(entry) + System.lineSeparator()).getBytes(StandardCharsets.UTF_8);
            Files.write(path, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            return true;
        } catch (IOException | RuntimeException failed) {
            // Never thrown onwards — see the interface note. Logged loudly, and the verification
            // will show the entry as present in the table and absent from the mirror, which is
            // the honest description of what just happened.
            log.error("Audit entry {} could not be mirrored to {}: {}", entry.id(), path, failed.getMessage());
            return false;
        }
    }

    @Override
    public boolean configured() {
        return true;
    }

    @Override
    public List<String> entryHashes() {
        if (!Files.exists(path)) {
            // Not an error: a freshly configured mirror has no file until the first entry. The
            // verification reads this as "the mirror has nothing", which is true.
            return List.of();
        }

        List<String> hashes = new ArrayList<>();
        try (Stream<String> lines = Files.lines(path, StandardCharsets.UTF_8)) {
            lines.forEach(line -> {
                if (line.isBlank()) {
                    return;
                }
                try {
                    String hash = json.readTree(line).path("entryHash").asText(null);
                    if (hash != null && !hash.isBlank()) {
                        hashes.add(hash);
                    }
                } catch (IOException unreadable) {
                    // A line that will not parse is itself a finding, but it is not this
                    // method's to raise: skipping it makes the entry count differ from the
                    // table's, which is what the verification reports.
                    log.warn("A line of {} could not be read as an audit entry", path);
                }
            });
        } catch (IOException | UncheckedIOException unreadable) {
            throw new IllegalStateException("The audit mirror at " + path + " could not be read", unreadable);
        }
        return hashes;
    }
}
