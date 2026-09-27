package com.asmolabs.vectispire.core.threatintel.internal;

import com.asmolabs.vectispire.common.domain.threatintel.EpssFile;
import com.asmolabs.vectispire.core.outbound.OutboundDownload;
import java.time.Duration;
import org.springframework.stereotype.Component;

/**
 * Downloads FIRST's daily EPSS file, from FIRST or from the mirror the deployment names.
 *
 * <p>Through {@link OutboundDownload}: the guard, the pinned sender, and one redirect to the same
 * origin at most — FIRST's stable address answers with one, to the day's dated file.
 *
 * <p><b>The archive is held, not the file.</b> What arrives is some 2.7 MB of gzip, kept in memory
 * so that the connection is closed before anything is written: the rows are then inflated and
 * parsed as a stream ({@link EpssFile}), a batch at a time, with the network already out of the
 * picture. Reading straight from the socket into the database would have held the connection open —
 * and its deadline running — for as long as the engine took to write 380,000 rows.
 *
 * <p><b>Never inside a transaction</b>, and never during a scan: the synchronisation calls this
 * before it writes anything, and the scans read what it stored.
 */
@Component
public class EpssFileSource {

    /**
     * The archive's ceiling: twenty times today's. An answer over it is refused, not truncated — and
     * a truncated archive would be refused by its own checksum anyway.
     */
    static final long MAX_BYTES = 64L * 1024 * 1024;

    /**
     * Each read's timeout, the exchange's being twice this. Longer than a JSON call's ten seconds:
     * a few megabytes over a slow link to a mirror, once a day.
     */
    static final Duration TIMEOUT = Duration.ofSeconds(60);

    private final OutboundDownload outbound;
    private final ThreatIntelProperties properties;

    public EpssFileSource(OutboundDownload outbound, ThreatIntelProperties properties) {
        this.outbound = outbound;
        this.properties = properties;
    }

    /**
     * The file's bytes, gzip as published — or inflated, when a mirror serves it with a content
     * encoding the client has already undone.
     *
     * @throws RuntimeException when it could not be fetched — never an empty file
     */
    public byte[] fetch() {
        return outbound.get(properties.epssFileUrl(), properties.epssPolicy(), "EPSS file", MAX_BYTES, TIMEOUT)
                // A mirror that lost the file has not published a file without scores.
                .orElseThrow(() -> new EpssFile.Unreadable("the file was not found at the configured address"));
    }

    /** Where it is read from, for the log line an operator reads when it fails. */
    public String location() {
        return properties.epssFileUrl();
    }
}
