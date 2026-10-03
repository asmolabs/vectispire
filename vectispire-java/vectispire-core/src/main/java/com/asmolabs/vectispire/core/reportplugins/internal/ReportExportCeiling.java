package com.asmolabs.vectispire.core.reportplugins.internal;

import com.asmolabs.vectispire.common.domain.reportplugins.ProjectExportBounds;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportExportRepository;
import java.util.OptionalLong;
import org.springframework.stereotype.Component;

/**
 * The bounds of the export a report run is given: the standard ones (decision 0035 §1), its size lowered to what
 * the database can keep in one row — <b>refused before the plugin runs, not lost after it produced</b>.
 *
 * <p><b>Why lower.</b> A produced run keeps its export in one row, written in one statement, and MySQL refuses a
 * statement larger than its {@code max_allowed_packet} — 64 MiB by default, the export's own bound. Connector/J
 * sends a {@code byte[]} in a client-side prepared statement as hexadecimal, two bytes for each: an export of
 * 64 MiB made a statement of 134,217,917 bytes, measured, and every report of a project that large ran its plugin,
 * produced, and then failed to record anything, its document dropped. So on MySQL the bound is half the packet,
 * less {@link #STATEMENT_MARGIN} for the statement around it: about 32 MiB on a default server. A deployment
 * that raises {@code max_allowed_packet} to 160 MiB ({@code --max-allowed-packet=160M}) gets the whole 64 MiB
 * back. PostgreSQL's {@code bytea} has no such ceiling below a gigabyte.
 *
 * <p><b>The document too</b> (lot R4). A produced run's package — the plugin's file, its signature and its
 * provenance — is a row of its own, written in one statement under the same packet. A manifest may allow 50 MiB,
 * which on a default MySQL server would be a run that renders, checks and signs, and then cannot record its
 * document. So the file's ceiling for the run is lowered the same way, less {@link #PACKAGE_MARGIN} for what the
 * package adds to it ({@link #outputBytes}); over it the plugin fills its directory and the run fails {@code
 * output_full}, the detail saying why ({@link #whyOutput}). The same raised packet restores the manifest's ceiling.
 *
 * <p>{@code ReportRunQueueIntegrationTest} stores an export and a package at these bounds on both engines.
 */
@Component
public class ReportExportCeiling {

    /** Room for the statement around the value — the other columns and the SQL, under a kilobyte measured. */
    static final long STATEMENT_MARGIN = 64 * 1024;

    /**
     * What a package adds to the file it carries, at most: the signature, the provenance in its envelope (a few
     * kilobytes), the zip's headers, and deflate's growth on bytes that do not compress (five bytes per 16 KiB block,
     * about 16 KiB at 50 MiB).
     */
    public static final long PACKAGE_MARGIN = 256 * 1024;

    /** What {@code max_allowed_packet} restores the standard bound: twice it, the margin and some room. */
    static final String RAISED_PACKET = "160M";

    private final ReportExportRepository exports;

    public ReportExportCeiling(ReportExportRepository exports) {
        this.exports = exports;
    }

    /** The bounds a run's export is built under, asked of the database now. */
    public ProjectExportBounds bounds() {
        ProjectExportBounds standard = ProjectExportBounds.STANDARD;
        return new ProjectExportBounds(storable(exports.largestStatementBytes()), standard.maxIssues(),
                standard.maxComponents());
    }

    /**
     * The ceiling of a run's file: the manifest's, lowered to what one statement keeps of its package, asked of the
     * database now.
     */
    public long outputBytes(long manifestCeiling) {
        return outputBytes(exports.largestStatementBytes(), manifestCeiling);
    }

    static long outputBytes(OptionalLong largestStatement, long manifestCeiling) {
        if (largestStatement.isEmpty()) {
            return manifestCeiling;
        }
        long storable = (largestStatement.getAsLong() - STATEMENT_MARGIN) / 2;
        return Math.max(1, Math.min(manifestCeiling, storable - PACKAGE_MARGIN));
    }

    /**
     * What a run whose file filled {@code ceiling} adds to its detail: why it is below the manifest's and what
     * restores it, or nothing when it is the manifest's.
     */
    static String whyOutput(long ceiling, long manifestCeiling) {
        if (ceiling >= manifestCeiling) {
            return "";
        }
        return " Its file's ceiling was lowered from the manifest's " + manifestCeiling + " bytes to " + ceiling
                + ": a report's signed package is kept with its run, and this database stores at most so much of it in "
                + "one statement (MySQL's max_allowed_packet, the package travelling hex-encoded at twice its size); a "
                + "max_allowed_packet of " + RAISED_PACKET + " restores the manifest's.";
    }

    /** The largest export one statement carries under a packet of that size, never above the standard bound. */
    static long storable(OptionalLong largestStatement) {
        long standard = ProjectExportBounds.STANDARD.maxJsonBytes();
        if (largestStatement.isEmpty()) {
            return standard;
        }
        return Math.max(1, Math.min(standard, (largestStatement.getAsLong() - STATEMENT_MARGIN) / 2));
    }

    /**
     * What a run refused under {@code bounds} adds to the refusal's sentence: why its bound is below the standard
     * one and what restores it, or nothing when it is the standard one.
     */
    static String why(ProjectExportBounds bounds) {
        long standard = ProjectExportBounds.STANDARD.maxJsonBytes();
        if (bounds.maxJsonBytes() >= standard) {
            return "";
        }
        return " A report's export is kept with its run, and this database stores at most " + bounds.maxJsonBytes()
                + " bytes of it in one statement (MySQL's max_allowed_packet, the export travelling hex-encoded at "
                + "twice its size); a max_allowed_packet of " + RAISED_PACKET + " restores the " + standard
                + " bytes every export may reach.";
    }
}
