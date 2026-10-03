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
 * <p>{@code ReportRunQueueIntegrationTest} stores an export at this bound on both engines.
 */
@Component
public class ReportExportCeiling {

    /** Room for the statement around the value — the other columns and the SQL, under a kilobyte measured. */
    static final long STATEMENT_MARGIN = 64 * 1024;

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
