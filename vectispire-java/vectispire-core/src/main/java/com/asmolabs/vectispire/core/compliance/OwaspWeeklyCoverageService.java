package com.asmolabs.vectispire.core.compliance;

import com.asmolabs.vectispire.common.domain.owasp.CoverageWeek;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.teams.TeamRules;
import com.asmolabs.vectispire.core.compliance.persistence.OwaspWeeklyCoverageEntity;
import com.asmolabs.vectispire.core.compliance.persistence.OwaspWeeklyCoverageRepository;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Records the OWASP grid week by week, per target, so that a past week's state can be shown.
 *
 * <h2>Why a record rather than a query over the past</h2>
 *
 * <p>A past week's open counts can be approximated from the issues' sightings; its <em>state</em>
 * cannot. Whether a category was covered, measured or switched off depended on settings and installed
 * rules that have moved since — the reasoning {@code ComplianceSnapshot} gives for the monthly
 * verdicts. So the state is read as the live grid reads it, through the same {@link
 * OwaspCoverageService} and the same rule, and kept. The weeks before the first capture have none, and
 * a reader says so.
 *
 * <h2>Three decisions</h2>
 *
 * <p><b>The current week is rewritten, at most every {@link #INTERVAL}.</b> A closed week thus keeps
 * its state at the last capture inside it — within six hours of its end — as the compliance history
 * keeps a month's end. Every hour would be cheaper to explain and is not cheap: a capture asks about a
 * dozen counts per target, and the grid moves at the rate scans and triage do.
 *
 * <p><b>The whole estate, every target that exists, whether scanned or not.</b> A target never
 * scanned is recorded: its categories read not measured or not covered, and that is the information —
 * a heatmap leaving it out would show an estate better examined than it is. Per target so that a reader
 * can aggregate to a project or a solution and see only what they may.
 *
 * <p><b>Two instances may capture the same week at once, and the unique key decides.</b> No instance
 * is elected: every instance runs every maintenance task. The week is deleted and written again in one
 * transaction, after the gate is asked again inside it. Two instances that pass the gate together race
 * on the unique key: on PostgreSQL the second one's insert waits for the first one's commit and is then
 * refused; on MySQL the second one's delete waits on the first one's rows and then takes them, or one
 * of the two is chosen as a deadlock's victim. Every outcome leaves one instance's complete set — never
 * two sets mixed, never a duplicate. <b>A failed write is not read as "somebody else did it"</b>: the
 * transaction rolls back, and the committed week is asked; only a fresh capture found there makes the
 * failure the race's. Anything else is a failure, logged once per pass. An upsert would have been the
 * alternative, and it is three statements — one per engine — for a race that costs one rolled-back
 * transaction every six hours at worst.
 */
@Service
public class OwaspWeeklyCoverageService {

    /** How old the current week's capture may be before it is written again. */
    static final Duration INTERVAL = Duration.ofHours(6);

    private static final Logger log = LoggerFactory.getLogger(OwaspWeeklyCoverageService.class);

    /** What a pass did — for the tests, and for nobody else to branch on. */
    public enum Outcome {
        /** The week was written by this pass. */
        CAPTURED,
        /** The week was written less than {@link #INTERVAL} ago. */
        NOT_DUE,
        /** Another instance wrote the week while this pass was reading the estate. */
        TAKEN_ELSEWHERE,
        /** Nothing written, and the committed week does not say another instance did it. */
        FAILED
    }

    private final OwaspCoverageService coverage;
    private final TargetCatalog targets;
    private final OwaspWeeklyCoverageRepository weeks;
    private final TransactionTemplate writes;
    private final Clock clock;

    public OwaspWeeklyCoverageService(
            OwaspCoverageService coverage,
            TargetCatalog targets,
            OwaspWeeklyCoverageRepository weeks,
            PlatformTransactionManager transactions,
            Clock clock) {
        this.coverage = coverage;
        this.targets = targets;
        this.weeks = weeks;
        this.writes = new TransactionTemplate(transactions);
        this.clock = clock;
    }

    /**
     * Writes the current week's record, if it is due.
     *
     * <p>Never throws: a capture that fails must not take the maintenance tick with it — the same
     * reasoning as {@code ComplianceHistoryService.capture}. A missing week is a hole in a heatmap; a
     * tick that stops is a purge, an outbox and a triage expiry that stop.
     */
    public Outcome capture() {
        return capture(clock.instant());
    }

    /** {@link #capture()} at a given instant — what the tests move through the week. */
    Outcome capture(Instant now) {
        Instant week = CoverageWeek.startOf(now);
        try {
            if (!due(week, now)) {
                return Outcome.NOT_DUE;
            }
            // **The reading is outside the write**, which holds a lock on the week only for as long as
            // the delete and the inserts take: the counts are a dozen statements per target, and a
            // transaction open across them would hold the week's rows for the whole pass.
            return write(week, now, read(week, now)) ? Outcome.CAPTURED : Outcome.TAKEN_ELSEWHERE;
        } catch (RuntimeException failed) {
            return afterFailure(week, now, failed);
        }
    }

    /**
     * The week's rows replaced by these, in one transaction — or joined to the caller's, which is how
     * the campaign holds one writer open while another arrives. False when the week turned out to be
     * fresh once inside: another instance committed it while this one was reading.
     */
    boolean write(Instant week, Instant now, List<OwaspWeeklyCoverageEntity> rows) {
        return Boolean.TRUE.equals(writes.execute(status -> {
            if (!due(week, now)) {
                return false;
            }
            weeks.deleteWeek(week);
            weeks.saveAll(rows);
            return true;
        }));
    }

    /** One row per target and category, read with the estate-wide part of the grid read once. */
    List<OwaspWeeklyCoverageEntity> read(Instant week, Instant now) {
        OwaspCoverageService.Reading reading = coverage.reading();
        List<OwaspWeeklyCoverageEntity> rows = new ArrayList<>();
        Stream.concat(
                        targets.repositories().stream().<ScanTarget>map(row -> new ScanTarget.Repository(row.id())),
                        targets.containers().stream().<ScanTarget>map(row -> new ScanTarget.Container(row.id())))
                .forEach(target -> {
                    for (OwaspCoverage.Split line : coverage.ofTarget(target, reading)) {
                        rows.add(row(week, now, target, line));
                    }
                });
        return rows;
    }

    private static OwaspWeeklyCoverageEntity row(Instant week, Instant now, ScanTarget target, OwaspCoverage.Split line) {
        OwaspWeeklyCoverageEntity row = new OwaspWeeklyCoverageEntity();
        row.setWeekStart(week);
        row.setTargetKind(kindOf(target));
        row.setTargetId(idOf(target));
        row.setCategory(line.id());
        row.setState(line.state().name());
        row.setOpenCount(line.open());
        row.setSettledCount(line.settled());
        row.setCapturedAt(now);
        return row;
    }

    private boolean due(Instant week, Instant now) {
        return weeks.newestCaptureOf(week)
                .map(newest -> !newest.isAfter(now.minus(INTERVAL)))
                .orElse(true);
    }

    /**
     * Rolled back; now asks the committed week whether another instance wrote it.
     *
     * <p>The rule {@code OneShotJobs} follows: a refused statement is read against the committed state,
     * never as a claim lost by its words — a lock timeout or a dropped connection fails the same way,
     * and only the committed row says whether anybody wrote the week.
     */
    private Outcome afterFailure(Instant week, Instant now, RuntimeException failed) {
        try {
            if (!due(week, now)) {
                log.info("OWASP weekly coverage for {} written by another instance meanwhile.", week);
                return Outcome.TAKEN_ELSEWHERE;
            }
        } catch (RuntimeException unreadable) {
            failed.addSuppressed(unreadable);
        }
        log.warn("OWASP weekly coverage capture skipped: {}", failed.getMessage());
        return Outcome.FAILED;
    }

    /** The kind as grants, gate policies and this record store it next to the identifier. */
    static String kindOf(ScanTarget target) {
        return switch (target) {
            case ScanTarget.Repository ignored -> TeamRules.KIND_REPOSITORY;
            case ScanTarget.Container ignored -> TeamRules.KIND_CONTAINER;
        };
    }

    private static long idOf(ScanTarget target) {
        return switch (target) {
            case ScanTarget.Repository repository -> repository.id();
            case ScanTarget.Container container -> container.id();
        };
    }
}
