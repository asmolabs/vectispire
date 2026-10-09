package com.asmolabs.vectispire.core.compliance.internal;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.compliance.persistence.AiReviewResultEntity;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import jakarta.annotation.PreDestroy;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Writes the OWASP reports completed scans asked for: one at a time, on a thread of its own, never on the
 * scan's.
 *
 * <h2>One at a time, and why on a thread rather than in the database</h2>
 *
 * <p>A local model takes minutes per report and answers one request at a time; a second request is queued
 * behind the first by the model server, and both then wait past the timeout. So this instance writes one
 * report at a time — a single thread — and <b>also waits for any review still running anywhere</b>, by
 * another replica or by a person on the button ({@link OwaspReviewService#anyRunning}): the running row each
 * review writes before it asks the model is the claim the instances share, read rather than taken. That
 * read leaves a window — two replicas can each see none running and start in the same second — whose cost is
 * two calls the model serves one after the other, slower, and never a wrong report. A claim taken in the
 * database would close it, at the price of a table and a lease for a model nobody runs on more than one
 * GPU; the read keeps the guarantee that matters, a model never asked by a queue of every scan at once.
 *
 * <h2>Folded, not queued</h2>
 *
 * <p>What is held is one request per repository, naming its newest scan: ten scans of one repository in a
 * minute are one report, written from the last of them. A repository whose report is already running —
 * here, or anywhere — is not asked again; its report is about to say what the scan says, near enough, and a
 * second one queued behind it would be the same report a few minutes later.
 *
 * <h2>What is lost, and what is not</h2>
 *
 * <p>The outbox carries the request durably up to here ({@link OwaspReportDelivery}). Once held, a request
 * lives in this instance's memory, and a stop before it starts loses it: the next scan of that repository
 * asks again, and the button is always there. A stop while the model writes leaves the running row, which
 * the hourly sweep settles as failed with its reason ({@link AbandonedReviewsTask}). A failure of the model
 * is recorded on the report row by {@link OwaspReviewService}, logged here, and reaches no scan: the scan
 * committed long before.
 *
 * <h2>Nobody asked, so nobody is named</h2>
 *
 * <p>The run has no user, and needs no visibility: it reads the repository's whole open backlog, which is
 * what a run from the button reads too — the button's route refuses a repository its caller does not see,
 * and reads the same evidence once it may. Every reader of the report then reaches it through that route,
 * with their own visibility. The audit entry a run from the button writes is written here too, with no
 * actor: a "system" user would put a person who does not exist into the trail an assessor reads.
 */
@Component
public class OwaspReportsAfterScans {

    private static final Logger log = LoggerFactory.getLogger(OwaspReportsAfterScans.class);

    /**
     * How long a request waits before looking again whether the model is free.
     *
     * <p>A report takes minutes; looking every minute starts the next one within a minute of the model
     * becoming free, for one indexed read a minute while something is running.
     */
    static final Duration WAIT_FOR_THE_MODEL = Duration.ofMinutes(1);

    /** Whether reports are written after scans: the switch, and model review itself. */
    static boolean switchedOn(SettingsService settings) {
        return settings.isEnabled(Setting.AI_REVIEW_OWASP_AFTER_SCAN) && settings.isEnabled(Setting.AI_REVIEW_ENABLED);
    }

    /** What became of a request handed over — logged, and what a test reads. */
    public enum Offer {
        /** Held, and a turn of the thread will write it. */
        HELD,
        /** A request for the same repository was held already, and now names this scan if it is newer. */
        FOLDED,
        /** The repository's report is being written now; nothing is held. */
        ALREADY_RUNNING,
        /** One of the two switches is off; nothing is held. */
        SWITCHED_OFF
    }

    private final OwaspReviewService reviews;
    private final TargetCatalog targets;
    private final SettingsService settings;
    private final AuditLogService audit;

    /** The repository → the newest scan whose report is asked for and not started. */
    private final Map<Long, Long> held = new ConcurrentHashMap<>();

    /** The repository whose report this instance is writing, if any — read by the deliveries, on another thread. */
    private volatile Long writing;

    private final ScheduledExecutorService thread = Executors.newSingleThreadScheduledExecutor(
            Thread.ofPlatform().name("owasp-report-after-scan").daemon().factory());

    private final Duration waitForTheModel;

    @Autowired
    public OwaspReportsAfterScans(
            OwaspReviewService reviews, TargetCatalog targets, SettingsService settings, AuditLogService audit) {
        this(reviews, targets, settings, audit, WAIT_FOR_THE_MODEL);
    }

    /** @param waitForTheModel {@link #WAIT_FOR_THE_MODEL}, shortened by a test that would otherwise wait a minute */
    OwaspReportsAfterScans(
            OwaspReviewService reviews,
            TargetCatalog targets,
            SettingsService settings,
            AuditLogService audit,
            Duration waitForTheModel) {
        this.reviews = reviews;
        this.targets = targets;
        this.settings = settings;
        this.audit = audit;
        this.waitForTheModel = waitForTheModel;
    }

    /**
     * Takes a completed scan's request for its repository's report, and returns at once.
     *
     * <p>Holds at most one request per repository: a request arriving while another is held folds into it,
     * naming the newer of the two scans.
     */
    public Offer offer(long repositoryId, long scanId) {
        if (!switchedOn(settings)) {
            return Offer.SWITCHED_OFF;
        }
        if (Long.valueOf(repositoryId).equals(writing) || reviews.isRunning(repositoryId)) {
            log.debug("OWASP report of repository {} is being written; scan {} asks for nothing more.", repositoryId, scanId);
            return Offer.ALREADY_RUNNING;
        }
        boolean[] fresh = {false};
        held.compute(repositoryId, (repository, before) -> {
            fresh[0] = before == null;
            return before == null ? scanId : Math.max(before, scanId);
        });
        if (!fresh[0]) {
            return Offer.FOLDED;
        }
        try {
            thread.execute(() -> write(repositoryId));
        } catch (RejectedExecutionException stopping) {
            // The context is closing: the request is lost with the process, as one held and not started is.
            held.remove(repositoryId);
        }
        return Offer.HELD;
    }

    /**
     * One turn: the repository's held request, written — or put back to wait for the model, or dropped.
     *
     * <p>Never throws: an exception escaping a task of the executor is swallowed by it, silently, and this
     * one is the only place a failure of an automatic report can be told.
     */
    private void write(long repositoryId) {
        Long scanId = held.get(repositoryId);
        if (scanId == null) {
            return;
        }
        try {
            if (!switchedOn(settings)) {
                held.remove(repositoryId);
                return;
            }
            if (reviews.isRunning(repositoryId)) {
                held.remove(repositoryId);
                log.debug("OWASP report of repository {} is being written elsewhere; scan {} asks for nothing more.",
                        repositoryId, scanId);
                return;
            }
            if (reviews.anyRunning()) {
                // Still held, so the scans arriving meanwhile fold into it rather than queue behind it.
                thread.schedule(() -> write(repositoryId), waitForTheModel.toMillis(), TimeUnit.MILLISECONDS);
                return;
            }
            // Marked before the request is taken, so a delivery between the two never finds it in neither.
            writing = repositoryId;
            scanId = held.remove(repositoryId);
            Optional<RepositoryView> repository = targets.repository(repositoryId);
            if (repository.isEmpty()) {
                log.info("OWASP report after scan {} not written: repository {} is gone.", scanId, repositoryId);
                return;
            }
            AiReviewResultEntity result = reviews.runAfterScan(repository.get(), scanId);
            // **Audited like the button's run**, and for the same reason: the repository's findings went out
            // to a host an operator configured. Recorded after the row is settled, outside any transaction.
            audit.record(AuditLogService.Record.of(
                    AuditOperation.AI_REVIEW_REQUESTED,
                    String.valueOf(repositoryId),
                    "OWASP report written after scan " + scanId + " (" + result.getModel() + ", " + result.getStatus() + ")",
                    null));
            log.info("OWASP report of repository {} after scan {}: {}.", repositoryId, scanId, result.getStatus());
        } catch (RejectedExecutionException stopping) {
            held.remove(repositoryId);
        } catch (RuntimeException failed) {
            // A refusal (model review switched off between two reads, the scan purged) or a failure before the
            // row existed. One the model caused is on the row already.
            log.warn("OWASP report of repository {} after scan {} not written: {}", repositoryId, scanId, failed.getMessage());
        } finally {
            writing = null;
        }
    }

    @PreDestroy
    void stop() {
        // A report the model is writing is left running; the hourly sweep settles it once its deadline passes.
        thread.shutdownNow();
    }
}
