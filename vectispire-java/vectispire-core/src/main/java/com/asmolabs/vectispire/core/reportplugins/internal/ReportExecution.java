package com.asmolabs.vectispire.core.reportplugins.internal;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.plugins.ImageDigest;
import com.asmolabs.vectispire.common.domain.plugins.PluginSignature;
import com.asmolabs.vectispire.common.domain.reportplugins.ProjectExportSchema;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportPluginManifest;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportPluginManifestStatus;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportRunReason;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportRunState;
import com.asmolabs.vectispire.common.scanning.scanners.ReportPluginRenderer;
import com.asmolabs.vectispire.core.access.AuthService;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.reportplugins.ProjectExportService;
import com.asmolabs.vectispire.core.reportplugins.ProjectExportTooLargeException;
import com.asmolabs.vectispire.core.reportplugins.ReportExecutor;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportExportEntity;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportExportRepository;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportPluginActivationRepository;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportPluginEntity;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportPluginManifestEntity;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportPluginManifestRepository;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportPluginRepository;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportRunEntity;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportRunRepository;
import com.asmolabs.vectispire.core.settings.ProductVersion;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * One claimed report run, carried out (decision 0035 §2): what the request could not settle is settled again, the
 * export is built, the plugin runs, and the outcome is recorded — by the executor that claimed the run, or not at
 * all.
 *
 * <h2>At the claim, again</h2>
 *
 * <p>The plugin may have been switched off for the project, disabled or withdrawn since the request, and the
 * requester deactivated, demoted or narrowed: a run of either fails, {@code plugin_unavailable} or {@code
 * requester_not_allowed}, rather than render a project for somebody who may no longer read it, with code nobody
 * vouches for any more. The manifest is the plugin's <b>approved one at the claim</b> — never an unapproved digest,
 * and an approval that landed after the request is what runs. A manifest reading an export major this installation
 * no longer produces is refused, {@code export_schema_unavailable}: it is never handed another.
 *
 * <h2>The export, at the claim</h2>
 *
 * <p>Built for the requester as they see the project now — the instant the document describes —, in memory, written
 * where the plugin reads it only once its signer is verified. Kept with the run only when the run produced: a
 * failed or refused run stores nothing but itself and its reason. {@code PROJECT_EXPORTED} is recorded, and {@code
 * VECTI-SEC-032} signalled, when the export reached the plugin's container — never for a refusal, which reaches
 * nothing.
 *
 * <h2>The outcome, by its owner</h2>
 *
 * <p>Every write names the run's state and its claimant, so an executor whose lease lapsed — its run failed as lost
 * meanwhile — writes nothing; its export is not stored either, in the same transaction. Audited after the commit:
 * {@code REPORT_PRODUCED}, {@code REPORT_FAILED}, or {@code REPORT_REFUSED}, which signals {@code VECTI-SEC-033}.
 * The output's bytes are not kept by this lot: their size and digest are, and lot R4 checks, signs and stores them.
 */
@Component
public class ReportExecution {

    private static final Logger log = LoggerFactory.getLogger(ReportExecution.class);

    /** The detail column's bound: a sentence and the start of what the plugin said. */
    static final int DETAIL = 2000;

    private final ReportRunRepository runs;
    private final ReportExportRepository exports;
    private final ReportPluginRepository plugins;
    private final ReportPluginManifestRepository manifests;
    private final ReportPluginActivationRepository activations;
    private final ProjectExportService exportService;
    private final AuthService accounts;
    private final VisibilityService visibility;
    private final ReportExecutor executor;
    private final ProductVersion productVersion;
    private final AuditLogService audit;
    private final ObjectMapper json;
    private final Clock clock;
    private final TransactionTemplate transactions;

    public ReportExecution(
            ReportRunRepository runs,
            ReportExportRepository exports,
            ReportPluginRepository plugins,
            ReportPluginManifestRepository manifests,
            ReportPluginActivationRepository activations,
            ProjectExportService exportService,
            AuthService accounts,
            VisibilityService visibility,
            ObjectProvider<ReportExecutor> executor,
            ProductVersion productVersion,
            AuditLogService audit,
            ObjectMapper json,
            Clock clock,
            PlatformTransactionManager transactions) {
        this.runs = runs;
        this.exports = exports;
        this.plugins = plugins;
        this.manifests = manifests;
        this.activations = activations;
        this.exportService = exportService;
        this.accounts = accounts;
        this.visibility = visibility;
        this.executor = executor.getIfAvailable();
        this.productVersion = productVersion;
        this.audit = audit;
        this.json = json;
        this.clock = clock;
        this.transactions = new TransactionTemplate(transactions);
    }

    /** What the run learnt on its way, whatever became of it: what its row records. */
    private record Learnt(
            String projectName,
            String manifestDigest,
            String imageDigest,
            PluginSignature signer,
            Instant exportedAt,
            ProjectExportService.RunExport export) {

        static final Learnt NOTHING = new Learnt(null, null, null, null, null, null);

        Learnt withManifest(String digest, ReportPluginManifest manifest) {
            return new Learnt(projectName, digest, ImageDigest.parse(manifest.image()).digest(), manifest.signature(),
                    exportedAt, export);
        }

        Learnt withExport(Instant at, ProjectExportService.RunExport built) {
            return new Learnt(built.projectName(), manifestDigest, imageDigest, signer, at, built);
        }
    }

    /**
     * Carries out run {@code runId}, claimed by {@code owner}. Never throws: what goes wrong is the run's failure,
     * recorded if the run is still this owner's.
     */
    public void execute(long runId, String owner) {
        Optional<ReportRunEntity> claimed = runs.findById(runId);
        if (claimed.isEmpty()) {
            return;
        }
        ReportRunEntity run = claimed.get();
        RequestActor requester = new RequestActor(run.getRequestedBy(), null, null);
        Learnt learnt = Learnt.NOTHING;
        try {
            if (executor == null) {
                finish(run, owner, requester, learnt, new ReportPluginRenderer.Outcome.Failed(
                        ReportRunReason.EXECUTOR_ERROR, "This control plane has no container endpoint to run it on.", false));
                return;
            }
            Optional<Approved> approved = approved(run);
            if (approved.isEmpty()) {
                finish(run, owner, requester, learnt, new ReportPluginRenderer.Outcome.Failed(
                        ReportRunReason.PLUGIN_UNAVAILABLE, "Since the request, report plugin \"" + run.getPluginId()
                                + "\" was switched off for this project, disabled, or left without an approved manifest; "
                                + "nothing was run.", false));
                return;
            }
            ReportPluginManifest manifest = approved.get().manifest();
            learnt = learnt.withManifest(approved.get().digest(), manifest);
            if (ProjectExportSchema.of(manifest.exportSchema()).isEmpty()) {
                finish(run, owner, requester, learnt, new ReportPluginRenderer.Outcome.Refused(
                        ReportRunReason.EXPORT_SCHEMA_UNAVAILABLE, "Its manifest reads " + ProjectExportSchema.NAME
                                + " major " + manifest.exportSchema() + ", which this installation no longer produces "
                                + "(it produces major " + ProjectExportSchema.MAJOR + "); it is never handed another."));
                return;
            }

            Optional<UserView> account = accounts.activeAccount(run.getRequestedById());
            if (account.isEmpty()) {
                finish(run, owner, requester, learnt, requesterNotAllowed("The account that requested it is no longer "
                        + "active."));
                return;
            }
            ProjectExportService.RunExport export;
            try {
                export = exportService.forRun(run.getProjectId(), account.get(),
                        // A session's: no credential narrows it, the route accepting none.
                        visibility.allowance(account.get(), Visibility.everything()), run.getRequesterLocale());
            } catch (NotFoundException | AccessDeniedException notAllowed) {
                finish(run, owner, requester, learnt, requesterNotAllowed("Its requester no longer sees the whole "
                        + "project, or no longer holds a role that may request a report; the export is built for the "
                        + "requester alone."));
                return;
            } catch (ProjectExportTooLargeException tooLarge) {
                finish(run, owner, requester, learnt, new ReportPluginRenderer.Outcome.Failed(
                        ReportRunReason.EXPORT_TOO_LARGE, tooLarge.getMessage(), false));
                return;
            }
            learnt = learnt.withExport(clock.instant(), export);

            ReportPluginRenderer.Outcome outcome;
            try {
                outcome = executor.render(manifest, export.json());
            } catch (RuntimeException failed) {
                log.warn("Report run {}: the executor failed: {}", runId, failed.getMessage(), failed);
                outcome = new ReportPluginRenderer.Outcome.Failed(ReportRunReason.EXECUTOR_ERROR,
                        "The executor failed: " + failed.getMessage(), true);
            }
            if (outcome.exportHandedOver()) {
                // The digest first: the SIEM event carries the description bounded, and the digest is what a SOC
                // matches a file it later finds against.
                audit.record(requester.entry(AuditOperation.PROJECT_EXPORTED, String.valueOf(run.getProjectId()),
                        "Project export handed to report plugin \"" + run.getPluginId() + "\", export.json SHA-256 "
                                + export.sha256() + ": run " + runId + ", manifest " + learnt.manifestDigest()
                                + ", project \"" + export.projectName() + "\", " + ProjectExportSchema.NAME + " "
                                + ProjectExportSchema.VERSION + ", " + export.issueCount() + " issue(s), "
                                + export.componentCount() + " component(s)."));
            }
            finish(run, owner, requester, learnt, outcome);
        } catch (RuntimeException unexpected) {
            log.error("Report run {} could not be carried out: {}", runId, unexpected.getMessage(), unexpected);
            try {
                finish(run, owner, requester, learnt, new ReportPluginRenderer.Outcome.Failed(
                        ReportRunReason.EXECUTOR_ERROR, "The control plane could not carry it out: "
                                + unexpected.getMessage(), learnt.export() != null));
            } catch (RuntimeException unrecorded) {
                // Left running: its lease lapses and the next turn fails it as lost.
                log.error("Report run {}: its failure could not be recorded either: {}", runId, unrecorded.getMessage());
            }
        }
    }

    private record Approved(String digest, ReportPluginManifest manifest) {}

    /** The plugin's approved manifest, if the plugin is still on for the project, enabled, and has one. */
    private Optional<Approved> approved(ReportRunEntity run) {
        return transactions.execute(status -> {
            Optional<ReportPluginEntity> plugin = plugins.findById(run.getPluginId());
            if (plugin.isEmpty() || !plugin.get().getEnabled() || plugin.get().getApprovedDigest() == null
                    || activations.findByPluginIdAndProjectId(run.getPluginId(), run.getProjectId()).isEmpty()) {
                return Optional.<Approved>empty();
            }
            return manifests.findByDigestAndPluginId(plugin.get().getApprovedDigest(), run.getPluginId())
                    .filter(row -> ReportPluginManifestStatus.ofStored(row.getStatus()) == ReportPluginManifestStatus.APPROVED)
                    .map(row -> new Approved(row.getDigest(), parse(row)));
        });
    }

    private ReportPluginManifest parse(ReportPluginManifestEntity row) {
        try {
            return json.readValue(row.getManifest(), ReportPluginManifest.class).validated();
        } catch (JsonProcessingException unreadable) {
            throw new IllegalStateException("Stored report plugin manifest " + row.getDigest() + " is unreadable.",
                    unreadable);
        }
    }

    private static ReportPluginRenderer.Outcome.Failed requesterNotAllowed(String detail) {
        return new ReportPluginRenderer.Outcome.Failed(ReportRunReason.REQUESTER_NOT_ALLOWED, detail
                + " Nothing was run.", false);
    }

    /**
     * Records the outcome — the run's row, and for a produced run its export — if {@code owner} still holds the
     * run, then audits it. A run that is no longer this owner's was decided without it: nothing is written.
     */
    private void finish(ReportRunEntity run, String owner, RequestActor requester, Learnt learnt,
            ReportPluginRenderer.Outcome outcome) {
        Instant now = clock.instant();
        ReportRunState state;
        ReportRunReason reason;
        String detail;
        Long outputSize = null;
        String outputSha256 = null;
        Integer exitCode = null;
        switch (outcome) {
            case ReportPluginRenderer.Outcome.Produced produced -> {
                state = ReportRunState.PRODUCED;
                reason = null;
                detail = null;
                outputSize = (long) produced.output().length;
                outputSha256 = Digests.sha256Hex(produced.output());
                exitCode = 0;
            }
            case ReportPluginRenderer.Outcome.Failed failed -> {
                state = ReportRunState.FAILED;
                reason = failed.reason();
                detail = bounded(failed.detail());
            }
            case ReportPluginRenderer.Outcome.Refused refused -> {
                state = ReportRunState.REFUSED;
                reason = refused.reason();
                detail = bounded(refused.detail());
            }
        }
        PluginSignature signer = state == ReportRunState.PRODUCED ? learnt.signer() : null;
        ProjectExportService.RunExport export = learnt.export();
        Long finalOutputSize = outputSize;
        String finalOutputSha256 = outputSha256;
        Integer finalExitCode = exitCode;
        boolean recorded = Boolean.TRUE.equals(transactions.execute(status -> {
            int ended = runs.finish(run.getId(), ReportRunState.RUNNING.wireName(), owner, state.wireName(),
                    reason == null ? null : reason.wireName(), detail, now,
                    export == null ? run.getProjectName() : export.projectName(), learnt.exportedAt(),
                    learnt.manifestDigest(), learnt.imageDigest(),
                    signer == null ? null : signer.identity(), signer == null ? null : signer.issuer(),
                    signer == null || signer.publicKey() == null ? null : Digests.sha256Hex(signer.publicKey()),
                    export == null ? null : ProjectExportSchema.VERSION,
                    export == null ? null : export.sha256(),
                    export == null ? null : (long) export.json().length,
                    finalExitCode, finalOutputSize, finalOutputSha256, productVersion.get());
            if (ended != 1) {
                return false;
            }
            if (state == ReportRunState.PRODUCED) {
                ReportExportEntity kept = new ReportExportEntity();
                kept.setRunId(run.getId());
                kept.setContent(export.json());
                kept.setSha256(export.sha256());
                kept.setSizeBytes((long) export.json().length);
                kept.setCreatedAt(now);
                exports.save(kept);
            }
            return true;
        }));
        if (!recorded) {
            log.warn("Report run {} was no longer this executor's when it ended ({}): its outcome is not recorded.",
                    run.getId(), state.wireName());
            return;
        }

        String about = "Report run " + run.getId() + " of report plugin \"" + run.getPluginId() + "\" for project "
                + run.getProjectId();
        switch (state) {
            // The three digests first: the description is bounded where it is stored, and they are what a reader
            // matches a document, its input and its code against.
            case PRODUCED -> audit.record(requester.entry(AuditOperation.REPORT_PRODUCED, String.valueOf(run.getId()),
                    "Report run " + run.getId() + " produced: output " + finalOutputSha256 + ", manifest "
                            + learnt.manifestDigest() + ", export " + export.sha256() + "; report plugin \""
                            + run.getPluginId() + "\", project " + run.getProjectId() + ", image " + learnt.imageDigest()
                            + ", " + finalOutputSize + " bytes, not yet checked nor signed."));
            case FAILED -> audit.record(requester.entry(AuditOperation.REPORT_FAILED, String.valueOf(run.getId()),
                    about + " failed, " + reason.wireName() + ": " + detail));
            case REFUSED -> audit.record(requester.entry(AuditOperation.REPORT_REFUSED, String.valueOf(run.getId()),
                    about + " refused, " + reason.wireName() + (learnt.manifestDigest() == null ? "" : ", manifest "
                            + learnt.manifestDigest()) + ": " + detail));
            default -> throw new IllegalStateException("A run ends produced, failed or refused, not " + state + ".");
        }
    }

    private static String bounded(String detail) {
        if (detail == null) {
            return null;
        }
        return detail.length() <= DETAIL ? detail : detail.substring(0, DETAIL - 1) + "…";
    }
}
