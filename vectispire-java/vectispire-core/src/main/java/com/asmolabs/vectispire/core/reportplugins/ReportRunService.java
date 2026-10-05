package com.asmolabs.vectispire.core.reportplugins;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportRunReason;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportRunState;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportDocumentEntity;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportDocumentRepository;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportPluginActivationRepository;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportPluginEntity;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportPluginRepository;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportRunEntity;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportRunRepository;
import com.asmolabs.vectispire.core.targets.SolutionQueryService;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessException;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * A project's reports, asked and read (decision 0035 §2, lot R3): a request queues a run; the control plane's
 * executor claims it, builds the export and runs the plugin ({@code ReportWorker}); a run is read back with what
 * came of it.
 *
 * <h2>Who</h2>
 *
 * <p><b>The whole project, images included, or the 404 of an absent one</b> — the export's guard, since the run
 * hands the plugin that export. <b>Write accounts and auditors</b> request (answer 4); the platform governor, who
 * acts on nothing a project holds, is refused with a 403 that comes after the project's, so that it says nothing of
 * whether the project exists. A request comes through a session — the route accepts no integration key — so the
 * claim reads the requester's visibility again with no credential narrowing it. Reading the runs is anybody's who
 * sees the whole project.
 *
 * <h2>What is refused before anything is queued</h2>
 *
 * <p>A plugin not switched on for the project — or not registered: the same words, 404 —, a plugin disabled (409
 * {@code report-plugin-disabled}), one with no approved manifest (409 {@code report-plugin-not-approved}), an
 * installation with no container endpoint on the control plane (409 {@code report-executor-unavailable}), and a
 * report of the same plugin for the same project already pending or running (409 {@code report-run-in-progress}).
 * What can change between the request and the claim — the activation, the approval, the requester's grant — is
 * checked again at the claim, which fails the run with its reason rather than run what nobody may run any more.
 *
 * <h2>One at a time per plugin and project</h2>
 *
 * <p>The run's {@code active_key} is unique and set while it is pending or running: two clicks, or two people,
 * asking the same plugin for the same project render one export, not two. The insert is what arbitrates, and a
 * failed insert is not proof of a lost race — a lock timeout fails it too — so the committed row is asked before
 * the request is told to wait.
 *
 * <h2>The document</h2>
 *
 * <p>A produced run's package is downloaded by whoever may read the run — the whole project, as for the runs (§4)
 * — and the download is audited, {@code REPORT_DOWNLOADED}. Every other answer is a 404 in words: the project's
 * first, then the run's, then a run that produced nothing, then a document past the evidence window — the run is
 * visible by then, so saying which is no disclosure.
 */
@Service
public class ReportRunService {

    /** A project's runs, newest first: a screen's page, not its history — the audit log keeps that. */
    static final int LISTED = 200;

    private final ReportRunRepository runs;
    private final ReportDocumentRepository documents;
    private final ReportPluginRepository plugins;
    private final ReportPluginActivationRepository activations;
    private final ReportWithdrawals withdrawals;
    private final SolutionQueryService projects;
    private final ObjectProvider<ReportExecutor> executor;
    private final AuditLogService audit;
    private final Clock clock;
    private final TransactionTemplate transactions;

    public ReportRunService(
            ReportRunRepository runs,
            ReportDocumentRepository documents,
            ReportPluginRepository plugins,
            ReportPluginActivationRepository activations,
            ReportWithdrawals withdrawals,
            SolutionQueryService projects,
            ObjectProvider<ReportExecutor> executor,
            AuditLogService audit,
            Clock clock,
            PlatformTransactionManager transactions) {
        this.runs = runs;
        this.documents = documents;
        this.plugins = plugins;
        this.activations = activations;
        this.withdrawals = withdrawals;
        this.projects = projects;
        this.executor = executor;
        this.audit = audit;
        this.clock = clock;
        this.transactions = new TransactionTemplate(transactions);
    }

    /**
     * Queues a report of {@code pluginId} for the project, for this requester — audited {@code REPORT_REQUESTED}
     * once committed.
     *
     * @param acceptLanguage the request's {@code Accept-Language}, as sent: the export states its first language as
     *     the requester's locale
     * @throws NotFoundException "Project not found." for a project absent, hidden or seen only in part; the plugin's
     *     sentence for one not switched on for it
     * @throws AccessDeniedException for a role that may not request a report
     * @throws ReportPluginConflict {@code report-executor-unavailable}, {@code report-plugin-disabled}, {@code
     *     report-plugin-not-approved}, {@code report-run-in-progress}
     */
    public ReportRunView request(long projectId, String pluginId, UserView requester,
            VisibilityService.Allowance allowance, String acceptLanguage, RequestActor actor) {
        String projectName = ReportPluginService.requireWholeProject(projects, projectId, allowance);
        ProjectExportService.requireMayExport(requester);
        if (pluginId == null || pluginId.isBlank()) {
            throw new InvalidInputException("A report request names the report plugin to render it with (pluginId).");
        }
        if (executor.getIfAvailable() == null) {
            throw new ReportPluginConflict(ReportPluginConflict.Cause.EXECUTOR_UNAVAILABLE, "This installation has no "
                    + "container endpoint on the control plane — its built-in worker is switched off, its scans run on "
                    + "agents — so it cannot run report plugins in this version.");
        }
        String key = activeKey(pluginId, projectId);
        // At the precision the column keeps: the 202 states it, the provenance reads it back from the row, and
        // MySQL rounds a nanosecond instant where PostgreSQL truncates — the two would differ by a microsecond.
        Instant now = clock.instant().truncatedTo(ChronoUnit.MICROS);

        ReportRunEntity saved;
        try {
            saved = transactions.execute(status -> {
                ReportPluginEntity plugin = plugins.findById(pluginId)
                        .filter(found -> activations.findByPluginIdAndProjectId(pluginId, projectId).isPresent())
                        .orElseThrow(() -> new NotFoundException(notSwitchedOn(pluginId, projectId)));
                if (!plugin.getEnabled()) {
                    throw new ReportPluginConflict(ReportPluginConflict.Cause.DISABLED, "Report plugin \"" + pluginId
                            + "\" is disabled: it renders no report until the platform governor enables it again.");
                }
                if (plugin.getApprovedDigest() == null) {
                    throw new ReportPluginConflict(ReportPluginConflict.Cause.NOT_APPROVED, "Report plugin \"" + pluginId
                            + "\" has no approved manifest — awaiting approval, or withdrawn — so it renders nothing.");
                }
                if (runs.existsByActiveKey(key)) {
                    throw inProgress(pluginId, projectId);
                }
                ReportRunEntity run = new ReportRunEntity();
                run.setProjectId(projectId);
                run.setProjectName(projectName);
                run.setPluginId(pluginId);
                run.setState(ReportRunState.PENDING.wireName());
                run.setActiveKey(key);
                run.setRequestedAt(now);
                run.setRequestedBy(requester.username());
                run.setRequestedById(requester.id());
                run.setRequesterLocale(ProjectExportService.runLocale(acceptLanguage));
                return runs.saveAndFlush(run);
            });
        } catch (DataAccessException refused) {
            // The unique key refuses the second of two racing inserts — and a lock timeout or a dropped connection
            // fail an insert too. Only the committed row says which: a waiting run is a wait, anything else is the
            // failure it was.
            if (runs.existsByActiveKey(key)) {
                throw inProgress(pluginId, projectId);
            }
            throw refused;
        }

        audit.record(actor.entry(AuditOperation.REPORT_REQUESTED, String.valueOf(saved.getId()),
                "Report requested of report plugin \"" + pluginId + "\" for project \"" + projectName + "\" ("
                        + projectId + "), run " + saved.getId() + ": queued for the control plane's executor."));
        return view(saved, Optional.empty());
    }

    /** The project's runs, newest first, for a caller who sees the whole project; 404 otherwise. */
    public List<ReportRunView> runs(long projectId, VisibilityService.Allowance allowance) {
        ReportPluginService.requireWholeProject(projects, projectId, allowance);
        List<ReportRunEntity> page = runs.findByProjectIdOrderByRequestedAtDescIdDesc(projectId, PageRequest.of(0, LISTED));
        Map<String, ReportWithdrawal> withdrawn = withdrawals.of(page.stream().map(ReportRunEntity::getManifestDigest).toList());
        return page.stream()
                .map(run -> view(run, Optional.ofNullable(run.getManifestDigest()).map(withdrawn::get)))
                .toList();
    }

    /** One run of the project; the project's 404 first, then the run's. */
    public ReportRunView run(long projectId, long runId, VisibilityService.Allowance allowance) {
        ReportPluginService.requireWholeProject(projects, projectId, allowance);
        return runs.findByIdAndProjectId(runId, projectId).map(run -> view(run, withdrawals.of(run.getManifestDigest())))
                .orElseThrow(() -> new NotFoundException("Report run " + runId + " not found."));
    }

    /**
     * A produced run's package, for a caller who sees the whole project — audited {@code REPORT_DOWNLOADED} once
     * read. A document whose manifest was withdrawn is handed over all the same, with its withdrawal: it is
     * evidence of what was handed out, and refusing it would leave its holders unable to compare their copy, while
     * the response and the run say that the installation no longer stands by it (0035 §4).
     *
     * @throws NotFoundException "Project not found." for a project absent, hidden or seen only in part; then the
     *     run's 404, a run that produced no document, or a document purged past the evidence window
     */
    public ReportDocumentDownload document(long projectId, long runId, VisibilityService.Allowance allowance,
            RequestActor actor) {
        ReportPluginService.requireWholeProject(projects, projectId, allowance);
        ReportRunEntity run = runs.findByIdAndProjectId(runId, projectId)
                .orElseThrow(() -> new NotFoundException("Report run " + runId + " not found."));
        ReportRunState state = ReportRunState.ofStored(run.getState());
        if (state != ReportRunState.PRODUCED) {
            throw new NotFoundException("Report run " + runId + " has no document: it is " + state.wireName()
                    + (state.ended() ? ", and only a produced run has one." : "; its document comes when it produces."));
        }
        ReportDocumentEntity document = documents.findById(runId).orElseThrow(() -> new NotFoundException(
                "The document of report run " + runId + " is no longer kept: its bytes were purged past the evidence "
                        + "window. The run keeps its digests — output " + run.getOutputSha256() + ", package "
                        + run.getPackageSha256() + "."));

        Optional<ReportWithdrawal> withdrawal = withdrawals.of(run.getManifestDigest());

        audit.record(actor.entry(AuditOperation.REPORT_DOWNLOADED, String.valueOf(runId),
                "Report downloaded, run " + runId + ": output " + run.getOutputSha256() + ", package "
                        + document.getSha256() + "; report plugin \"" + run.getPluginId() + "\", project \""
                        + run.getProjectName() + "\" (" + projectId + ")"
                        + withdrawal.map(found -> "; served as withdrawn, its manifest withdrawn at "
                                + found.withdrawnAt() + ".").orElse(".")));
        return new ReportDocumentDownload("report-" + runId + "-" + run.getPluginId() + ".zip", document.getSha256(),
                document.getContent(), withdrawal);
    }

    /** What keeps one run of a plugin per project pending or running at a time. */
    public static String activeKey(String pluginId, long projectId) {
        return pluginId + "@" + projectId;
    }

    private static ReportPluginConflict inProgress(String pluginId, long projectId) {
        return new ReportPluginConflict(ReportPluginConflict.Cause.RUN_IN_PROGRESS, "A report of \"" + pluginId
                + "\" for project " + projectId + " is already pending or running: it is the one to wait for.");
    }

    /** The plugin's 404 — the same words for a plugin that does not exist and one not switched on here. */
    private static String notSwitchedOn(String pluginId, long projectId) {
        return "Report plugin \"" + pluginId + "\" is not switched on for project " + projectId + ".";
    }

    static ReportRunView view(ReportRunEntity run, Optional<ReportWithdrawal> withdrawal) {
        return new ReportRunView(run.getId(), run.getProjectId(), run.getProjectName(), run.getPluginId(),
                ReportRunState.ofStored(run.getState()), ReportRunReason.ofStored(run.getReason()).orElse(null),
                run.getDetail(), run.getRequestedAt(), run.getRequestedBy(), run.getStartedAt(), run.getExportedAt(),
                run.getFinishedAt(), run.getManifestDigest(), run.getImageDigest(), run.getSignerIdentity(),
                run.getSignerIssuer(), run.getSignerKeySha256(), run.getExportSchemaVersion(), run.getExportSha256(),
                run.getExportSize(), run.getExitCode(), run.getOutputSize(), run.getOutputSha256(),
                run.getProductVersion(), run.getOutputMediaType(), run.getSigningKeyId(), run.getPackageSha256(),
                withdrawal.map(ReportWithdrawal::withdrawnAt).orElse(null),
                withdrawal.map(ReportWithdrawal::withdrawnBy).orElse(null),
                withdrawal.map(ReportWithdrawal::withdrawalJustification).orElse(null));
    }
}
