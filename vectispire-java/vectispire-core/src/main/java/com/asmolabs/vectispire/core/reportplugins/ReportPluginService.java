package com.asmolabs.vectispire.core.reportplugins;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.plugins.PluginSignature;
import com.asmolabs.vectispire.common.domain.reportplugins.ProjectExportSchema;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportPluginManifest;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportPluginManifestStatus;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportRunState;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportPluginActivationEntity;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportPluginActivationRepository;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportPluginEntity;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportPluginManifestEntity;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportPluginManifestRepository;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportPluginRepository;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportRunRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.SolutionQueryService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * The report plugins' registry (decision 0035 §4, lot R2): registration, the approval of each manifest digest,
 * activation per project, withdrawal — and no delete.
 *
 * <h2>Who decides what</h2>
 *
 * <ul>
 *   <li><b>Registering, updating, enabling and disabling is the platform governor's</b> — the routes carry
 *       {@code @RequiresPlatformGovernor}, as for a scanner plugin (0017 §6): deciding that third-party code
 *       may exist on the platform is a rule everybody else plays by.
 *   <li><b>A digest is approved by a second person</b> when {@code FOUR_EYES_APPROVAL_REQUIRED} is on —
 *       anybody holding {@code canWriteGovernance} (the governor, an administrator, a CISO) but the account
 *       that registered it. Its output leaves the platform under the installation's key; one person deciding
 *       alone which code may produce signed documents is the concentration four-eyes splits. With the rule off
 *       a registration takes effect at once, for 0032's reason: an installation with one approver could
 *       otherwise never register one. The rule is read when the approval is given, as for a checklist
 *       template's publication.
 *   <li><b>Switching one on for a project is the security lead's</b>, for a caller who sees the whole
 *       project, images included — the export's guard, since a report renders the whole project.
 *   <li><b>Withdrawing a digest is the governor's, in writing</b>: it never runs again, cannot be registered
 *       again, and the documents it produced will be served as withdrawn (lot R7, which reads the state kept
 *       here).
 * </ul>
 *
 * <h2>One approved digest serves; one pending waits</h2>
 *
 * <p>A plugin carries at most one approved digest — what a run uses — and one pending. Registering a new
 * manifest under four-eyes makes it the pending one and sets aside an earlier pending one ({@code
 * superseded}), which never ran; the approved one keeps serving meanwhile. Setting a plugin back to a digest
 * approved earlier and never withdrawn takes effect at once: two people have already vouched for exactly
 * those bytes.
 *
 * <p><b>Every change is audited after its transaction commits</b> — the audit log opens its own — and
 * signals {@code VECTI-SEC-031} through the outbox ({@code SecurityEventType.signalledBy}). A gesture that
 * changes nothing records nothing.
 */
@Service
public class ReportPluginService {

    /** Bounds of a withdrawal's justification (0035 §4): a sentence, not a word, nor an essay. */
    static final int MIN_JUSTIFICATION = 20;
    static final int MAX_JUSTIFICATION = 500;

    private final ReportPluginRepository plugins;
    private final ReportPluginManifestRepository manifests;
    private final ReportPluginActivationRepository activations;
    private final ReportRunRepository runs;
    private final SolutionQueryService projects;
    private final SettingsService settings;
    private final AuditLogService audit;
    private final ObjectMapper json;
    private final Clock clock;
    private final TransactionTemplate transactions;

    public ReportPluginService(
            ReportPluginRepository plugins,
            ReportPluginManifestRepository manifests,
            ReportPluginActivationRepository activations,
            ReportRunRepository runs,
            SolutionQueryService projects,
            SettingsService settings,
            AuditLogService audit,
            ObjectMapper json,
            Clock clock,
            PlatformTransactionManager transactions) {
        this.plugins = plugins;
        this.manifests = manifests;
        this.activations = activations;
        this.runs = runs;
        this.projects = projects;
        this.settings = settings;
        this.audit = audit;
        this.json = json;
        this.clock = clock;
        this.transactions = new TransactionTemplate(transactions);
    }

    // ------------------------------------------------------------------ reading

    public List<ReportPluginView> list() {
        List<ReportPluginEntity> rows = plugins.findAllByOrderByIdAsc();
        Map<String, List<ReportPluginManifestEntity>> history = manifests
                .findByPluginIdInOrderByRegisteredAtDescDigestAsc(rows.stream().map(ReportPluginEntity::getId).toList())
                .stream()
                .collect(Collectors.groupingBy(ReportPluginManifestEntity::getPluginId));
        return rows.stream().map(row -> view(row, history.getOrDefault(row.getId(), List.of()))).toList();
    }

    public ReportPluginView get(String id) {
        return view(require(id));
    }

    // ------------------------------------------------------------------ the registry

    /**
     * Registers a report plugin under a new id: approved at once with four-eyes off, pending a second
     * person's approval with it on.
     *
     * @throws com.asmolabs.vectispire.common.domain.plugins.InvalidPluginException a manifest refused (400)
     * @throws ReportPluginConflict {@code report-plugin-id-taken} — ids are never reused (409)
     */
    public ReportPluginView register(ReportPluginManifest requested, UserView registrant, RequestActor actor) {
        ReportPluginManifest manifest = requireManifest(requested);
        String digest = manifest.digest();
        boolean fourEyes = settings.isEnabled(Setting.FOUR_EYES_APPROVAL_REQUIRED);
        Instant now = clock.instant();

        ReportPluginEntity saved = write(() -> transactions.execute(status -> {
            if (plugins.existsById(manifest.id())) {
                throw new ReportPluginConflict(ReportPluginConflict.Cause.ID_TAKEN, "A report plugin with id \""
                        + manifest.id() + "\" is already registered; an id is never reused, since the documents it "
                        + "produced name it.");
            }
            store(manifest, digest, registrant, fourEyes, now);
            ReportPluginEntity plugin = new ReportPluginEntity();
            plugin.setId(manifest.id());
            plugin.setName(manifest.name());
            plugin.setApprovedDigest(fourEyes ? null : digest);
            plugin.setPendingDigest(fourEyes ? digest : null);
            plugin.setEnabled(true);
            plugin.setCreatedAt(now);
            plugin.setCreatedBy(registrant.username());
            plugin.setUpdatedAt(now);
            plugin.setUpdatedBy(registrant.username());
            return plugins.save(plugin);
        }));

        audit.record(actor.entry(AuditOperation.REPORT_PLUGIN_REGISTERED, manifest.id(),
                "Report plugin \"" + manifest.id() + "\" registered, manifest " + digest + " "
                        + (fourEyes ? "pending a second person's approval (four-eyes)" : "in effect at once (four-eyes off)")
                        + ": " + summary(manifest)));
        return view(saved);
    }

    /**
     * Gives a plugin a new manifest under the same id. With four-eyes on it waits for approval and the
     * approved one keeps serving; with it off it serves at once. A digest approved earlier serves at once;
     * a withdrawn one is refused. The pending or approved manifest again changes nothing and records nothing.
     *
     * @throws ReportPluginConflict {@code report-plugin-withdrawn} for a withdrawn digest
     */
    public ReportPluginView update(String id, ReportPluginManifest requested, UserView registrant, RequestActor actor) {
        ReportPluginManifest manifest = requireManifest(requested);
        if (!manifest.id().equals(id)) {
            throw new InvalidInputException("The manifest's id \"" + manifest.id() + "\" is not the plugin's \"" + id
                    + "\": an id is never changed, since the documents it produced name it.");
        }
        String digest = manifest.digest();
        boolean fourEyes = settings.isEnabled(Setting.FOUR_EYES_APPROVAL_REQUIRED);
        Instant now = clock.instant();

        // What the update did, for the audit entry: nothing, pending, or serving — and what it set aside.
        record Updated(ReportPluginEntity plugin, String outcome, String setAside) {}

        Updated updated = write(() -> transactions.execute(status -> {
            ReportPluginEntity plugin = require(id);
            if (digest.equals(plugin.getPendingDigest())
                    || (digest.equals(plugin.getApprovedDigest()) && plugin.getPendingDigest() == null)) {
                return new Updated(plugin, null, null);
            }
            Optional<ReportPluginManifestEntity> known = manifests.findById(digest);
            ReportPluginManifestStatus knownStatus = known.map(row -> ReportPluginManifestStatus.ofStored(row.getStatus()))
                    .orElse(null);
            if (knownStatus == ReportPluginManifestStatus.WITHDRAWN) {
                throw new ReportPluginConflict(ReportPluginConflict.Cause.WITHDRAWN, "Manifest " + digest + " of \"" + id
                        + "\" was withdrawn: it never runs again. A fixed image is a new manifest.");
            }
            String setAside = setAsidePending(plugin);
            String outcome;
            if (knownStatus == ReportPluginManifestStatus.APPROVED) {
                plugin.setApprovedDigest(digest);
                plugin.setName(manifest.name());
                outcome = "serving at once — approved before";
            } else if (fourEyes) {
                store(manifest, digest, registrant, true, now);
                plugin.setPendingDigest(digest);
                outcome = "pending a second person's approval (four-eyes); " + (plugin.getApprovedDigest() == null
                        ? "no approved manifest serves meanwhile"
                        : "manifest " + plugin.getApprovedDigest() + " serves meanwhile");
            } else {
                store(manifest, digest, registrant, false, now);
                plugin.setApprovedDigest(digest);
                plugin.setName(manifest.name());
                outcome = "in effect at once (four-eyes off)";
            }
            plugin.setUpdatedAt(now);
            plugin.setUpdatedBy(registrant.username());
            return new Updated(plugins.save(plugin), outcome, setAside);
        }));

        if (updated.outcome() != null) {
            audit.record(actor.entry(AuditOperation.REPORT_PLUGIN_UPDATED, id,
                    "Report plugin \"" + id + "\" given manifest " + digest + ", " + updated.outcome()
                            + (updated.setAside() == null ? "" : "; pending manifest " + updated.setAside() + " set aside")
                            + ": " + summary(manifest)));
        }
        return view(updated.plugin());
    }

    /**
     * Approves the plugin's pending digest: from now on, what its runs use.
     *
     * @param approver the signed-in account — one holding {@code canWriteGovernance}, and with four-eyes on
     *     not the account that registered the digest
     * @throws NotFoundException a plugin or a digest of it that does not exist
     * @throws AccessDeniedException a role that does not write governance
     * @throws ReportPluginConflict {@code report-plugin-not-pending}, {@code report-plugin-four-eyes}
     */
    public ReportPluginView approve(String id, String digest, UserView approver, RequestActor actor) {
        if (!Role.of(approver.role()).map(Role::canWriteGovernance).orElse(false)) {
            throw new AccessDeniedException("Approving a report plugin is for the roles that write governance.");
        }
        boolean fourEyes = settings.isEnabled(Setting.FOUR_EYES_APPROVAL_REQUIRED);
        Instant now = clock.instant();

        record Approved(ReportPluginEntity plugin, ReportPluginManifestEntity row) {}

        Approved approved = write(() -> transactions.execute(status -> {
            ReportPluginEntity plugin = require(id);
            ReportPluginManifestEntity row = requireManifestRow(plugin, digest);
            if (ReportPluginManifestStatus.ofStored(row.getStatus()) != ReportPluginManifestStatus.PENDING_APPROVAL
                    || !row.getDigest().equals(plugin.getPendingDigest())) {
                throw new ReportPluginConflict(ReportPluginConflict.Cause.NOT_PENDING, "Manifest " + digest + " of \""
                        + id + "\" is not awaiting approval: it is " + row.getStatus() + ".");
            }
            if (fourEyes && approver.id() != null && approver.id().equals(row.getRegisteredById())) {
                throw new ReportPluginConflict(ReportPluginConflict.Cause.FOUR_EYES, "Four-eyes approval: manifest "
                        + digest + " of \"" + id + "\" was registered by " + row.getRegisteredBy()
                        + ", so it has to be approved by somebody else.");
            }
            row.setStatus(ReportPluginManifestStatus.APPROVED.wireName());
            row.setApprovedAt(now);
            row.setApprovedBy(approver.username());
            row.setApprovedById(approver.id());
            row.setApprovalFourEyes(fourEyes);
            manifests.save(row);
            plugin.setApprovedDigest(row.getDigest());
            plugin.setPendingDigest(null);
            plugin.setName(parse(row).name());
            plugin.setUpdatedAt(now);
            plugin.setUpdatedBy(approver.username());
            return new Approved(plugins.save(plugin), row);
        }));

        audit.record(actor.entry(AuditOperation.REPORT_PLUGIN_APPROVED, id,
                "Report plugin \"" + id + "\" manifest " + digest + " approved, four-eyes "
                        + (fourEyes ? "required" : "not required") + " (registered by "
                        + approved.row().getRegisteredBy() + "): its runs use it from now on."));
        return view(approved.plugin());
    }

    /** Disables or enables a plugin; its activations are kept either way. Repeating it records nothing. */
    public ReportPluginView setEnabled(String id, boolean enabled, UserView governor, RequestActor actor) {
        record Changed(ReportPluginEntity plugin, boolean changed) {}
        Changed result = write(() -> transactions.execute(status -> {
            ReportPluginEntity plugin = require(id);
            if (plugin.getEnabled() == enabled) {
                return new Changed(plugin, false);
            }
            plugin.setEnabled(enabled);
            plugin.setUpdatedAt(clock.instant());
            plugin.setUpdatedBy(governor.username());
            return new Changed(plugins.save(plugin), true);
        }));
        if (result.changed()) {
            audit.record(actor.entry(AuditOperation.REPORT_PLUGIN_ENABLED_CHANGED, id,
                    "Report plugin \"" + id + "\" " + (enabled ? "enabled: its activations may be asked for reports again."
                            : "disabled: no report is rendered with it; its activations are kept.")));
        }
        return view(result.plugin());
    }

    /**
     * Withdraws a digest, with its justification: it never runs again and cannot be registered again; the
     * plugin's pending or approved digest, if it was this one, is cleared — a fixed image is a new manifest.
     * <b>Every document it produced is withdrawn with it</b> — read off this row by the run's manifest digest,
     * never copied onto the documents — and stays stored: its download and its run say so, and the status route
     * answers a holder that the installation no longer stands by it. The audit entry counts them.
     *
     * @throws InvalidInputException without a justification of {@value #MIN_JUSTIFICATION} to {@value
     *     #MAX_JUSTIFICATION} characters
     * @throws ReportPluginConflict {@code report-plugin-withdrawn} when it already was
     */
    public ReportPluginView withdraw(String id, String digest, String justification, UserView governor,
            RequestActor actor) {
        String reason = requireJustification(justification);
        Instant now = clock.instant();

        record Withdrawn(ReportPluginEntity plugin, String was, long documents) {}

        Withdrawn withdrawn = write(() -> transactions.execute(status -> {
            ReportPluginEntity plugin = require(id);
            ReportPluginManifestEntity row = requireManifestRow(plugin, digest);
            ReportPluginManifestStatus was = ReportPluginManifestStatus.ofStored(row.getStatus());
            if (was == ReportPluginManifestStatus.WITHDRAWN) {
                throw new ReportPluginConflict(ReportPluginConflict.Cause.WITHDRAWN, "Manifest " + digest + " of \"" + id
                        + "\" is already withdrawn.");
            }
            row.setStatus(ReportPluginManifestStatus.WITHDRAWN.wireName());
            row.setWithdrawnAt(now);
            row.setWithdrawnBy(governor.username());
            row.setWithdrawalJustification(reason);
            manifests.save(row);
            if (row.getDigest().equals(plugin.getApprovedDigest())) {
                plugin.setApprovedDigest(null);
            }
            if (row.getDigest().equals(plugin.getPendingDigest())) {
                plugin.setPendingDigest(null);
            }
            plugin.setUpdatedAt(now);
            plugin.setUpdatedBy(governor.username());
            return new Withdrawn(plugins.save(plugin), was.wireName(),
                    runs.countByManifestDigestAndState(digest, ReportRunState.PRODUCED.wireName()));
        }));

        audit.record(actor.entry(AuditOperation.REPORT_PLUGIN_WITHDRAWN, id,
                // The justification right after the digest: the column holds 255 characters, the row keeps it whole.
                // The documents it withdraws in a few characters before it, for the same reason.
                "Report plugin \"" + id + "\" manifest " + digest + " withdrawn (was " + withdrawn.was() + ", "
                        + withdrawn.documents() + " document(s) withdrawn with it): " + reason));
        return view(withdrawn.plugin());
    }

    // ------------------------------------------------------------------ activations

    /** The report plugins switched on for a project the caller sees whole; 404 otherwise. */
    public List<ReportPluginActivationView> activations(long projectId, VisibilityService.Allowance allowance) {
        requireWholeProject(projectId, allowance);
        List<ReportPluginActivationEntity> rows = activations.findByProjectIdOrderByPluginIdAsc(projectId);
        Map<String, String> names = plugins.findAllById(rows.stream().map(ReportPluginActivationEntity::getPluginId).toList())
                .stream()
                .collect(Collectors.toMap(ReportPluginEntity::getId, ReportPluginEntity::getName));
        return rows.stream().map(row -> view(row, names.get(row.getPluginId()))).toList();
    }

    /**
     * Switches a plugin on for a project. Repeating it changes nothing and records nothing. A disabled plugin
     * may be switched on — it renders once enabled — but one without an approved manifest may not.
     *
     * @throws NotFoundException a project absent, hidden or seen only in part; a plugin that does not exist
     * @throws ReportPluginConflict {@code report-plugin-not-approved}
     */
    public ReportPluginActivationView activate(long projectId, String pluginId, VisibilityService.Allowance allowance,
            RequestActor actor) {
        String projectName = requireWholeProject(projectId, allowance);
        record Activated(ReportPluginActivationEntity activation, String pluginName, boolean created) {}
        Activated result = transactions.execute(status -> {
            ReportPluginEntity plugin = require(pluginId);
            Optional<ReportPluginActivationEntity> existing = activations.findByPluginIdAndProjectId(pluginId, projectId);
            if (existing.isPresent()) {
                return new Activated(existing.get(), plugin.getName(), false);
            }
            if (plugin.getApprovedDigest() == null) {
                throw new ReportPluginConflict(ReportPluginConflict.Cause.NOT_APPROVED, "Report plugin \"" + pluginId
                        + "\" has no approved manifest — awaiting approval, or withdrawn — so it cannot be switched on.");
            }
            ReportPluginActivationEntity activation = new ReportPluginActivationEntity();
            activation.setPluginId(pluginId);
            activation.setProjectId(projectId);
            activation.setActivatedAt(clock.instant());
            activation.setActivatedBy(actorName(actor));
            return new Activated(activations.save(activation), plugin.getName(), true);
        });
        if (result.created()) {
            audit.record(actor.entry(AuditOperation.REPORT_PLUGIN_ACTIVATED, pluginId + "@" + projectId,
                    "Report plugin \"" + pluginId + "\" switched on for project \"" + projectName + "\" (" + projectId
                            + "): it may be given that project's whole export to render."));
        }
        return view(result.activation(), result.pluginName());
    }

    /** Switches it off; 404 when it was not on. */
    public void deactivate(long projectId, String pluginId, VisibilityService.Allowance allowance, RequestActor actor) {
        String projectName = requireWholeProject(projectId, allowance);
        transactions.executeWithoutResult(status -> {
            ReportPluginActivationEntity activation = activations.findByPluginIdAndProjectId(pluginId, projectId)
                    .orElseThrow(() -> new NotFoundException(
                            "Report plugin \"" + pluginId + "\" is not switched on for project " + projectId + "."));
            activations.delete(activation);
        });
        audit.record(actor.entry(AuditOperation.REPORT_PLUGIN_DEACTIVATED, pluginId + "@" + projectId,
                "Report plugin \"" + pluginId + "\" switched off for project \"" + projectName + "\" (" + projectId
                        + "): it is given that project's export no more."));
    }

    // ------------------------------------------------------------------ internals

    /**
     * The project's name, for a caller who sees every target filed in it — or the 404 of an absent project.
     * The export's guard (0035 §1): a plugin switched on here renders the whole project, images included.
     */
    private String requireWholeProject(long projectId, VisibilityService.Allowance allowance) {
        return requireWholeProject(projects, projectId, allowance);
    }

    /** The guard itself, which a report request applies too: one rule for who may have a project rendered. */
    static String requireWholeProject(SolutionQueryService projects, long projectId, VisibilityService.Allowance allowance) {
        Optional<SolutionQueryService.ProjectMembers> members = projects.members(projectId);
        Optional<String> name = members.map(SolutionQueryService.ProjectMembers::name);
        List<Long> repositoryIds = members.map(SolutionQueryService.ProjectMembers::repositoryIds).orElse(List.of());
        List<ScanTarget> filed = members.map(SolutionQueryService.ProjectMembers::targets).orElse(List.of());
        RowVisibility.requireEveryTargetOfProject(projectId, name, repositoryIds, filed, allowance);
        return RowVisibility.requireWhollyVisibleProject(projectId, name, repositoryIds, allowance).name();
    }

    /**
     * The registry's write, with a concurrent writer's win reported as what it is: somebody changed the
     * plugin between this request's read and its write — read it again — rather than a 500.
     */
    private <T> T write(Supplier<T> body) {
        try {
            return body.get();
        } catch (OptimisticLockingFailureException raced) {
            throw new ReportPluginConflict(ReportPluginConflict.Cause.CHANGED, "The report plugin changed while this "
                    + "request was being decided — another gesture won. Read it again.");
        }
    }

    /** A manifest validated, with an export major this installation produces. */
    private static ReportPluginManifest requireManifest(ReportPluginManifest manifest) {
        if (manifest == null) {
            throw new InvalidInputException("A report plugin manifest is required.");
        }
        manifest.validated();
        if (ProjectExportSchema.of(manifest.exportSchema()).isEmpty()) {
            throw new InvalidInputException("This installation produces " + ProjectExportSchema.NAME + " major "
                    + ProjectExportSchema.MAJOR + ", not " + manifest.exportSchema()
                    + ": a plugin is never handed a document of another major.");
        }
        return manifest;
    }

    /**
     * The manifest's row: inserted, or — for a digest set aside before anybody approved it, registered
     * again — made pending or approved again with its new registrant. Never its content: the digest is it.
     */
    private void store(ReportPluginManifest manifest, String digest, UserView registrant, boolean pending, Instant now) {
        ReportPluginManifestEntity row = manifests.findById(digest).orElseGet(() -> {
            ReportPluginManifestEntity fresh = new ReportPluginManifestEntity();
            fresh.setDigest(digest);
            fresh.setPluginId(manifest.id());
            try {
                fresh.setManifest(json.writeValueAsString(manifest));
            } catch (JsonProcessingException unwritable) {
                throw new IllegalStateException("The manifest could not be written.", unwritable);
            }
            return fresh;
        });
        row.setRegisteredAt(now);
        row.setRegisteredBy(registrant.username());
        row.setRegisteredById(registrant.id());
        if (pending) {
            row.setStatus(ReportPluginManifestStatus.PENDING_APPROVAL.wireName());
        } else {
            row.setStatus(ReportPluginManifestStatus.APPROVED.wireName());
            row.setApprovedAt(now);
            row.setApprovedBy(registrant.username());
            row.setApprovedById(registrant.id());
            row.setApprovalFourEyes(false);
        }
        manifests.save(row);
    }

    /** The plugin's pending digest marked superseded and cleared; its digest, or null when there was none. */
    private String setAsidePending(ReportPluginEntity plugin) {
        String pending = plugin.getPendingDigest();
        if (pending == null) {
            return null;
        }
        manifests.findById(pending).ifPresent(row -> {
            row.setStatus(ReportPluginManifestStatus.SUPERSEDED.wireName());
            manifests.save(row);
        });
        plugin.setPendingDigest(null);
        return pending;
    }

    private ReportPluginManifestEntity requireManifestRow(ReportPluginEntity plugin, String digest) {
        return manifests.findByDigestAndPluginId(digest == null ? "" : digest, plugin.getId())
                .orElseThrow(() -> new NotFoundException("Report plugin \"" + plugin.getId() + "\" has no manifest "
                        + digest + "."));
    }

    private ReportPluginEntity require(String id) {
        return plugins.findById(id == null ? "" : id)
                .orElseThrow(() -> new NotFoundException("No report plugin \"" + id + "\" is registered."));
    }

    private ReportPluginManifest parse(ReportPluginManifestEntity row) {
        try {
            return json.readValue(row.getManifest(), ReportPluginManifest.class);
        } catch (JsonProcessingException unreadable) {
            throw new IllegalStateException("Stored report plugin manifest " + row.getDigest() + " is unreadable.",
                    unreadable);
        }
    }

    private ReportPluginView view(ReportPluginEntity plugin) {
        return view(plugin, manifests.findByPluginIdOrderByRegisteredAtDescDigestAsc(plugin.getId()));
    }

    private ReportPluginView view(ReportPluginEntity plugin, List<ReportPluginManifestEntity> history) {
        return new ReportPluginView(plugin.getId(), plugin.getName(), plugin.getApprovedDigest(),
                plugin.getPendingDigest(), plugin.getEnabled(), plugin.getCreatedAt(), plugin.getCreatedBy(),
                plugin.getUpdatedAt(), plugin.getUpdatedBy(), history.stream().map(this::view).toList());
    }

    private ReportPluginManifestView view(ReportPluginManifestEntity row) {
        return new ReportPluginManifestView(row.getDigest(), ReportPluginManifestStatus.ofStored(row.getStatus()),
                parse(row), row.getRegisteredAt(), row.getRegisteredBy(), row.getApprovedAt(), row.getApprovedBy(),
                row.getApprovalFourEyes(), row.getWithdrawnAt(), row.getWithdrawnBy(), row.getWithdrawalJustification());
    }

    private static ReportPluginActivationView view(ReportPluginActivationEntity row, String pluginName) {
        return new ReportPluginActivationView(row.getId(), row.getPluginId(), pluginName, row.getProjectId(),
                row.getActivatedAt(), row.getActivatedBy());
    }

    private static String requireJustification(String justification) {
        String reason = justification == null ? "" : justification.strip();
        if (reason.length() < MIN_JUSTIFICATION || reason.length() > MAX_JUSTIFICATION) {
            throw new InvalidInputException("Withdrawing a report plugin's manifest needs its justification, written: "
                    + MIN_JUSTIFICATION + " to " + MAX_JUSTIFICATION + " characters saying what was wrong with it — "
                    + "every document it produced will be served with it.");
        }
        for (int i = 0; i < reason.length(); i++) {
            char c = reason.charAt(i);
            if (c != '\n' && Character.isISOControl(c)) {
                throw new InvalidInputException("A withdrawal's justification is text, with no control character but "
                        + "newlines.");
            }
        }
        return reason;
    }

    /**
     * What the audit entry says of a manifest: the image, the major, the type and who must have signed it —
     * a key by its fingerprint, not its PEM.
     */
    private static String summary(ReportPluginManifest manifest) {
        return "image " + manifest.image() + ", export major " + manifest.exportSchema() + ", " + manifest.mediaType()
                .wireName() + " as " + manifest.output() + " up to " + manifest.maxOutputBytes() + " bytes in "
                + manifest.timeoutSeconds() + " s, " + signer(manifest.signature()) + ".";
    }

    private static String signer(PluginSignature signature) {
        return switch (signature.form()) {
            case KEYLESS -> "signed keyless by " + signature.identity() + " via " + signature.issuer();
            case KEY -> "signed by key sha256:" + Digests.sha256Hex(signature.publicKey()).substring(0, 12);
        };
    }

    private static String actorName(RequestActor actor) {
        return actor == null || actor.username() == null ? "unknown" : actor.username();
    }
}
