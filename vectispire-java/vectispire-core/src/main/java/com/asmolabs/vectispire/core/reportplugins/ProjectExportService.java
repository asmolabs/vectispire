package com.asmolabs.vectispire.core.reportplugins;

import com.asmolabs.vectispire.common.domain.access.VisibleProject;
import com.asmolabs.vectispire.common.domain.access.VisibleScope;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.checklists.DocumentZip;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceEvaluation;
import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.issues.RemediationSla;
import com.asmolabs.vectispire.common.domain.reportplugins.ProjectExport;
import com.asmolabs.vectispire.common.domain.reportplugins.ProjectExportBounds;
import com.asmolabs.vectispire.common.domain.reportplugins.ProjectExportSchema;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.AccountNames;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.access.UserView;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.checklists.ChecklistDocumentService;
import com.asmolabs.vectispire.core.compliance.ComplianceService;
import com.asmolabs.vectispire.core.crypto.SigningKeyService;
import com.asmolabs.vectispire.core.gate.GateRegisterService;
import com.asmolabs.vectispire.core.gate.GateVerdictView;
import com.asmolabs.vectispire.core.inventory.ConsolidatedInventoryService;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.IssueView;
import com.asmolabs.vectispire.core.issues.SlaService;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueFilters;
import com.asmolabs.vectispire.core.scanning.PluginOutcome;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.persistence.queries.NewestCompletedScanRow;
import com.asmolabs.vectispire.core.settings.BrandingProperties;
import com.asmolabs.vectispire.core.settings.ExportProperties;
import com.asmolabs.vectispire.core.settings.ProductVersion;
import com.asmolabs.vectispire.core.targets.ContainerView;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import com.asmolabs.vectispire.core.targets.SolutionQueryService;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * A project's export — the {@code vectispire-project-export} document of decision 0035 §1 — built for a
 * caller who sees the whole project, signed by the platform's key, and handed over audited.
 *
 * <h2>Who, and for what</h2>
 *
 * <p><b>The whole project, images included, or the 404 of an absent one</b> ({@link
 * RowVisibility#requireEveryTargetOfProject}): an export is a statement about a project under the platform's
 * key, and built from part of it would leave out targets nobody told the reader about. An integration key
 * narrowed to one repository never sees a whole project. <b>Write accounts and auditors</b> may take one
 * (answer 4); the platform governor, who acts on nothing, may not — the role's refusal is a 403, since a
 * role is no secret, and comes after the project's, so that it says nothing of whether the project exists.
 *
 * <h2>What is in it, and what never is</h2>
 *
 * <p>The parts the schema lists, each read from its owner. Never source: an issue's text is carried only for
 * the types whose text is an advisory's or a catalogue's ({@link #CARRIES_TITLE}), since a tool's message
 * may quote the code it matched and a secret's the secret. Never a credential: a repository's URL is the
 * masked one every screen shows. Never an e-mail address: people are named by display name ({@link
 * AccountNames}). Evidence by digest only — the embedded checklist statements already do so.
 *
 * <h2>Bounded, never cut short</h2>
 *
 * <p>Over {@link ProjectExportBounds#STANDARD} the request is refused with the figure that exceeded (409
 * {@code project-export-too-large}): the issues counted before one is read, the components once merged, the
 * JSON as it is written, into a buffer that stops at the bound rather than holding any size to measure it.
 *
 * <h2>One read, then the audit</h2>
 *
 * <p>Built in one read-only transaction — every part from one snapshot — and audited after it ends ({@code
 * PROJECT_EXPORTED}, which signals {@code VECTI-SEC-032}): the audit log writes in a transaction of its own,
 * and an entry naming an export nobody received would be a false one.
 */
@Service
public class ProjectExportService {

    /** The zip's two entries: the export, and its detached signature as cosign writes one. */
    static final String EXPORT = "export.json";
    static final String SIGNATURE = EXPORT + ".sig";

    /**
     * The types whose stored text is an advisory's or a catalogue's, never a tool's message about the code:
     * the only ones whose {@code title} the export carries. A type added later carries none until it is put
     * here, which is the safe side to be wrong on.
     */
    static final Set<FindingType> CARRIES_TITLE = EnumSet.of(FindingType.VULNERABILITY, FindingType.LICENSE,
            FindingType.EOL);

    private final SolutionQueryService projects;
    private final TargetCatalog targets;
    private final AccountNames names;
    private final ScanCatalog scans;
    private final GateRegisterService gate;
    private final IssueCatalog issues;
    private final SlaService sla;
    private final ConsolidatedInventoryService inventory;
    private final ComplianceService compliance;
    private final ChecklistDocumentService checklists;
    private final SigningKeyService signing;
    private final ProductVersion productVersion;
    private final BrandingProperties branding;
    private final ExportProperties exportProperties;
    private final ObjectMapper json;
    private final AuditLogService audit;
    private final Clock clock;
    private final TransactionTemplate reading;

    public ProjectExportService(
            SolutionQueryService projects,
            TargetCatalog targets,
            AccountNames names,
            ScanCatalog scans,
            GateRegisterService gate,
            IssueCatalog issues,
            SlaService sla,
            ConsolidatedInventoryService inventory,
            ComplianceService compliance,
            ChecklistDocumentService checklists,
            SigningKeyService signing,
            ProductVersion productVersion,
            BrandingProperties branding,
            ExportProperties exportProperties,
            ObjectMapper json,
            AuditLogService audit,
            Clock clock,
            PlatformTransactionManager transactions) {
        this.projects = projects;
        this.targets = targets;
        this.names = names;
        this.scans = scans;
        this.gate = gate;
        this.issues = issues;
        this.sla = sla;
        this.inventory = inventory;
        this.compliance = compliance;
        this.checklists = checklists;
        this.signing = signing;
        this.productVersion = productVersion;
        this.branding = branding;
        this.exportProperties = exportProperties;
        this.json = json;
        this.audit = audit;
        this.clock = clock;
        this.reading = new TransactionTemplate(transactions);
        this.reading.setReadOnly(true);
    }

    /**
     * The schema of a major this installation produces, or "No project export schema of major N." — the
     * same words for a major retired and one never written.
     */
    public byte[] schema(int major) {
        return ProjectExportSchema.of(major).orElseThrow(() -> new NotFoundException(
                "No project export schema of major " + major + ": this installation produces major "
                        + ProjectExportSchema.MAJOR + "."));
    }

    /**
     * The project's export, signed, for this caller — audited once built.
     *
     * @param requester the signed-in account, or the account an integration key acts for
     * @param allowance the caller's visibility — the account's grant intersected with the credential's
     *     restriction, so that a key narrowed to one repository never sees a whole project
     * @param acceptLanguage the request's {@code Accept-Language}, as sent; its first language is the
     *     requester's locale, absent when it names none
     * @throws NotFoundException "Project not found." for a project absent, hidden, or seen only in part
     * @throws AccessDeniedException for a role that may not take an export
     * @throws ProjectExportTooLargeException over a bound
     */
    public ProjectExportDownload export(long projectId, UserView requester, VisibilityService.Allowance allowance,
            String acceptLanguage, RequestActor actor) {
        return export(projectId, requester, allowance, acceptLanguage, actor, ProjectExportBounds.STANDARD);
    }

    /** {@link #export}, under other bounds — the refusals' test, which cannot store 100,000 issues per run. */
    ProjectExportDownload export(long projectId, UserView requester, VisibilityService.Allowance allowance,
            String acceptLanguage, RequestActor actor, ProjectExportBounds bounds) {
        Built built = reading.execute(status -> build(projectId, requester, allowance, locale(acceptLanguage), bounds));

        byte[] signature = signing.sign(built.json()).getBytes(StandardCharsets.US_ASCII);
        LinkedHashMap<String, DocumentZip.Entry> parts = new LinkedHashMap<>();
        parts.put(EXPORT, DocumentZip.Entry.of(built.json()));
        parts.put(SIGNATURE, DocumentZip.Entry.of(signature));
        byte[] content = DocumentZip.of(parts);
        String sha256 = Digests.sha256Hex(built.json());

        // The digest first: the SIEM event carries the entry's description bounded, and a long project
        // name must not push out the one value a SOC matches the file it later finds against.
        audit.record(actor.entry(AuditOperation.PROJECT_EXPORTED, String.valueOf(projectId),
                "Project export downloaded, export.json SHA-256 " + sha256 + ": project \"" + built.projectName()
                        + "\", " + ProjectExportSchema.NAME + " " + ProjectExportSchema.VERSION + ", "
                        + built.issueCount() + " issue(s), " + built.componentCount() + " component(s), signed with key "
                        + signing.getKeyId() + "."));
        return new ProjectExportDownload("project-" + projectId + "-export.zip", sha256, content);
    }

    /**
     * The export a report run hands its plugin (decision 0035 §2): built at the claim — the instant the document
     * describes — for the requester as they see the project <em>now</em>, by the same rules as a download.
     * Unsigned and not audited here: the package's provenance attests to it by its digest, and the run records
     * whether the export reached a plugin — a refused one never received it.
     *
     * @param allowance the requester's visibility, read again at the claim; a report is asked through a session,
     *     never an integration key, so no credential narrows it
     * @param locale the requester's locale, as the request named it
     * @param bounds the standard bounds, or lower ones where the run could not keep an export that large
     * @throws NotFoundException "Project not found." for a project gone, or no longer seen whole
     * @throws AccessDeniedException for a role that may no longer take an export
     * @throws ProjectExportTooLargeException over a bound
     */
    public RunExport forRun(long projectId, UserView requester, VisibilityService.Allowance allowance, String locale,
            ProjectExportBounds bounds) {
        Built built = reading.execute(status -> build(projectId, requester, allowance, locale, bounds));
        return new RunExport(built.projectName(), built.json(), Digests.sha256Hex(built.json()), built.issueCount(),
                built.componentCount(), built.about().id(), built.about().requester());
    }

    /**
     * An export handed to a report plugin, and what the run records of it.
     *
     * @param exportId the export's own identifier, as {@code export.id} states it
     * @param requester the requester as the export names them — by display name, never an e-mail address — which
     *     the package's provenance repeats
     */
    public record RunExport(String projectName, byte[] json, String sha256, int issueCount, int componentCount,
            String exportId, ProjectExport.Person requester) {}

    /** The requester's locale as a run keeps it: {@link #locale}, or nothing past a BCP 47 tag's usual length. */
    static String runLocale(String acceptLanguage) {
        String locale = locale(acceptLanguage);
        return locale == null || locale.length() > 35 ? null : locale;
    }

    /** The export's bytes and what the audit entry says of them. */
    private record Built(
            String projectName, byte[] json, int issueCount, int componentCount, ProjectExport.About about) {}

    private Built build(long projectId, UserView requester, VisibilityService.Allowance allowance, String locale,
            ProjectExportBounds bounds) {
        Optional<SolutionQueryService.ProjectMembers> members = projects.members(projectId);
        Optional<String> name = members.map(SolutionQueryService.ProjectMembers::name);
        List<Long> repositoryIds = members.map(SolutionQueryService.ProjectMembers::repositoryIds).orElse(List.of());
        List<ScanTarget> filed = members.map(SolutionQueryService.ProjectMembers::targets).orElse(List.of());
        // The project first, then the role: a governor asking for a project that does not exist is told
        // so in the words anybody else is, and the 403 says nothing about the project.
        VisibleScope scope = RowVisibility.requireEveryTargetOfProject(projectId, name, repositoryIds, filed, allowance);
        VisibleProject whole = RowVisibility.requireWhollyVisibleProject(projectId, name, repositoryIds, allowance);
        requireMayExport(requester);

        IssueFilters backlog = backlogOf(filed, scope, null);
        long open = issues.count(backlogOf(filed, scope, IssueState.OPEN.wireName()));
        bounds.issues(open).ifPresent(exceeded -> {
            throw new ProjectExportTooLargeException(exceeded);
        });
        ConsolidatedInventoryService.ConsolidatedInventory merged = inventory.of(scope);
        bounds.components(merged.components().size()).ifPresent(exceeded -> {
            throw new ProjectExportTooLargeException(exceeded);
        });

        List<IssueView> unresolved = issues.issues(backlogOf(filed, scope, IssueState.OPEN.wireName())).stream()
                .sorted(Comparator.comparing(IssueView::id))
                .toList();
        // Counted again from what was read: the bound was asked of a count, and a scan landing between the
        // two statements must not slip a list past it.
        bounds.issues(unresolved.size()).ifPresent(exceeded -> {
            throw new ProjectExportTooLargeException(exceeded);
        });
        List<ProjectExport.Checklist> statements = checklists.statementsForExport(whole, repositoryIds).stream()
                .map(exported -> new ProjectExport.Checklist(exported.draft(), exported.documentSha256(),
                        exported.statement()))
                .toList();

        // Every name a part records, resolved once: display names, never the user names the rows keep.
        Set<String> recorded = new HashSet<>();
        unresolved.forEach(issue -> recorded.add(issue.triagedBy()));
        statements.forEach(checklist -> checklist.statement().withNames(stored -> {
            recorded.add(stored);
            return stored;
        }));
        Map<String, AccountNames.Named> people = names.byUsername(recorded);

        ProjectExport.About about = about(requester, locale);
        ProjectExport document = ProjectExport.of(
                about,
                project(projectId, allowance, repositoryIds, members.map(SolutionQueryService.ProjectMembers::containerIds)
                        .orElse(List.of())),
                scansOf(filed),
                verdictsOf(filed),
                unresolved.stream().map(issue -> issue(issue, people)).toList(),
                issues.countByTypeSeverityStateAndTriage(backlog).stream()
                        .sorted(Comparator.comparing(IssueAggregates.StateCount::type)
                                .thenComparing(IssueAggregates.StateCount::severity)
                                .thenComparing(IssueAggregates.StateCount::state)
                                .thenComparing(IssueAggregates.StateCount::triageStatus,
                                        Comparator.nullsFirst(Comparator.naturalOrder())))
                        .map(count -> new ProjectExport.IssueCount(count.type(), count.severity(), count.state(),
                                count.triageStatus(), count.count()))
                        .toList(),
                inventoryOf(merged),
                complianceOf(scope),
                statements.stream()
                        .map(checklist -> new ProjectExport.Checklist(checklist.draft(), checklist.documentSha256(),
                                checklist.statement().withNames(stored -> displayName(stored, people))))
                        .toList());

        ProjectExportBounds.BoundedBuffer buffer = bounds.buffer();
        try {
            json.writerWithDefaultPrettyPrinter().writeValue(buffer, document);
        } catch (Exception failed) {
            for (Throwable cause = failed; cause != null; cause = cause.getCause()) {
                if (cause instanceof ProjectExportBounds.TooLarge tooLarge) {
                    throw new ProjectExportTooLargeException(tooLarge.exceeded());
                }
            }
            throw new IllegalStateException("A project export could not be written.", failed);
        }
        return new Built(whole.name(), buffer.toByteArray(), unresolved.size(), merged.components().size(), about);
    }

    /**
     * Write accounts and auditors (decision 0035, answer 4): an auditor reads a project's whole state
     * already, and an export is reading. The governor — no effects, no triage — is the one role left out.
     */
    static void requireMayExport(UserView requester) {
        Optional<Role> role = Optional.ofNullable(requester).flatMap(user -> Role.of(user.role()));
        if (role.isEmpty() || !(role.get().canCauseEffects() || role.get() == Role.AUDITOR)) {
            throw new AccessDeniedException("A project export is taken by a write account or an auditor; the platform "
                    + "governor's role acts on nothing a project holds.");
        }
    }

    /** The project's backlog: its targets, and the caller's visibility beside them, which is the whole. */
    private static IssueFilters backlogOf(List<ScanTarget> filed, VisibleScope scope, String state) {
        return new IssueFilters(state, null, null, null, null, null, false, false, null, false, Map.of(),
                scope.visibility(), null, false, Set.copyOf(filed));
    }

    private ProjectExport.About about(UserView requester, String locale) {
        ProjectExport.Person person = names.byId(requester.id())
                .map(named -> new ProjectExport.Person(named.accountId(), named.displayName()))
                .orElse(new ProjectExport.Person(requester.id(), null));
        return new ProjectExport.About(UUID.randomUUID().toString(), clock.instant(), productVersion.get(), person,
                locale, new ProjectExport.Installation(branding.name(), exportProperties.publicUrl().orElse(null)));
    }

    private ProjectExport.Project project(long projectId, VisibilityService.Allowance allowance,
            List<Long> repositoryIds, List<Long> containerIds) {
        SolutionQueryService.ProjectDetail detail = projects.project(projectId, allowance);
        List<ProjectExport.Repository> repositories = targets.repositories(repositoryIds).stream()
                .sorted(Comparator.comparing(RepositoryView::id))
                // The URL as every screen shows it: a token the stored URL carries is masked, never exported.
                .map(repository -> new ProjectExport.Repository(repository.id(), repository.name(),
                        RepositoryUrl.redact(repository.url()), repository.branch(), repository.subPath()))
                .toList();
        List<ProjectExport.Container> containers = targets.containers(containerIds).stream()
                .sorted(Comparator.comparing(ContainerView::id))
                .map(container -> new ProjectExport.Container(container.id(), container.registry(),
                        container.imageName(), container.tag()))
                .toList();
        ProjectExport.Solution solution = detail.solution() == null || detail.solution().id() == null ? null
                : new ProjectExport.Solution(detail.solution().id(), detail.solution().name());
        return new ProjectExport.Project(projectId, detail.name(), detail.description(), detail.createdAt(), solution,
                repositories, containers);
    }

    private List<ProjectExport.TargetScan> scansOf(List<ScanTarget> filed) {
        Map<ScanTarget, NewestCompletedScanRow> newest = scans.newestCompleted(filed);
        Map<Long, ScanCatalog.ScanOutline> outlines =
                scans.outlinesOf(newest.values().stream().map(NewestCompletedScanRow::scanId).toList());
        return filed.stream().map(target -> {
            ScanCatalog.ScanOutline outline = Optional.ofNullable(newest.get(target))
                    .map(row -> outlines.get(row.scanId())).orElse(null);
            return new ProjectExport.TargetScan(targetOf(target), outline == null ? null : scan(outline));
        }).toList();
    }

    private static ProjectExport.Scan scan(ScanCatalog.ScanOutline outline) {
        List<String> examined = outline.examinedTypes()
                .map(types -> types.stream().map(FindingType::wireName).sorted().toList())
                .orElse(null);
        List<String> failures = outline.failures() == null || outline.failures().isBlank()
                ? List.of()
                : Arrays.stream(outline.failures().split(" \\| ")).filter(failure -> !failure.isBlank()).toList();
        return new ProjectExport.Scan(outline.id(), outline.createdAt(), outline.durationMs(), examined, failures,
                outline.plugins().stream().map(ProjectExportService::step).toList());
    }

    private static ProjectExport.PluginStep step(PluginOutcome outcome) {
        return new ProjectExport.PluginStep(outcome.pluginId(), outcome.manifestDigest(), outcome.state(),
                outcome.findings(), outcome.languages(), outcome.reason(), outcome.refusal(), outcome.signature());
    }

    private List<ProjectExport.TargetVerdict> verdictsOf(List<ScanTarget> filed) {
        return filed.stream().map(target -> {
            Optional<GateVerdictView> last = switch (target) {
                case ScanTarget.Repository repository -> gate.lastForRepository(repository.id(), Instant.EPOCH, null);
                case ScanTarget.Container container -> gate.lastForContainer(container.id(), Instant.EPOCH, null);
            };
            return new ProjectExport.TargetVerdict(targetOf(target), last.map(verdict -> new ProjectExport.Verdict(
                    verdict.passed(), verdict.decidedAt(), verdict.failOnSeverity(), verdict.policySource(),
                    verdict.policyVersion(), verdict.relaxationsIgnored(), verdict.evaluated(), verdict.violations(),
                    verdict.criticalCount(), verdict.highCount(), verdict.mediumCount(), verdict.lowCount()))
                    .orElse(null));
        }).toList();
    }

    private ProjectExport.Issue issue(IssueView issue, Map<String, AccountNames.Named> people) {
        boolean titled = FindingType.fromWireName(issue.type()).map(CARRIES_TITLE::contains).orElse(false);
        ProjectExport.Component component = issue.packageName() == null && issue.purl() == null ? null
                : new ProjectExport.Component(issue.packageName(), issue.packageVersion(), issue.purl());
        Optional<TriageStatus> status = TriageStatus.fromWireName(issue.triageStatus());
        // A decision is one somebody recorded: a new issue starts under review with nobody named, and the
        // export says nobody decided rather than print the default as a decision.
        boolean decided = issue.triagedAt() != null || issue.triagedBy() != null;
        ProjectExport.Triage triage = !decided ? null : new ProjectExport.Triage(
                issue.triageStatus(), issue.triageJustification(), issue.triageComment(),
                issue.triagedBy() == null ? null : person(issue.triagedBy(), people), issue.triagedAt(),
                issue.triageExpiresAt());
        Optional<RemediationSla.Assessment> deadline = sla.policy().assess(Severity.of(issue.severity()),
                issue.firstSeenAt(), IssueState.OPEN.wireName().equals(issue.state()),
                status.map(TriageStatus::isSettled).orElse(false), clock.instant());
        return new ProjectExport.Issue(issue.id(),
                issue.repoId() != null ? new ProjectExport.Target(ProjectExport.Target.REPOSITORY, issue.repoId())
                        : new ProjectExport.Target(ProjectExport.Target.CONTAINER, issue.containerId()),
                issue.type(), issue.severity(), issue.identifier(), titled ? issue.description() : null,
                issue.tool() != null ? issue.tool() : issue.source(), component, issue.filePath(), issue.line(),
                issue.firstSeenAt(), issue.lastSeenAt(), issue.state(), issue.isKev(), issue.epssScore(),
                issue.cvssScore(), issue.fixVersions(), triage,
                deadline.map(assessment -> new ProjectExport.Remediation(assessment.dueAt(),
                        assessment.state().name().toLowerCase(Locale.ROOT))).orElse(null));
    }

    private static ProjectExport.Inventory inventoryOf(ConsolidatedInventoryService.ConsolidatedInventory merged) {
        return new ProjectExport.Inventory(merged.complete(),
                merged.targets().stream().map(target -> new ProjectExport.InventoryTarget(
                        new ProjectExport.Target(target.kind(), target.id()), target.scanId(),
                        target.inventory().wireName(), target.componentCount())).toList(),
                merged.components().stream().map(component -> new ProjectExport.InventoryComponent(component.name(),
                        component.version(), component.purl(), component.type(),
                        component.targets().stream().map(carrier -> new ProjectExport.Target(carrier.kind(), carrier.id()))
                                .toList(), component.sources())).toList());
    }

    private ProjectExport.Compliance complianceOf(VisibleScope scope) {
        ComplianceService.ComplianceSummary summary = compliance.getSummary(scope.visibility());
        return new ProjectExport.Compliance(summary.totalMonitoredTargets(), summary.observedTargets(),
                summary.freshTargets(), summary.evaluations().stream().map(ProjectExportService::framework).toList());
    }

    private static ProjectExport.Framework framework(ComplianceEvaluation evaluation) {
        return new ProjectExport.Framework(evaluation.framework().name(), evaluation.framework().getTitle(),
                evaluation.overallStatus().name(), evaluation.scorePercentage(),
                evaluation.controls().stream().map(assessed -> new ProjectExport.Control(assessed.control().id(),
                        assessed.control().name(), assessed.control().category().name(), assessed.status().name(),
                        assessed.scorePercentage(), assessed.details())).toList());
    }

    private static ProjectExport.Target targetOf(ScanTarget target) {
        return switch (target) {
            case ScanTarget.Repository repository ->
                    new ProjectExport.Target(ProjectExport.Target.REPOSITORY, repository.id());
            case ScanTarget.Container container -> new ProjectExport.Target(ProjectExport.Target.CONTAINER, container.id());
        };
    }

    /** A recorded user name as the export names its holder: by account and display name, or nobody. */
    private static ProjectExport.Person person(String recorded, Map<String, AccountNames.Named> people) {
        AccountNames.Named named = people.get(recorded);
        return named == null ? new ProjectExport.Person(null, null)
                : new ProjectExport.Person(named.accountId(), named.displayName());
    }

    /** A statement's name, as the export prints it: the display name, or nothing. */
    private static String displayName(String recorded, Map<String, AccountNames.Named> people) {
        AccountNames.Named named = recorded == null ? null : people.get(recorded);
        return named == null ? null : named.displayName();
    }

    /**
     * The first language an {@code Accept-Language} names, as a BCP 47 tag — absent when it names none, or
     * cannot be read: a wildcard is nobody's language, and an unreadable header is not the requester's
     * fault to be refused for.
     */
    static String locale(String acceptLanguage) {
        if (acceptLanguage == null || acceptLanguage.isBlank() || acceptLanguage.length() > 200) {
            return null;
        }
        try {
            return Locale.LanguageRange.parse(acceptLanguage).stream()
                    .map(Locale.LanguageRange::getRange)
                    .filter(range -> !range.contains("*"))
                    .findFirst()
                    .map(range -> Locale.forLanguageTag(range).toLanguageTag())
                    .filter(tag -> !tag.equals("und"))
                    .orElse(null);
        } catch (IllegalArgumentException unreadable) {
            return null;
        }
    }
}
