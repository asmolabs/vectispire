package com.asmolabs.vectispire.core.forges;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.forges.ImportMapping.Placement;
import com.asmolabs.vectispire.common.domain.forges.ImportSkip;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeImportRequest;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeImportResult;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeImportedTarget;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeRefusedImport;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeSkippedImport;
import com.asmolabs.vectispire.core.forges.internal.ImportPlanner;
import com.asmolabs.vectispire.core.forges.internal.ImportPlanner.Plan;
import com.asmolabs.vectispire.core.forges.internal.ImportPlanner.Source;
import com.asmolabs.vectispire.core.forges.persistence.ForgeImportLinkEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeImportLinkRepository;
import com.asmolabs.vectispire.core.targets.RepositoryView;
import com.asmolabs.vectispire.core.targets.SolutionAdministrationService.ProjectView;
import com.asmolabs.vectispire.core.targets.SolutionAdministrationService.SolutionView;
import com.asmolabs.vectispire.core.targets.TargetImports;
import com.asmolabs.vectispire.core.targets.TargetScans;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Importing a discovery's selected repositories as ordinary targets (decision 0037 §5, lot D6).
 *
 * <p><b>Up to 1,000 repositories in one transaction</b>, so that a failure halfway leaves no half-filed estate:
 * everything or nothing. The targets, solutions and projects are created by the targets' owner through the forms'
 * own gestures ({@link TargetImports}) — the same refusals, the same entries — with the provenance link written
 * beside each target in the same transaction.
 *
 * <p><b>Planned again inside the transaction.</b> The preview's verdict is advice (§4): whatever became a target in
 * between — typed by hand, imported by somebody else — is read here and skipped, {@code already_present} or {@code
 * already_imported}. Replaying an import therefore creates nothing.
 *
 * <p><b>Two imports of one selection at once.</b> Both read the same repositories as absent; the unique guard of
 * V73 — the repository, its branch and its sub-path — lets the first target in, and the second import's write is
 * refused, waiting first on the winner's key. A failed import does not say why it failed, and a lock timeout or a
 * dropped connection fail it the same way; so once it has rolled back, the import is planned again from what is
 * committed. If that plan creates less than the one that failed, something got there first, and the import runs
 * again, skipping it; if it creates the same, the failure was the import's own and is thrown as it came.
 *
 * <p><b>Audited after the commit</b>: each creation's entry, as the forms write it, with where it came from; then
 * one {@code FORGE_IMPORT_APPLIED} entry summarising the gesture, signalled {@code VECTI-SEC-035} once — a SOC wants
 * one event for one gesture, not three hundred — and only when the import created something.
 *
 * <p><b>No grant, no schedule of its own.</b> A new target is visible to administrators and to whoever holds a grant
 * on the project it is filed into (answer 5), and takes the installation's default schedule at its own slot.
 */
@Service
public class ForgeImportService {

    private static final Logger log = LoggerFactory.getLogger(ForgeImportService.class);

    /** How many times an import that lost a race is planned again: each attempt skips what the winner created. */
    static final int ATTEMPTS = 3;

    private final ImportPlanner planner;
    private final TargetImports targets;
    private final ForgeImportLinkRepository links;
    private final AuditLogService audit;

    public ForgeImportService(
            ImportPlanner planner, TargetImports targets, ForgeImportLinkRepository links, AuditLogService audit) {
        this.planner = planner;
        this.targets = targets;
        this.links = links;
        this.audit = audit;
    }

    /** What one transaction created, and the plan it applied. */
    private record Applied(Plan plan, List<ForgeImportedTarget> created, List<String> solutions, List<String> projects) {}

    /**
     * Imports the request's repositories.
     *
     * @throws InvalidInputException the request out of its bounds, naming what does not exist, or a repository the
     *     import would refuse — the first ones named; the preview lists them all
     */
    public ForgeImportResult apply(UUID connectionId, ForgeImportRequest request, RequestActor actor) {
        for (int attempt = 1; ; attempt++) {
            Plan[] tried = new Plan[1];
            try {
                Applied applied = targets.inOneTransaction(actor, batch -> {
                    Source source = planner.source(connectionId, request == null ? null : request.discoveryId());
                    Plan plan = planner.plan(source, request);
                    tried[0] = plan;
                    refuseIfAnyRefused(plan.refused());
                    return write(plan, batch, actor);
                });
                record(applied, actor);
                return result(applied);
            } catch (RuntimeException failed) {
                if (tried[0] == null || attempt >= ATTEMPTS || !raced(connectionId, request, tried[0])) {
                    throw failed;
                }
                log.info("Forge import from connection {} lost a race (attempt {}): planned again from what is "
                        + "committed: {}", connectionId, attempt, failed.getMessage());
            }
        }
    }

    /** Whether what is committed now makes the request create less than the attempt that failed. */
    private boolean raced(UUID connectionId, ForgeImportRequest request, Plan failed) {
        try {
            Plan now = planner.plan(planner.source(connectionId, request.discoveryId()), request);
            return !ImportPlanner.sameCreations(failed, now);
        } catch (RuntimeException unreadable) {
            return false;
        }
    }

    private static void refuseIfAnyRefused(List<ForgeRefusedImport> refused) {
        if (refused.isEmpty()) {
            return;
        }
        String first = refused.stream().limit(3)
                .map(repository -> repository.fullPath() + ": " + repository.refusal())
                .collect(Collectors.joining(" "));
        throw new InvalidInputException(refused.size() + " of the selected repositories would be refused — " + first
                + (refused.size() > 3 ? " …" : "") + " Untick them or change what the preview names, then import again.");
    }

    private Applied write(Plan plan, TargetImports.Batch batch, RequestActor actor) {
        Source source = plan.source();
        Map<String, Long> solutionIds = new HashMap<>();
        Map<String, Long> projectIds = new HashMap<>();
        List<String> solutionsCreated = new ArrayList<>();
        List<String> projectsCreated = new ArrayList<>();
        for (ImportPlanner.PlannedSolution planned : plan.solutions()) {
            TargetImports.Placed<SolutionView> solution = batch.solution(planned.name());
            solutionIds.put(planned.name().toLowerCase(Locale.ROOT), solution.view().id());
            if (solution.created()) {
                solutionsCreated.add(solution.view().name());
            }
        }
        for (ImportPlanner.PlannedProject planned : plan.projects()) {
            long solutionId = solutionIds.get(planned.solution().toLowerCase(Locale.ROOT));
            TargetImports.Placed<ProjectView> project = batch.project(solutionId, planned.name());
            projectIds.put(key(planned.solution(), planned.name()), project.view().id());
            if (project.created()) {
                projectsCreated.add(planned.solution() + " / " + project.view().name());
            }
        }

        // An entry's description holds 255 characters: the URL first, as the form writes it, then where it came from.
        String origin = " — imported from connection " + BoundedText.clip(source.connection().getName(), 40)
                + ", discovery " + source.discoveryId();
        String importer = actor.username() == null ? "unknown" : BoundedText.clip(actor.username(), 255);
        List<ForgeImportedTarget> created = new ArrayList<>();
        for (ImportPlanner.Target target : plan.targets()) {
            Placement placement = target.placement();
            Long projectId = placement.filed() ? projectIds.get(key(placement.solution(), placement.project())) : null;
            String provenance = origin + ", forge id " + target.repository().getForgeId()
                    + (placement.filed() ? ", into project " + placement.solution() + " / " + placement.project() : "");
            RepositoryView repository = batch.repository(target.changes(), projectId, plan.at(), provenance);

            ForgeImportLinkEntity link = new ForgeImportLinkEntity();
            link.setRepositoryId(repository.id());
            link.setConnectionId(source.connectionId());
            link.setForgeId(target.repository().getForgeId());
            link.setDiscoveryId(source.discoveryId());
            link.setImportedAt(plan.at());
            link.setImportedBy(importer);
            links.save(link);

            Long scanId = null;
            if (target.firstScanNotBefore() != null) {
                TargetScans.Queued scan = batch.firstScan(repository, target.firstScanNotBefore());
                scanId = scan.id();
            }
            created.add(new ForgeImportedTarget(target.repository().getForgeId(), target.repository().getFullPath(),
                    repository.id(), repository.url(), placement.solution(), placement.project(), scanId,
                    target.firstScanNotBefore()));
        }
        // The link's unique keys are checked here, inside the transaction, rather than at a commit no catch sees.
        links.flush();
        return new Applied(plan, List.copyOf(created), List.copyOf(solutionsCreated), List.copyOf(projectsCreated));
    }

    /** The summary entry, after the commit; signalled when the import created something. */
    private void record(Applied applied, RequestActor actor) {
        Plan plan = applied.plan();
        Map<ImportSkip, Long> skipped = new EnumMap<>(ImportSkip.class);
        plan.skipped().forEach(repository -> skipped.merge(repository.reason(), 1L, Long::sum));
        // 255 characters: the counts first, which the SOC's event carries; the credentials as far as they fit.
        String description = "Forge import, connection " + BoundedText.clip(plan.source().connection().getName(), 40)
                + ", discovery " + plan.source().discoveryId() + ": " + applied.created().size() + " target(s) created, "
                + plan.skipped().size() + " skipped"
                + (skipped.isEmpty() ? "" : " (" + skipped.entrySet().stream()
                        .map(entry -> entry.getValue() + " " + entry.getKey().wireName())
                        .collect(Collectors.joining(", ")) + ")")
                + ", " + applied.solutions().size() + " solution(s) and " + applied.projects().size()
                + " project(s) created, first scans " + plan.spacing()
                        .map(gap -> applied.created().size() + " " + gap.toSeconds() + " s apart")
                        .orElse("none")
                + ", no grant; credentials " + (plan.credentials().isEmpty() ? "none" : plan.credentials().stream()
                        .map(host -> host.host() + " " + host.credential().kind())
                        .collect(Collectors.joining(", ")));
        AuditLogService.Record entry = actor.entry(AuditOperation.FORGE_IMPORT_APPLIED,
                plan.source().connectionId().toString(), description);
        audit.record(applied.created().isEmpty() ? entry : entry.signalling(SecurityEventType.FORGE_IMPORT_APPLIED));
    }

    private static ForgeImportResult result(Applied applied) {
        Plan plan = applied.plan();
        List<ForgeSkippedImport> skipped = plan.skipped();
        return new ForgeImportResult(plan.source().connectionId(), plan.source().discoveryId(), applied.created(),
                skipped, applied.solutions(), applied.projects(), ForgeSelectionService.firstScans(plan));
    }

    private static String key(String solution, String project) {
        return solution.toLowerCase(Locale.ROOT) + "\n" + project.toLowerCase(Locale.ROOT);
    }
}
