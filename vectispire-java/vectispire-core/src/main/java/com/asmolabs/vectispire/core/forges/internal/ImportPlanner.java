package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.forges.DiscoveredRepository;
import com.asmolabs.vectispire.common.domain.forges.DiscoveryState;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.common.domain.forges.ImportMapping;
import com.asmolabs.vectispire.common.domain.forges.ImportMapping.Placement;
import com.asmolabs.vectispire.common.domain.forges.ImportSkip;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.forges.ForgeDiscoveryConflict;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeCredentialChoice;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeCredentialView;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeHostCredential;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeImportRequest;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeRefusedImport;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeSkippedImport;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeImportLinkEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeImportLinkRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryRepository;
import com.asmolabs.vectispire.core.targets.GitTokenAdministrationService;
import com.asmolabs.vectispire.core.targets.RepositoryAdministrationService.Changes;
import com.asmolabs.vectispire.core.targets.SolutionAdministrationService.ProjectView;
import com.asmolabs.vectispire.core.targets.SolutionAdministrationService.SolutionView;
import com.asmolabs.vectispire.core.targets.SshKeyAdministrationService;
import com.asmolabs.vectispire.core.targets.TargetImports;
import com.asmolabs.vectispire.core.targets.TargetSchedules;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

/**
 * Reads a discovery's snapshot as the selection and the import see it, and plans an import (decision 0037 §4–5):
 * which repositories become targets, filed where, cloned how, scanned when — and which are skipped, and why.
 *
 * <p><b>One planner for the preview and the import.</b> The preview shows the plan and writes nothing; the import
 * plans again <em>inside its transaction</em> and applies that plan. The preview's verdict is advice (§4): between
 * the two, a target may have been typed by hand or another import may have run, and what the import reads in its
 * own transaction is what it acts on.
 *
 * <p><b>"Already present" is one rule</b>, the repository form's: {@link RepositoryUrl#identity} of the
 * repository's HTTPS <em>or</em> SSH clone URL equals that of an existing target's URL, whatever the target's
 * branch and sub-path ({@link TargetImports#presentByIdentity}). Once imported, the provenance link recognises a
 * repository by the forge's id, so a repository renamed on the forge is still the target it was.
 */
@Component
public class ImportPlanner {

    /** The most repositories one import creates, in one transaction (answer 8); a larger selection is several. */
    public static final int MAX_IMPORT = 1_000;

    /** The most forge ids a selection carries: a discovery's own bound. */
    public static final int MAX_SELECTION = 20_000;

    /** Between two first scans (answer 4). */
    public static final int DEFAULT_SPACING_SECONDS = 60;
    public static final int MIN_SPACING_SECONDS = 10;
    public static final int MAX_SPACING_SECONDS = 600;

    /** The width of {@code t_repository.name}: a full path longer than it leaves the name to the URL. */
    private static final int TARGET_NAME_LENGTH = 255;

    private static final Set<String> SELECTABLE_STATES =
            Set.of(DiscoveryState.COMPLETED.wireName(), DiscoveryState.PARTIAL.wireName());

    private final ForgeConnectionRepository connections;
    private final ForgeDiscoveryRepository discoveries;
    private final ForgeRepositoryRepository snapshot;
    private final ForgeImportLinkRepository links;
    private final TargetImports targets;
    private final GitTokenAdministrationService tokens;
    private final SshKeyAdministrationService keys;
    private final TargetSchedules schedules;
    private final ForgeIntegrations integrations;
    private final Clock clock;

    public ImportPlanner(
            ForgeConnectionRepository connections,
            ForgeDiscoveryRepository discoveries,
            ForgeRepositoryRepository snapshot,
            ForgeImportLinkRepository links,
            TargetImports targets,
            GitTokenAdministrationService tokens,
            SshKeyAdministrationService keys,
            TargetSchedules schedules,
            ForgeIntegrations integrations,
            Clock clock) {
        this.connections = connections;
        this.discoveries = discoveries;
        this.snapshot = snapshot;
        this.links = links;
        this.targets = targets;
        this.tokens = tokens;
        this.keys = keys;
        this.schedules = schedules;
        this.integrations = integrations;
        this.clock = clock;
    }

    // ------------------------------------------------------------------------------------------------- the source

    /** A discovery the selection may read, with its connection. */
    public record Source(ForgeConnectionEntity connection, ForgeDiscoveryEntity discovery, ForgeKind kind) {

        public UUID connectionId() {
            return connection.getId();
        }

        public long discoveryId() {
            return discovery.getId();
        }
    }

    /**
     * The discovery to select from: the connection's latest that ended with something to choose — completed, or
     * partial.
     *
     * <p><b>Partial, too.</b> A partial run stopped at a bound — thirty minutes, twenty thousand repositories, a
     * long rate limit — and what it listed it listed whole: every repository it kept is a repository the forge
     * holds. What a partial run proves nothing about is what it did not reach (§3), and nothing here infers
     * anything from that. A failed run is refused: it stopped on an error, and the screen should say so rather than
     * offer the pages it read before.
     *
     * <p><b>The latest only.</b> The snapshot is one per connection, rewritten by each run: an older run's listing
     * is no longer what the snapshot says, so selecting from it would offer what a newer run found gone. A run
     * still going does not supersede the last ended one.
     *
     * @throws NotFoundException the connection's, then the discovery's
     * @throws ForgeDiscoveryConflict {@code forge-discovery-not-selectable} with {@code state}; {@code
     *     forge-discovery-superseded} with {@code latestDiscoveryId}
     */
    public Source source(UUID connectionId, Long discoveryId) {
        ForgeConnectionEntity connection = connections.findById(connectionId)
                .orElseThrow(() -> new NotFoundException("Forge connection not found."));
        if (discoveryId == null) {
            throw new InvalidInputException("Name the discovery to import from: discoveryId.");
        }
        ForgeDiscoveryEntity discovery = discoveries.findByIdAndConnectionId(discoveryId, connectionId)
                .orElseThrow(() -> new NotFoundException("Forge discovery " + discoveryId + " not found."));
        if (!SELECTABLE_STATES.contains(discovery.getState())) {
            throw new ForgeDiscoveryConflict(ForgeDiscoveryConflict.Cause.NOT_SELECTABLE, "Discovery " + discoveryId
                    + " is " + discovery.getState() + ": repositories are selected from a discovery that completed, or "
                    + "ended partial.", Map.of("state", discovery.getState()));
        }
        ForgeDiscoveryEntity latest = discoveries
                .findFirstByConnectionIdAndStateInOrderByRequestedAtDescIdDesc(connectionId, SELECTABLE_STATES)
                .orElse(discovery);
        if (!latest.getId().equals(discovery.getId())) {
            throw new ForgeDiscoveryConflict(ForgeDiscoveryConflict.Cause.SUPERSEDED, "Discovery " + latest.getId()
                    + " has ended since discovery " + discoveryId + ": select from it.",
                    Map.of("latestDiscoveryId", latest.getId()));
        }
        return new Source(connection, discovery, ForgeKind.parse(connection.getKind()));
    }

    // ------------------------------------------------------------------------------------------------ the snapshot

    /**
     * One repository of the discovery, as the selection judges it.
     *
     * @param presentAs the targets filing it by identity, sorted
     * @param importedAs the target an earlier import from this connection made of it
     * @param notSelectable why it cannot be ticked; empty when it can
     * @param proposed where the forge's layout suggests filing it
     */
    public record Row(
            ForgeRepositoryEntity repository,
            List<Long> presentAs,
            Long importedAs,
            Optional<ImportSkip> notSelectable,
            Placement proposed) {}

    /** Every repository the discovery listed, by full path. */
    public List<Row> rows(Source source) {
        return rows(source, snapshot.listedBy(source.connectionId(), source.discoveryId()), links.findByConnectionId(
                source.connectionId()));
    }

    private List<Row> rows(Source source, List<ForgeRepositoryEntity> listed, List<ForgeImportLinkEntity> linked) {
        Map<String, Long> importedAs = new HashMap<>();
        linked.forEach(link -> importedAs.put(link.getForgeId(), link.getRepositoryId()));
        Set<String> identities = new HashSet<>();
        listed.forEach(row -> identitiesOf(row).forEach(identities::add));
        Map<String, List<Long>> present = targets.presentByIdentity(identities);

        return listed.stream()
                .sorted(Comparator.comparing((ForgeRepositoryEntity row) -> row.getFullPath().toLowerCase(Locale.ROOT))
                        .thenComparing(ForgeRepositoryEntity::getForgeId))
                .map(row -> {
                    List<Long> presentAs = identitiesOf(row).stream()
                            .flatMap(identity -> present.getOrDefault(identity, List.of()).stream())
                            .collect(Collectors.toCollection(TreeSet::new)).stream().toList();
                    Long imported = importedAs.get(row.getForgeId());
                    Optional<ImportSkip> skip = imported != null ? Optional.of(ImportSkip.ALREADY_IMPORTED)
                            : !presentAs.isEmpty() ? Optional.of(ImportSkip.ALREADY_PRESENT)
                            : row.getDefaultBranch() == null ? Optional.of(ImportSkip.NO_DEFAULT_BRANCH)
                            : row.getHttpUrl() == null && row.getSshUrl() == null ? Optional.of(ImportSkip.NO_CLONE_URL)
                            : Optional.empty();
                    return new Row(row, presentAs, imported, skip, ImportMapping.proposed(
                            source.kind(), row.getNamespacePath(), row.getName(), row.getPersonal()));
                })
                .toList();
    }

    /** The identities of the forge's two clone URLs — matched through both, the SSH host may differ (§4). */
    private static List<String> identitiesOf(ForgeRepositoryEntity row) {
        List<String> identities = new ArrayList<>(2);
        RepositoryUrl.identity(row.getHttpUrl()).ifPresent(identities::add);
        RepositoryUrl.identity(row.getSshUrl()).filter(identity -> !identities.contains(identity))
                .ifPresent(identities::add);
        return identities;
    }

    // ---------------------------------------------------------------------------------------------------- the plan

    /**
     * One target the import creates.
     *
     * @param changes what the repository form is given for it
     * @param placement where it is filed
     * @param firstScanNotBefore when its first scan may start; null without one
     */
    public record Target(
            ForgeRepositoryEntity repository,
            Changes changes,
            ForgeCredentialView credential,
            Placement placement,
            Instant firstScanNotBefore,
            String warning) {}

    /** A solution the plan files into: reused when {@code existing} is present. */
    public record PlannedSolution(String name, Optional<SolutionView> existing) {}

    /** A project the plan files into: reused when {@code existing} is present, with how far its grants reach. */
    public record PlannedProject(
            String solution, String name, Optional<ProjectView> existing, TargetImports.ProjectReach reach, int targets) {}

    /**
     * What an import would do.
     *
     * @param spacing between two first scans; empty when none is asked for
     */
    public record Plan(
            Source source,
            Instant at,
            List<Target> targets,
            List<ForgeSkippedImport> skipped,
            List<ForgeRefusedImport> refused,
            List<PlannedSolution> solutions,
            List<PlannedProject> projects,
            List<ForgeHostCredential> credentials,
            Optional<Duration> spacing,
            Duration defaultInterval,
            VisibilityMode visibilityMode) {

        /**
         * What the plan creates, as a set a second reading compares: the repositories, and the solutions and
         * projects it would create. Two plans of one request creating the same are the same plan; a plan read after
         * a failed import that creates less is the trace of whatever got there first.
         */
        public Set<String> creations() {
            Set<String> creations = new TreeSet<>();
            targets.forEach(target -> creations.add("repository " + target.repository().getForgeId()));
            solutions.stream().filter(solution -> solution.existing().isEmpty())
                    .forEach(solution -> creations.add("solution " + solution.name().toLowerCase(Locale.ROOT)));
            projects.stream().filter(project -> project.existing().isEmpty()).forEach(project -> creations.add(
                    "project " + project.solution().toLowerCase(Locale.ROOT) + " / " + project.name().toLowerCase(Locale.ROOT)));
            return creations;
        }

        /** Who will see a target filed there, in words (§4): the preview's answer to "who will see the new targets". */
        public String visibleTo(Placement placement) {
            if (visibilityMode == VisibilityMode.EVERYONE) {
                return "every signed-in account: visibility is not restricted on this installation";
            }
            String base = "administrators and the roles that see the whole estate";
            if (!placement.filed()) {
                return base + " — it is filed into no project";
            }
            PlannedProject project = projects.stream()
                    .filter(planned -> planned.solution().equalsIgnoreCase(placement.solution())
                            && planned.name().equalsIgnoreCase(placement.project()))
                    .findFirst().orElseThrow();
            String name = project.solution() + " / " + project.name();
            if (project.existing().isEmpty()) {
                return base + " only — project " + name + " is new and nobody holds a grant on it yet";
            }
            TargetImports.ProjectReach reach = project.reach();
            if (reach.accounts() == 0 && reach.teams() == 0) {
                return base + " only — nobody holds a grant on project " + name;
            }
            return base + ", and the " + reach.accounts() + " account(s) and " + reach.teams()
                    + " team(s) granted project " + name;
        }
    }

    /**
     * Plans the import the request asks for, from the source's snapshot as it reads now.
     *
     * @throws InvalidInputException a request out of its bounds or naming what does not exist — refused whole, in
     *     words; a repository the import could not create is not refused here but listed, {@code refused}, so that
     *     the preview can show it against its row
     * @throws com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException the connection is
     *     suspended, its forge's integration disabled. Here rather than at the routes: every preview, every import
     *     and every import's replanning after a lost race plans, and none of them calls the forge — the import acts
     *     on what a discovery said, so the forge's switch is asked where that is read (decision 0040 §1). The
     *     selection's own reads and ticks stay open: they change nothing outside the connection's snapshot.
     */
    public Plan plan(Source source, ForgeImportRequest request) {
        integrations.requireEnabled(source.kind());
        if (request == null) {
            throw new InvalidInputException("Describe the import: the discovery, the repositories and their credentials.");
        }
        Set<String> wanted = forgeIds(request.forgeIds(), MAX_IMPORT, "An import");
        if (wanted.isEmpty()) {
            throw new InvalidInputException("Select at least one repository to import.");
        }
        ImportMapping mapping = ImportMapping.of(request.mapping() == null ? null
                : request.mapping().stream().map(rule -> rule == null ? null : rule.rule()).toList());
        Optional<Duration> spacing = spacing(request.firstScan(), request.spacingSeconds());
        Map<String, Choice> choices = choices(request.credentials());

        List<ForgeRepositoryEntity> listed = snapshot.listedBy(source.connectionId(), source.discoveryId()).stream()
                .filter(row -> wanted.contains(row.getForgeId()))
                .toList();
        if (listed.size() < wanted.size()) {
            Set<String> found = listed.stream().map(ForgeRepositoryEntity::getForgeId).collect(Collectors.toSet());
            List<String> missing = wanted.stream().filter(id -> !found.contains(id)).limit(5).toList();
            throw new InvalidInputException((wanted.size() - listed.size()) + " of the selected repositories are not "
                    + "listed by discovery " + source.discoveryId() + ": " + String.join(", ", missing)
                    + (wanted.size() - listed.size() > missing.size() ? ", …" : "") + ".");
        }
        List<Row> rows = rows(source, listed, links.findByConnectionIdAndForgeIdIn(source.connectionId(), wanted));

        Instant at = clock.instant();
        List<Target> planned = new ArrayList<>();
        List<ForgeSkippedImport> skipped = new ArrayList<>();
        List<ForgeRefusedImport> refused = new ArrayList<>();
        Map<String, HostUse> hosts = new LinkedHashMap<>();
        Set<String> identities = new HashSet<>();
        Map<String, List<TokenOption>> tokensByHost = tokensByHost();
        Map<UUID, String> keyNames = keys.list().stream()
                .collect(Collectors.toMap(SshKeyAdministrationService.KeyView::id, SshKeyAdministrationService.KeyView::name));

        for (Row row : rows) {
            ForgeRepositoryEntity repository = row.repository();
            if (row.notSelectable().isPresent()) {
                skipped.add(new ForgeSkippedImport(repository.getForgeId(), repository.getFullPath(),
                        row.notSelectable().get(), row.importedAs() != null ? List.of(row.importedAs()) : row.presentAs()));
                continue;
            }
            List<String> own = identitiesOf(repository);
            if (own.stream().anyMatch(identities::contains)) {
                skipped.add(new ForgeSkippedImport(repository.getForgeId(), repository.getFullPath(),
                        ImportSkip.DUPLICATE_IN_SELECTION, List.of()));
                continue;
            }
            identities.addAll(own);

            String host = hostOf(repository);
            Choice choice = Optional.ofNullable(choices.get(host)).orElseGet(() -> proposal(host, tokensByHost));
            String url = choice.sshKeyId() != null ? repository.getSshUrl() : repository.getHttpUrl();
            if (url == null) {
                skipped.add(new ForgeSkippedImport(repository.getForgeId(), repository.getFullPath(),
                        ImportSkip.NO_CLONE_URL, List.of()));
                continue;
            }
            ForgeCredentialView credential = credentialView(choice, keyNames, tokensByHost);
            hosts.computeIfAbsent(host, ignored -> new HostUse(choice, credential)).count++;

            ImportMapping.Outcome placed = mapping.place(source.kind(), repository.getForgeId(),
                    repository.getNamespacePath(), repository.getName(), repository.getPersonal());
            Changes changes = new Changes(url, repository.getDefaultBranch(),
                    repository.getFullPath().length() <= TARGET_NAME_LENGTH ? repository.getFullPath() : null,
                    null, null, null, request.requiredAgentLabel(),
                    choice.sshKeyId() == null ? null : choice.sshKeyId().toString(), null,
                    choice.httpsTokenId() == null ? null : choice.httpsTokenId().toString(), null);
            Optional<String> refusal = placed.refusal().or(() -> targets.refusal(changes));
            if (refusal.isPresent()) {
                refused.add(new ForgeRefusedImport(repository.getForgeId(), repository.getFullPath(), refusal.get()));
                continue;
            }
            planned.add(new Target(repository, changes, credential, placed.placement(), null,
                    warning(repository, choice)));
        }

        List<PlannedSolution> solutions = new ArrayList<>();
        List<PlannedProject> projects = new ArrayList<>();
        place(planned, solutions, projects);

        // The k-th new target's first scan waits k spacings: three hundred at sixty seconds are five hours of clones
        // reaching the forge one by one, rather than one burst that a forge's abuse detection answers.
        List<Target> scheduled = new ArrayList<>(planned.size());
        for (Target target : planned) {
            long k = scheduled.size();
            Instant notBefore = spacing.map(gap -> at.plus(gap.multipliedBy(k))).orElse(null);
            scheduled.add(new Target(target.repository(), target.changes(), target.credential(), target.placement(),
                    notBefore, target.warning()));
        }

        List<ForgeHostCredential> credentials = hosts.entrySet().stream()
                .map(entry -> new ForgeHostCredential(entry.getKey(), entry.getValue().credential,
                        entry.getValue().choice.proposed(), entry.getValue().count))
                .toList();
        return new Plan(source, at, List.copyOf(scheduled), List.copyOf(skipped), List.copyOf(refused),
                List.copyOf(solutions), List.copyOf(projects), credentials, spacing, schedules.defaultInterval(),
                targets.visibilityMode());
    }

    /**
     * The solutions and projects the targets are filed into, each once, compared as {@code SolutionAdministrationService}
     * compares names — case aside — and each found existing or not.
     */
    private void place(List<Target> planned, List<PlannedSolution> solutions, List<PlannedProject> projects) {
        Map<String, PlannedSolution> bySolution = new LinkedHashMap<>();
        Map<String, String[]> byProject = new LinkedHashMap<>();
        Map<String, Integer> counts = new HashMap<>();
        for (Target target : planned) {
            Placement placement = target.placement();
            if (!placement.filed()) {
                continue;
            }
            String solutionKey = placement.solution().toLowerCase(Locale.ROOT);
            PlannedSolution solution = bySolution.computeIfAbsent(solutionKey, ignored -> {
                Optional<SolutionView> existing = targets.solutionNamed(placement.solution());
                return new PlannedSolution(existing.map(SolutionView::name).orElse(placement.solution()), existing);
            });
            String projectKey = solutionKey + "\n" + placement.project().toLowerCase(Locale.ROOT);
            byProject.putIfAbsent(projectKey, new String[] {solution.name(), placement.project()});
            counts.merge(projectKey, 1, Integer::sum);
        }
        solutions.addAll(bySolution.values());

        Map<String, Optional<ProjectView>> existingProjects = new LinkedHashMap<>();
        for (Map.Entry<String, String[]> entry : byProject.entrySet()) {
            PlannedSolution solution = bySolution.get(entry.getKey().substring(0, entry.getKey().indexOf('\n')));
            existingProjects.put(entry.getKey(), solution.existing()
                    .flatMap(existing -> targets.projectNamed(existing.id(), entry.getValue()[1])));
        }
        Map<Long, TargetImports.ProjectReach> reach = targets.grantees(existingProjects.values().stream()
                .flatMap(Optional::stream).map(ProjectView::id).toList());
        for (Map.Entry<String, String[]> entry : byProject.entrySet()) {
            Optional<ProjectView> existing = existingProjects.get(entry.getKey());
            projects.add(new PlannedProject(entry.getValue()[0],
                    existing.map(ProjectView::name).orElse(entry.getValue()[1]), existing,
                    existing.map(project -> reach.getOrDefault(project.id(), new TargetImports.ProjectReach(0, 0)))
                            .orElse(new TargetImports.ProjectReach(0, 0)),
                    counts.get(entry.getKey())));
        }
    }

    /**
     * The forge ids of a request: distinct, in the order given, at most {@code max}.
     *
     * @param what the gesture, for the refusal
     */
    public static Set<String> forgeIds(Collection<String> raw, int max, String what) {
        Set<String> ids = new LinkedHashSet<>();
        if (raw == null) {
            return ids;
        }
        for (String id : raw) {
            if (id == null || id.isBlank()) {
                throw new InvalidInputException("A forge id is empty.");
            }
            ids.add(BoundedText.within(id.trim(), DiscoveredRepository.FORGE_ID_LENGTH, "A forge id"));
        }
        if (ids.size() > max) {
            throw new InvalidInputException(what + " takes at most " + String.format(Locale.ROOT, "%,d", max)
                    + " repositories; this one names " + String.format(Locale.ROOT, "%,d", ids.size())
                    + ". Import a larger selection in several parts.");
        }
        return ids;
    }

    private static Optional<Duration> spacing(Boolean firstScan, Integer spacingSeconds) {
        if (spacingSeconds != null && (spacingSeconds < MIN_SPACING_SECONDS || spacingSeconds > MAX_SPACING_SECONDS)) {
            throw new InvalidInputException("The spacing between first scans is between " + MIN_SPACING_SECONDS
                    + " seconds and " + MAX_SPACING_SECONDS / 60 + " minutes.");
        }
        if (!Boolean.TRUE.equals(firstScan)) {
            return Optional.empty();
        }
        return Optional.of(Duration.ofSeconds(spacingSeconds == null ? DEFAULT_SPACING_SECONDS : spacingSeconds));
    }

    // --------------------------------------------------------------------------------------------- the credentials

    /** A credential for one host: at most one of the two, and whether the proposal chose it. */
    private record Choice(UUID sshKeyId, UUID httpsTokenId, boolean proposed) {}

    private record TokenOption(UUID id, String name) {}

    private static final class HostUse {
        private final Choice choice;
        private final ForgeCredentialView credential;
        private int count;

        private HostUse(Choice choice, ForgeCredentialView credential) {
            this.choice = choice;
            this.credential = credential;
        }
    }

    private Map<String, List<TokenOption>> tokensByHost() {
        Map<String, List<TokenOption>> byHost = new HashMap<>();
        for (GitTokenAdministrationService.TokenView token : tokens.list()) {
            byHost.computeIfAbsent(token.host().toLowerCase(Locale.ROOT), ignored -> new ArrayList<>())
                    .add(new TokenOption(token.id(), token.name()));
        }
        return byHost;
    }

    /**
     * The credentials the request chose, by host: each host once, at most one credential each, and a token only
     * for the host it is bound to (decision 0022) — refused here in the request's words rather than once per
     * repository by the form.
     */
    private Map<String, Choice> choices(List<ForgeCredentialChoice> raw) {
        Map<String, Choice> choices = new HashMap<>();
        if (raw == null) {
            return choices;
        }
        Map<String, List<TokenOption>> tokensByHost = null;
        Set<UUID> keyIds = null;
        for (ForgeCredentialChoice choice : raw) {
            if (choice == null) {
                throw new InvalidInputException("A credential choice is empty.");
            }
            String host = RepositoryUrl.normalizeHost(choice.host());
            if (choices.containsKey(host)) {
                throw new InvalidInputException("Two credentials are chosen for " + host + ": choose one.");
            }
            UUID key = uuid(choice.sshKeyId(), "SSH key");
            UUID token = uuid(choice.httpsTokenId(), "HTTPS token");
            if (key != null && token != null) {
                throw new InvalidInputException("The repositories of " + host + " are cloned with an SSH key or an "
                        + "HTTPS token, not both.");
            }
            if (key != null) {
                if (keyIds == null) {
                    keyIds = keys.list().stream().map(SshKeyAdministrationService.KeyView::id).collect(Collectors.toSet());
                }
                if (!keyIds.contains(key)) {
                    throw new InvalidInputException("No SSH key with id " + key + ".");
                }
            }
            if (token != null) {
                if (tokensByHost == null) {
                    tokensByHost = tokensByHost();
                }
                boolean bound = tokensByHost.getOrDefault(host, List.of()).stream().anyMatch(t -> t.id().equals(token));
                if (!bound) {
                    boolean exists = tokensByHost.values().stream().flatMap(List::stream).anyMatch(t -> t.id().equals(token));
                    throw new InvalidInputException(exists
                            ? "This HTTPS token is issued for another host and would be sent to no other: the "
                                    + "repositories of " + host + " need a token bound to " + host + "."
                            : "No HTTPS token with id " + token + ".");
                }
            }
            choices.put(host, new Choice(key, token, false));
        }
        return choices;
    }

    /** The one HTTPS token bound to the host when there is exactly one (§5); none otherwise. */
    private static Choice proposal(String host, Map<String, List<TokenOption>> tokensByHost) {
        List<TokenOption> bound = tokensByHost.getOrDefault(host, List.of());
        return bound.size() == 1 ? new Choice(null, bound.getFirst().id(), true) : new Choice(null, null, true);
    }

    private static ForgeCredentialView credentialView(
            Choice choice, Map<UUID, String> keyNames, Map<String, List<TokenOption>> tokensByHost) {
        if (choice.sshKeyId() != null) {
            return new ForgeCredentialView("ssh_key", choice.sshKeyId(), keyNames.get(choice.sshKeyId()));
        }
        if (choice.httpsTokenId() != null) {
            String name = tokensByHost.values().stream().flatMap(List::stream)
                    .filter(token -> token.id().equals(choice.httpsTokenId())).map(TokenOption::name)
                    .findFirst().orElse(null);
            return new ForgeCredentialView("https_token", choice.httpsTokenId(), name);
        }
        return new ForgeCredentialView("none", null, null);
    }

    /**
     * The host the repository is cloned from, as a token is bound to it: its HTTPS clone URL's, or its SSH URL's
     * when the forge gave no HTTPS one.
     */
    private static String hostOf(ForgeRepositoryEntity repository) {
        return RepositoryUrl.host(repository.getHttpUrl())
                .or(() -> RepositoryUrl.host(repository.getSshUrl()))
                .map(host -> {
                    String lower = host.toLowerCase(Locale.ROOT);
                    while (lower.endsWith(".")) {
                        lower = lower.substring(0, lower.length() - 1);
                    }
                    return lower;
                })
                .orElse("");
    }

    /** A private repository imported with no credential fails its first scan, visibly (§5): said first. */
    private static String warning(ForgeRepositoryEntity repository, Choice choice) {
        if (choice.sshKeyId() != null || choice.httpsTokenId() != null) {
            return null;
        }
        String visibility = repository.getVisibility();
        if ("public".equalsIgnoreCase(visibility)) {
            return null;
        }
        return (visibility == null ? "The forge did not say whether this repository is public"
                : "This repository is " + visibility)
                + " and is imported with no clone credential: its scans will fail with \"requires authentication\" "
                + "unless it can be cloned anonymously.";
    }

    private static UUID uuid(String value, String what) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(value.trim());
        } catch (IllegalArgumentException malformed) {
            throw new InvalidInputException("\"" + BoundedText.clip(value.trim(), 60) + "\" is not a valid " + what
                    + " identifier.");
        }
    }

    /** Whether two readings of one request create the same — after a failed import, whether anything raced it. */
    public static boolean sameCreations(Plan first, Plan second) {
        return Objects.equals(first.creations(), second.creations());
    }
}
