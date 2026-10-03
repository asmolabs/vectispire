package com.asmolabs.vectispire.core.targets;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibleScope;
import com.asmolabs.vectispire.common.domain.errors.NotFoundException;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.ProjectEntity;
import com.asmolabs.vectispire.core.targets.persistence.ProjectRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The solutions tree as one reader may see it, with each project's open backlog (decision 0023).
 *
 * <h2>What a reader is shown</h2>
 *
 * <ul>
 *   <li><b>A project appears</b> when the reader holds a grant on it, or sees at least one of its
 *       repositories or images. With only the targets they may see — and {@code partial} set when
 *       the project holds others: a partial grant sees a partial project, and says so, because a
 *       figure that silently covers half a project reads as the whole of it.
 *   <li><b>A solution appears</b> when one of its projects does, and is {@code partial} when any
 *       repository or image filed under it is hidden from the reader.
 *   <li><b>"No project" is a group of its own</b>, never omitted: every repository and every image
 *       an administrator has not filed yet is listed there, so filing is visibly unfinished rather
 *       than invisibly so.
 *   <li>A reader whose visibility is everything — an administrator, a global role, or anyone
 *       while the deployment is open — sees every solution and project, empty ones included.
 * </ul>
 *
 * <p><b>The figures leave settled triage out</b>, like every figure of risk: a backlog whose team
 * argued each finding not affected is not a backlog. They are counted over the visible member
 * repositories and images only, in one grouped query for the whole tree — an image's findings are
 * part of its project's backlog since images can be filed (amendment of 2026-09-30 to decision 0023).
 */
@Service
public class SolutionQueryService {

    private final SolutionRepository solutions;
    private final ProjectRepository projects;
    private final GitRepositoryRepository repositories;
    private final ContainerRepository containers;
    private final TargetBacklog backlog;
    private final TargetScans scans;

    public SolutionQueryService(
            SolutionRepository solutions,
            ProjectRepository projects,
            GitRepositoryRepository repositories,
            ContainerRepository containers,
            TargetBacklog backlog,
            TargetScans scans) {
        this.solutions = solutions;
        this.projects = projects;
        this.repositories = repositories;
        this.containers = containers;
        this.backlog = backlog;
        this.scans = scans;
    }

    /**
     * Unresolved issues by severity, settled triage left out.
     *
     * @param total the sum of the six, so a screen does not add them itself and disagree
     */
    public record OpenIssues(long critical, long high, long medium, long low, long negligible, long unknown, long total) {

        static final OpenIssues NONE = new OpenIssues(0, 0, 0, 0, 0, 0, 0);

        static OpenIssues of(Map<Severity, Long> counts) {
            long critical = counts.getOrDefault(Severity.CRITICAL, 0L);
            long high = counts.getOrDefault(Severity.HIGH, 0L);
            long medium = counts.getOrDefault(Severity.MEDIUM, 0L);
            long low = counts.getOrDefault(Severity.LOW, 0L);
            long negligible = counts.getOrDefault(Severity.NEGLIGIBLE, 0L);
            long unknown = counts.getOrDefault(Severity.UNKNOWN, 0L);
            return new OpenIssues(critical, high, medium, low, negligible, unknown,
                    critical + high + medium + low + negligible + unknown);
        }
    }

    /** A repository as the tree lists it; the inventory holds the rest. */
    public record RepositoryRef(Long id, String name) {}

    /** A container image as the tree lists it, {@code registry/name:tag}; the inventory holds the rest. */
    public record ContainerRef(Long id, String name) {}

    /**
     * @param partial the project holds repositories or images this reader does not see; its figures
     *     and its lists cover only those they do
     * @param checklistsVisible the project's checklists are open to this reader — exactly the verdict of
     *     their whole-project guard ({@code RowVisibility.seesWholeProject}): true when the reader sees
     *     everything, or holds the project granted as such, or sees every one of its repositories and it
     *     has at least one. Images play no part, so a project whose only hidden target is an image is
     *     {@code partial} and still {@code checklistsVisible}; a project with no repository is
     *     {@code checklistsVisible} only to a reader who sees everything or holds its grant, since "every
     *     one of none" would open an empty project to anybody
     * @param repositoryCount the repositories listed, which are the visible ones
     * @param openIssues over the listed repositories <b>and</b> the listed images
     * @param detectedLanguages the union of the languages the listed repositories' newest completed
     *     scans found, sorted — in the vocabulary a plugin manifest declares, so the plugin screen puts
     *     the two side by side. Over the visible repositories only, like every figure of the node
     * @param languagesUnknownFor the listed repositories whose languages are unknown — no completed
     *     scan, or a newest one that recorded no whole census — by id. The union says nothing of them:
     *     a project reading "Java" with a repository here may be Java and Go, and a screen says so
     *     rather than presenting the union as the whole project (decision 0007). Repositories only: an
     *     image carries no language census, and is neither in the union nor among the unknown
     * @param containerCount the images listed, which are the visible ones
     * @param containers the images filed in the project that this reader sees
     */
    public record ProjectNode(
            Long id,
            Long solutionId,
            String name,
            String description,
            Instant createdAt,
            boolean partial,
            boolean checklistsVisible,
            int repositoryCount,
            OpenIssues openIssues,
            List<RepositoryRef> repositories,
            List<Language> detectedLanguages,
            List<Long> languagesUnknownFor,
            int containerCount,
            List<ContainerRef> containers) {}

    /**
     * @param partial a repository or an image filed under this solution is hidden from this reader
     * @param containerCount the images its shown projects list
     */
    public record SolutionNode(
            Long id,
            String name,
            String description,
            Instant createdAt,
            boolean partial,
            int repositoryCount,
            OpenIssues openIssues,
            List<ProjectNode> projects,
            int containerCount) {}

    /** The repositories and images in no project that this reader may see, with their figures. */
    public record Unfiled(
            int repositoryCount,
            OpenIssues openIssues,
            List<RepositoryRef> repositories,
            int containerCount,
            List<ContainerRef> containers) {}

    public record SolutionTree(List<SolutionNode> solutions, Unfiled unfiled) {}

    /** The solution a project read on its own is in, named. */
    public record SolutionRef(Long id, String name) {}

    /**
     * A project read on its own ({@code GET /api/v1/projects/{id}}) — what its node in the tree says,
     * field for field, with its solution named beside it, for a screen or a reporting plugin that asks
     * about one project and should not read the whole tree to find it.
     *
     * <p>Every field means what the {@link ProjectNode} field of the same name means, and is computed by
     * the same code over the same targets: a figure read here and in the tree cannot disagree.
     *
     * @param solution the solution the project is in; {@code solutionId} repeats its identifier, so a
     *     screen holding a node's type can hold this one
     */
    public record ProjectDetail(
            Long id,
            Long solutionId,
            SolutionRef solution,
            String name,
            String description,
            Instant createdAt,
            boolean partial,
            boolean checklistsVisible,
            int repositoryCount,
            OpenIssues openIssues,
            List<RepositoryRef> repositories,
            List<Language> detectedLanguages,
            List<Long> languagesUnknownFor,
            int containerCount,
            List<ContainerRef> containers) {

        static ProjectDetail of(ProjectNode node, SolutionRef solution) {
            return new ProjectDetail(node.id(), node.solutionId(), solution, node.name(), node.description(),
                    node.createdAt(), node.partial(), node.checklistsVisible(), node.repositoryCount(), node.openIssues(),
                    node.repositories(), node.detectedLanguages(), node.languagesUnknownFor(), node.containerCount(),
                    node.containers());
        }
    }

    /**
     * A project and the targets filed in it now — what a module that answers for a whole project
     * needs to decide whether its caller sees all of it ({@code RowVisibility.requireWhollyVisibleProject}),
     * and what the backlog narrows a project to.
     *
     * @param repositoryIds every repository filed in the project at the moment of asking, visible or not:
     *     the guard compares them with the caller's visibility, and a list narrowed first would let a
     *     partial reader pass for a whole one
     * @param containerIds every image filed in the project at the moment of asking, visible or not. The
     *     checklists read {@code repositoryIds} alone: their measurements and their guard speak for the
     *     project's repositories, and images entering them is an open point of the amendment of
     *     2026-09-30, not something a new component decides in passing
     */
    public record ProjectMembers(long projectId, String name, List<Long> repositoryIds, List<Long> containerIds) {

        public ProjectMembers {
            repositoryIds = List.copyOf(repositoryIds);
            containerIds = List.copyOf(containerIds);
        }

        /** Every target filed in the project, repositories then images. */
        public List<ScanTarget> targets() {
            return Stream.concat(
                            repositoryIds.stream().<ScanTarget>map(ScanTarget.Repository::new),
                            containerIds.stream().<ScanTarget>map(ScanTarget.Container::new))
                    .toList();
        }
    }

    /** The project and its targets, or empty when there is no such project. */
    @Transactional(readOnly = true)
    public Optional<ProjectMembers> members(long projectId) {
        return projects.findById(projectId).map(project -> new ProjectMembers(project.getId(), project.getName(),
                repositories.findIdsByProjectIdIn(List.of(project.getId())),
                containers.findIdsByProjectIdIn(List.of(project.getId()))));
    }

    /**
     * The project a repository is filed in now, if any — a repository is in one project at most. Asked by
     * a module that reacts to new evidence about a repository on behalf of its project (the checklists'
     * automatic answers), with no caller to judge: whoever serves the result applies its own guard.
     */
    @Transactional(readOnly = true)
    public Optional<Long> projectOf(long repositoryId) {
        return repositories.findById(repositoryId).map(RepositoryEntity::getProjectId);
    }

    /**
     * The repositories and images filed in this solution's projects now, visible or not — empty when
     * there is no such solution, or it holds none. The backlog narrows by them and applies its reader's
     * visibility beside them, so the list carries no more than a lookup of the tree would.
     */
    @Transactional(readOnly = true)
    public List<ScanTarget> targetsOfSolution(long solutionId) {
        return Stream.concat(
                        repositories.findIdsBySolutionId(solutionId).stream().<ScanTarget>map(ScanTarget.Repository::new),
                        containers.findIdsBySolutionId(solutionId).stream().<ScanTarget>map(ScanTarget.Container::new))
                .toList();
    }

    /**
     * The project as far as the caller sees it, or "Project not found." for a project that does not exist
     * and one the caller sees nothing of, alike — the scope a module's aggregate over one project is
     * computed on (its compliance, its consolidated inventory). The rule is the tree's, and it is {@code
     * RowVisibility}'s: a grant on the project, or one of its targets visible, or everything.
     */
    @Transactional(readOnly = true)
    public VisibleScope visibleProject(long projectId, VisibilityService.Allowance allowance) {
        Optional<ProjectMembers> members = members(projectId);
        return RowVisibility.requireVisibleProject(projectId, members.map(ProjectMembers::name),
                members.map(ProjectMembers::targets).orElse(List.of()), allowance);
    }

    /**
     * The solution as far as the caller sees it, or "Solution not found." — absent and wholly hidden
     * alike; the tree shows a solution exactly when it shows one of its projects.
     */
    @Transactional(readOnly = true)
    public VisibleScope visibleSolution(long solutionId, VisibilityService.Allowance allowance) {
        Optional<SolutionEntity> solution = solutions.findById(solutionId);
        List<Long> projectIds = solution
                .map(found -> projects.findBySolutionId(found.getId()).stream().map(ProjectEntity::getId).toList())
                .orElse(List.of());
        return RowVisibility.requireVisibleSolution(solutionId, solution.map(SolutionEntity::getName), projectIds,
                solution.map(found -> targetsOfSolution(found.getId())).orElse(List.of()), allowance);
    }

    /**
     * Every project, then every solution, as far as the caller sees each — the scopes the tree would
     * list, each exactly as {@link #visibleProject} and {@link #visibleSolution} would answer it, for a
     * reader that walks all of them (the score simulation) rather than asking about one.
     *
     * <p><b>The guard's rule, not a copy of it.</b> Each scope goes through {@code RowVisibility}, and
     * one it refuses is left out: a second test of "may this caller see this project" written here
     * could come to list a project the tree hides. Four reads for the whole estate rather than three
     * per scope.
     */
    @Transactional(readOnly = true)
    public List<VisibleScope> visibleScopes(VisibilityService.Allowance allowance) {
        Map<Long, List<ScanTarget>> filedByProject = new HashMap<>();
        repositories.findAll().stream()
                .filter(repository -> repository.getProjectId() != null)
                .forEach(repository -> filedByProject.computeIfAbsent(repository.getProjectId(), id -> new ArrayList<>())
                        .add(new ScanTarget.Repository(repository.getId())));
        containers.findAll().stream()
                .filter(container -> container.getProjectId() != null)
                .forEach(container -> filedByProject.computeIfAbsent(container.getProjectId(), id -> new ArrayList<>())
                        .add(new ScanTarget.Container(container.getId())));

        List<ProjectEntity> allProjects = projects.findAll().stream()
                .sorted(Comparator.comparing(ProjectEntity::getId))
                .toList();
        List<VisibleScope> scopes = new ArrayList<>();
        Map<Long, List<Long>> projectsBySolution = new HashMap<>();
        for (ProjectEntity project : allProjects) {
            projectsBySolution.computeIfAbsent(project.getSolutionId(), id -> new ArrayList<>()).add(project.getId());
            try {
                scopes.add(RowVisibility.requireVisibleProject(project.getId(), Optional.of(project.getName()),
                        filedByProject.getOrDefault(project.getId(), List.of()), allowance));
            } catch (NotFoundException hidden) {
                // Not this caller's: the tree does not list it either.
            }
        }
        for (SolutionEntity solution : solutions.findAll().stream().sorted(Comparator.comparing(SolutionEntity::getId)).toList()) {
            List<Long> projectIds = projectsBySolution.getOrDefault(solution.getId(), List.of());
            List<ScanTarget> filed = projectIds.stream()
                    .flatMap(projectId -> filedByProject.getOrDefault(projectId, List.of()).stream())
                    .toList();
            try {
                scopes.add(RowVisibility.requireVisibleSolution(
                        solution.getId(), Optional.of(solution.getName()), projectIds, filed, allowance));
            } catch (NotFoundException hidden) {
                // As above.
            }
        }
        return scopes;
    }

    /**
     * One project as its node in the tree describes it, or "Project not found." when the tree would not
     * list it for this caller — the same visibility rule ({@link #visibleProject}), the same figures,
     * computed over the project's targets only rather than over the estate's.
     */
    @Transactional(readOnly = true)
    public ProjectDetail project(long projectId, VisibilityService.Allowance allowance) {
        Optional<ProjectEntity> project = projects.findById(projectId);
        List<RepositoryEntity> filedRepositories =
                project.map(found -> repositories.findByProjectId(found.getId())).orElse(List.of());
        List<ContainerEntity> filedContainers =
                project.map(found -> containers.findByProjectId(found.getId())).orElse(List.of());
        VisibleScope scope = RowVisibility.requireVisibleProject(
                projectId,
                project.map(ProjectEntity::getName),
                Stream.concat(
                                filedRepositories.stream().<ScanTarget>map(repository -> new ScanTarget.Repository(repository.getId())),
                                filedContainers.stream().<ScanTarget>map(container -> new ScanTarget.Container(container.getId())))
                        .toList(),
                allowance);
        ProjectEntity found = project.orElseThrow();

        Set<ScanTarget> seen = Set.copyOf(scope.targets());
        List<RepositoryEntity> visible = filedRepositories.stream()
                .filter(repository -> seen.contains(new ScanTarget.Repository(repository.getId())))
                .toList();
        List<ContainerEntity> visibleContainers = filedContainers.stream()
                .filter(container -> seen.contains(new ScanTarget.Container(container.getId())))
                .toList();
        // Narrowed to the project's visible targets, written into the statement as the tree's are: the
        // backlog is asked about this project alone, never about the estate and then filtered.
        Map<ScanTarget, Map<Severity, Long>> open =
                seen.isEmpty() ? Map.of() : backlog.openBySeverityPerTarget(scope.visibility());
        Map<Long, Set<Language>> languages =
                scans.detectedLanguages(visible.stream().map(RepositoryEntity::getId).toList());
        ProjectNode node = projectNode(
                found,
                visible,
                visibleContainers,
                filedRepositories.size() + filedContainers.size(),
                RowVisibility.seesWholeProject(
                        projectId, filedRepositories.stream().map(RepositoryEntity::getId).toList(), allowance),
                open,
                languages);
        // A project's solution is a foreign key the schema enforces, and a solution holding a project
        // cannot be deleted: the name is there. Read as optional all the same, rather than a 500 on a
        // race nobody can produce.
        String solutionName = solutions.findById(found.getSolutionId()).map(SolutionEntity::getName).orElse(null);
        return ProjectDetail.of(node, new SolutionRef(found.getSolutionId(), solutionName));
    }

    @Transactional(readOnly = true)
    public SolutionTree tree(VisibilityService.Allowance allowance) {
        Visibility visibility = allowance.visibility();
        boolean everything = visibility instanceof Visibility.Everything;

        List<RepositoryEntity> allRepositories = repositories.findAll();
        List<RepositoryEntity> visible = allRepositories.stream()
                .filter(repository -> visibility.permits(new ScanTarget.Repository(repository.getId())))
                .toList();
        List<ContainerEntity> allContainers = containers.findAll();
        List<ContainerEntity> visibleContainers = allContainers.stream()
                .filter(container -> visibility.permits(new ScanTarget.Container(container.getId())))
                .toList();
        Map<Long, List<RepositoryEntity>> visibleByProject = byProject(visible, RepositoryEntity::getProjectId);
        Map<Long, List<ContainerEntity>> visibleContainersByProject =
                byProject(visibleContainers, ContainerEntity::getProjectId);
        // Every filed target, visible or not, per project: what "partial" is measured against.
        Map<Long, Long> filedByProject = new HashMap<>();
        // Every filed repository, visible or not, per project: what the checklists' guard compares.
        Map<Long, List<Long>> repositoryIdsByProject = allRepositories.stream()
                .filter(repository -> repository.getProjectId() != null)
                .collect(Collectors.groupingBy(RepositoryEntity::getProjectId,
                        Collectors.mapping(RepositoryEntity::getId, Collectors.toList())));
        Stream.concat(allRepositories.stream().map(RepositoryEntity::getProjectId),
                        allContainers.stream().map(ContainerEntity::getProjectId))
                .filter(java.util.Objects::nonNull)
                .forEach(projectId -> filedByProject.merge(projectId, 1L, Long::sum));

        Map<ScanTarget, Map<Severity, Long>> open = openBySeverity(visible, visibleContainers, everything);
        // Of the repositories filed in a project and visible: an unfiled one belongs to no project's
        // union, and a hidden one's languages are its own.
        Map<Long, Set<Language>> languages = scans.detectedLanguages(visible.stream()
                .filter(repository -> repository.getProjectId() != null)
                .map(RepositoryEntity::getId)
                .toList());

        List<ProjectEntity> allProjects = projects.findAll();
        List<ProjectEntity> shownProjects = allProjects.stream()
                .filter(project -> everything
                        || allowance.grantedProjects().contains(project.getId())
                        || visibleByProject.containsKey(project.getId())
                        || visibleContainersByProject.containsKey(project.getId()))
                .toList();
        Map<Long, List<ProjectNode>> nodesBySolution = shownProjects.stream()
                .map(project -> projectNode(
                        project,
                        visibleByProject.getOrDefault(project.getId(), List.of()),
                        visibleContainersByProject.getOrDefault(project.getId(), List.of()),
                        filedByProject.getOrDefault(project.getId(), 0L),
                        RowVisibility.seesWholeProject(project.getId(),
                                repositoryIdsByProject.getOrDefault(project.getId(), List.of()), allowance),
                        open,
                        languages))
                .sorted(Comparator.comparing(ProjectNode::name, String.CASE_INSENSITIVE_ORDER))
                .collect(Collectors.groupingBy(ProjectNode::solutionId));

        // Hidden targets per solution, over every project of it and not only the shown ones:
        // a project the reader cannot see at all still makes the solution's figures partial.
        Map<Long, Long> solutionOfProject = allProjects.stream()
                .collect(Collectors.toMap(ProjectEntity::getId, ProjectEntity::getSolutionId));
        Map<Long, Long> filedBySolution = new HashMap<>();
        filedByProject.forEach((projectId, count) -> filedBySolution.merge(solutionOfProject.get(projectId), count, Long::sum));

        List<SolutionNode> solutionNodes = solutions.findAll().stream()
                .filter(solution -> everything || nodesBySolution.containsKey(solution.getId()))
                .map(solution -> solutionNode(
                        solution,
                        nodesBySolution.getOrDefault(solution.getId(), List.of()),
                        filedBySolution.getOrDefault(solution.getId(), 0L)))
                .sorted(Comparator.comparing(SolutionNode::name, String.CASE_INSENSITIVE_ORDER))
                .toList();

        List<RepositoryEntity> unfiled = visibleByProject.getOrDefault(null, List.of());
        List<ContainerEntity> unfiledContainers = visibleContainersByProject.getOrDefault(null, List.of());
        return new SolutionTree(
                solutionNodes,
                new Unfiled(
                        unfiled.size(),
                        sum(unfiled, unfiledContainers, open),
                        refs(unfiled),
                        unfiledContainers.size(),
                        containerRefs(unfiledContainers)));
    }

    private static ProjectNode projectNode(
            ProjectEntity project,
            List<RepositoryEntity> visible,
            List<ContainerEntity> visibleContainers,
            long filed,
            boolean checklistsVisible,
            Map<ScanTarget, Map<Severity, Long>> open,
            Map<Long, Set<Language>> languages) {
        Set<Language> union = EnumSet.noneOf(Language.class);
        List<Long> unknown = new ArrayList<>();
        for (RepositoryEntity repository : visible) {
            Set<Language> known = languages.get(repository.getId());
            if (known == null) {
                unknown.add(repository.getId());
            } else {
                union.addAll(known);
            }
        }
        unknown.sort(Comparator.naturalOrder());
        return new ProjectNode(
                project.getId(),
                project.getSolutionId(),
                project.getName(),
                project.getDescription(),
                project.getCreatedAt(),
                visible.size() + visibleContainers.size() < filed,
                checklistsVisible,
                visible.size(),
                sum(visible, visibleContainers, open),
                refs(visible),
                List.copyOf(union),
                List.copyOf(unknown),
                visibleContainers.size(),
                containerRefs(visibleContainers));
    }

    private static SolutionNode solutionNode(SolutionEntity solution, List<ProjectNode> projects, long filed) {
        int repositoriesShown = projects.stream().mapToInt(ProjectNode::repositoryCount).sum();
        int containersShown = projects.stream().mapToInt(ProjectNode::containerCount).sum();
        return new SolutionNode(
                solution.getId(),
                solution.getName(),
                solution.getDescription(),
                solution.getCreatedAt(),
                repositoriesShown + containersShown < filed,
                repositoriesShown,
                add(projects.stream().map(ProjectNode::openIssues).toList()),
                projects,
                containersShown);
    }

    /**
     * The open backlog per visible target and severity, in one query.
     *
     * <p>Through the scoreboard's own grouped count — asked of {@code issues}, which owns it —
     * narrowed to the visible repositories and images, which that predicate writes into the statement
     * rather than binding one parameter each: the list is sized by the estate. An unrestricted reader
     * is not narrowed at all: listing every target in an {@code or} would say the same thing at the
     * cost of a statement as long as the estate.
     */
    private Map<ScanTarget, Map<Severity, Long>> openBySeverity(
            List<RepositoryEntity> visible, List<ContainerEntity> visibleContainers, boolean everything) {
        if (!everything && visible.isEmpty() && visibleContainers.isEmpty()) {
            return Map.of();
        }
        Visibility narrowed = everything
                ? Visibility.everything()
                : Visibility.only(Stream.concat(
                                visible.stream().<ScanTarget>map(repository -> new ScanTarget.Repository(repository.getId())),
                                visibleContainers.stream().<ScanTarget>map(container -> new ScanTarget.Container(container.getId())))
                        .toList());
        return backlog.openBySeverityPerTarget(narrowed);
    }

    private static OpenIssues sum(
            Collection<RepositoryEntity> repositories,
            Collection<ContainerEntity> containers,
            Map<ScanTarget, Map<Severity, Long>> open) {
        Map<Severity, Long> total = new EnumMap<>(Severity.class);
        Stream.concat(
                        repositories.stream().<ScanTarget>map(repository -> new ScanTarget.Repository(repository.getId())),
                        containers.stream().<ScanTarget>map(container -> new ScanTarget.Container(container.getId())))
                .forEach(target -> open.getOrDefault(target, Map.of())
                        .forEach((severity, count) -> total.merge(severity, count, Long::sum)));
        return total.isEmpty() ? OpenIssues.NONE : OpenIssues.of(total);
    }

    private static OpenIssues add(List<OpenIssues> parts) {
        return parts.stream().reduce(OpenIssues.NONE, (a, b) -> new OpenIssues(
                a.critical() + b.critical(),
                a.high() + b.high(),
                a.medium() + b.medium(),
                a.low() + b.low(),
                a.negligible() + b.negligible(),
                a.unknown() + b.unknown(),
                a.total() + b.total()));
    }

    /** Grouped by project, the unfiled ones under the {@code null} key. */
    private static <T> Map<Long, List<T>> byProject(List<T> targets, Function<T, Long> projectOf) {
        Map<Long, List<T>> grouped = new HashMap<>();
        for (T target : targets) {
            grouped.computeIfAbsent(projectOf.apply(target), id -> new ArrayList<>()).add(target);
        }
        return grouped;
    }

    private static List<RepositoryRef> refs(List<RepositoryEntity> repositories) {
        return repositories.stream()
                .map(repository -> new RepositoryRef(repository.getId(), TargetNaming.of(repository)))
                .sorted(Comparator.comparing(RepositoryRef::name, String.CASE_INSENSITIVE_ORDER)
                        .thenComparing(RepositoryRef::id))
                .toList();
    }

    private static List<ContainerRef> containerRefs(List<ContainerEntity> containers) {
        return containers.stream()
                .map(container -> new ContainerRef(container.getId(), TargetNaming.of(container)))
                .sorted(Comparator.comparing(ContainerRef::name, String.CASE_INSENSITIVE_ORDER)
                        .thenComparing(ContainerRef::id))
                .toList();
    }
}
