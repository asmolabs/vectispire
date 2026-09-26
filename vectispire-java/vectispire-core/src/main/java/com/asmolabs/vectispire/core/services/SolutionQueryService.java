package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.persistence.ProjectEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.SolutionEntity;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.IssueAggregates;
import com.asmolabs.vectispire.core.repositories.IssueFilters;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Projects;
import com.asmolabs.vectispire.core.repositories.Solutions;
import com.asmolabs.vectispire.core.services.shared.TargetNaming;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The solutions tree as one reader may see it, with each project's open backlog (decision 0023).
 *
 * <h2>What a reader is shown</h2>
 *
 * <ul>
 *   <li><b>A project appears</b> when the reader holds a grant on it, or sees at least one of its
 *       repositories. With only the repositories they may see — and {@code partial} set when the
 *       project holds others: a partial grant sees a partial project, and says so, because a
 *       figure that silently covers half a project reads as the whole of it.
 *   <li><b>A solution appears</b> when one of its projects does, and is {@code partial} when any
 *       repository filed under it is hidden from the reader.
 *   <li><b>"No project" is a group of its own</b>, never omitted: every repository an
 *       administrator has not filed yet is listed there, so filing is visibly unfinished rather
 *       than invisibly so.
 *   <li>A reader whose visibility is everything — an administrator, a global role, or anyone
 *       while the deployment is open — sees every solution and project, empty ones included.
 * </ul>
 *
 * <p><b>The figures leave settled triage out</b>, like every figure of risk: a backlog whose team
 * argued each finding not affected is not a backlog. They are counted over the visible member
 * repositories only, in one grouped query for the whole tree.
 */
@Service
public class SolutionQueryService {

    private final Solutions solutions;
    private final Projects projects;
    private final GitRepositories repositories;
    private final Issues issues;

    public SolutionQueryService(Solutions solutions, Projects projects, GitRepositories repositories, Issues issues) {
        this.solutions = solutions;
        this.projects = projects;
        this.repositories = repositories;
        this.issues = issues;
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

    /**
     * @param partial the project holds repositories this reader does not see; its figures and its
     *     list cover only those they do
     * @param repositoryCount the repositories listed, which are the visible ones
     */
    public record ProjectNode(
            Long id,
            Long solutionId,
            String name,
            String description,
            Instant createdAt,
            boolean partial,
            int repositoryCount,
            OpenIssues openIssues,
            List<RepositoryRef> repositories) {}

    /** @param partial a repository filed under this solution is hidden from this reader */
    public record SolutionNode(
            Long id,
            String name,
            String description,
            Instant createdAt,
            boolean partial,
            int repositoryCount,
            OpenIssues openIssues,
            List<ProjectNode> projects) {}

    /** The repositories in no project that this reader may see, with their figures. */
    public record Unfiled(int repositoryCount, OpenIssues openIssues, List<RepositoryRef> repositories) {}

    public record SolutionTree(List<SolutionNode> solutions, Unfiled unfiled) {}

    @Transactional(readOnly = true)
    public SolutionTree tree(VisibilityService.Allowance allowance) {
        Visibility visibility = allowance.visibility();
        boolean everything = visibility instanceof Visibility.Everything;

        List<RepositoryEntity> all = repositories.findAll();
        List<RepositoryEntity> visible = all.stream()
                .filter(repository -> visibility.permits(new ScanTarget.Repository(repository.getId())))
                .toList();
        Map<Long, List<RepositoryEntity>> visibleByProject = byProject(visible);
        Map<Long, Long> filedByProject = all.stream()
                .filter(repository -> repository.getProjectId() != null)
                .collect(Collectors.groupingBy(RepositoryEntity::getProjectId, Collectors.counting()));

        Map<Long, Map<Severity, Long>> open = openBySeverity(visible, everything);

        List<ProjectEntity> allProjects = projects.findAll();
        List<ProjectEntity> shownProjects = allProjects.stream()
                .filter(project -> everything
                        || allowance.grantedProjects().contains(project.getId())
                        || visibleByProject.containsKey(project.getId()))
                .toList();
        Map<Long, List<ProjectNode>> nodesBySolution = shownProjects.stream()
                .map(project -> projectNode(
                        project,
                        visibleByProject.getOrDefault(project.getId(), List.of()),
                        filedByProject.getOrDefault(project.getId(), 0L),
                        open))
                .sorted(Comparator.comparing(ProjectNode::name, String.CASE_INSENSITIVE_ORDER))
                .collect(Collectors.groupingBy(ProjectNode::solutionId));

        // Hidden repositories per solution, over every project of it and not only the shown ones:
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
        return new SolutionTree(
                solutionNodes,
                new Unfiled(unfiled.size(), sum(unfiled, open), refs(unfiled)));
    }

    private static ProjectNode projectNode(
            ProjectEntity project, List<RepositoryEntity> visible, long filed, Map<Long, Map<Severity, Long>> open) {
        return new ProjectNode(
                project.getId(),
                project.getSolutionId(),
                project.getName(),
                project.getDescription(),
                project.getCreatedAt(),
                visible.size() < filed,
                visible.size(),
                sum(visible, open),
                refs(visible));
    }

    private static SolutionNode solutionNode(SolutionEntity solution, List<ProjectNode> projects, long filed) {
        int visible = projects.stream().mapToInt(ProjectNode::repositoryCount).sum();
        return new SolutionNode(
                solution.getId(),
                solution.getName(),
                solution.getDescription(),
                solution.getCreatedAt(),
                visible < filed,
                visible,
                add(projects.stream().map(ProjectNode::openIssues).toList()),
                projects);
    }

    /**
     * The open backlog per visible repository and severity, in one query.
     *
     * <p>Through the scoreboard's own grouped count, narrowed to the visible repositories — the
     * reader's visibility with its containers dropped, since no container is in a project. An
     * unrestricted reader is not narrowed at all: listing every repository in an {@code or} would
     * say the same thing at the cost of a statement as long as the estate.
     */
    private Map<Long, Map<Severity, Long>> openBySeverity(List<RepositoryEntity> visible, boolean everything) {
        if (!everything && visible.isEmpty()) {
            return Map.of();
        }
        Visibility narrowed = everything
                ? Visibility.everything()
                : Visibility.only(visible.stream()
                        .<ScanTarget>map(repository -> new ScanTarget.Repository(repository.getId()))
                        .toList());
        Map<Long, Map<Severity, Long>> counts = new HashMap<>();
        for (IssueAggregates.TargetSeverityCount row : issues.countOpenByTargetAndSeverity(
                new IssueFilters(null, null, null, null, null, null, false, false, null, true, Map.of(), narrowed)
                        .toSpecification())) {
            if (row.repoId() == null) {
                continue;
            }
            counts.computeIfAbsent(row.repoId(), id -> new EnumMap<>(Severity.class))
                    .merge(Severity.of(row.severity()), row.count(), Long::sum);
        }
        return counts;
    }

    private static OpenIssues sum(Collection<RepositoryEntity> repositories, Map<Long, Map<Severity, Long>> open) {
        Map<Severity, Long> total = new EnumMap<>(Severity.class);
        for (RepositoryEntity repository : repositories) {
            open.getOrDefault(repository.getId(), Map.of()).forEach((severity, count) -> total.merge(severity, count, Long::sum));
        }
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
    private static Map<Long, List<RepositoryEntity>> byProject(List<RepositoryEntity> repositories) {
        Map<Long, List<RepositoryEntity>> grouped = new HashMap<>();
        for (RepositoryEntity repository : repositories) {
            grouped.computeIfAbsent(repository.getProjectId(), id -> new ArrayList<>()).add(repository);
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
}
