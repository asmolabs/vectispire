package com.asmolabs.vectispire.common.domain.forges;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Where an import files each repository (decision 0037 §4): the solution and project the forge's layout
 * suggests, then whatever a person changed.
 *
 * <p><b>Proposed, shown, editable — never inferred.</b> Decision 0023 files nothing into a project without a
 * person; this proposes, the preview shows, and the import applies what the request says, which is the proposal
 * only where nobody changed it.
 *
 * <p><b>The proposal per forge.</b> GitLab: the top-level group is the solution and the repository's parent
 * group below it the project ({@code acme/backend/payments/api} → {@code backend/payments}); a repository
 * directly under the top-level group goes to a project named after that group. GitHub: the organisation is the
 * solution and each repository its own project, GitHub having no level between them (answer 3). A personal
 * namespace: neither — the repository is imported into no project unless a rule names one.
 *
 * <p><b>The rules.</b> A rule names a namespace — which it covers with everything below it — or one repository
 * by its forge id, and changes the solution, the project, or both, or files into no project. Applied from the
 * shallowest namespace to the deepest, then the repository's own: the most specific word on each field wins, so
 * renaming the top-level group's solution keeps every subgroup's proposed project.
 *
 * @param rules as the request gave them, validated
 */
public record ImportMapping(List<Rule> rules) {

    /** The width of {@code t_solution.name} and {@code t_project.name}. */
    public static final int NAME_LENGTH = 100;

    /** More than a screen sends for a thousand repositories, each with a rule of its own and its namespace's. */
    public static final int MAX_RULES = 5_000;

    /**
     * One change to the proposal.
     *
     * @param namespacePath the namespace it covers, with everything below it; or
     * @param forgeId the one repository it covers
     * @param solution the solution's name, existing or to create; null keeps what applies so far
     * @param project the project's name within it; null keeps what applies so far
     * @param noProject true files into no project, whatever applies so far
     */
    public record Rule(String namespacePath, String forgeId, String solution, String project, Boolean noProject) {}

    /**
     * Where one repository goes: both null for no project, both set otherwise.
     *
     * @param solution the solution's name, as proposed or as a rule wrote it
     * @param project the project's name within the solution
     */
    public record Placement(String solution, String project) {

        public static final Placement NONE = new Placement(null, null);

        public boolean filed() {
            return project != null;
        }
    }

    /** No rule: the proposal everywhere. */
    public static final ImportMapping PROPOSED = new ImportMapping(List.of());

    public ImportMapping {
        rules = List.copyOf(rules);
    }

    /**
     * The request's rules, refused in words: a rule names a namespace or a repository and not both, names
     * something to change, and is the only rule for what it names.
     */
    public static ImportMapping of(List<Rule> raw) {
        if (raw == null || raw.isEmpty()) {
            return PROPOSED;
        }
        if (raw.size() > MAX_RULES) {
            throw new InvalidInputException("At most " + MAX_RULES + " mapping rules per import.");
        }
        List<Rule> rules = new ArrayList<>();
        Set<String> named = new HashSet<>();
        for (Rule rule : raw) {
            if (rule == null) {
                throw new InvalidInputException("A mapping rule is empty.");
            }
            String namespace = blankToNull(rule.namespacePath());
            String forgeId = blankToNull(rule.forgeId());
            if ((namespace == null) == (forgeId == null)) {
                throw new InvalidInputException("A mapping rule names a namespacePath or a forgeId, not both and not "
                        + "neither.");
            }
            if (namespace != null) {
                namespace = BoundedText.within(stripSlashes(namespace), DiscoveredRepository.PATH_LENGTH,
                        "A mapping rule's namespacePath");
            } else {
                forgeId = BoundedText.within(forgeId, DiscoveredRepository.FORGE_ID_LENGTH, "A mapping rule's forgeId");
            }
            boolean noProject = Boolean.TRUE.equals(rule.noProject());
            String solution = rule.solution() == null ? null : name(rule.solution(), "A solution name");
            String project = rule.project() == null ? null : name(rule.project(), "A project name");
            String what = namespace != null ? "namespace " + namespace : "repository " + forgeId;
            if (noProject && (solution != null || project != null)) {
                throw new InvalidInputException("The rule for " + what + " files into no project and names one: "
                        + "choose.");
            }
            if (!noProject && solution == null && project == null) {
                throw new InvalidInputException("The rule for " + what + " changes nothing: name a solution, a "
                        + "project, or no project.");
            }
            String key = namespace != null ? "n:" + namespace.toLowerCase(Locale.ROOT) : "r:" + forgeId;
            if (!named.add(key)) {
                throw new InvalidInputException("Two mapping rules name " + what + ".");
            }
            rules.add(new Rule(namespace, forgeId, solution, project, noProject));
        }
        return new ImportMapping(rules);
    }

    /**
     * The proposal for a repository, before any rule.
     *
     * @param namespacePath where it lives, {@code group/subgroup} — GitHub's owner
     * @param name its own name, the last segment of its path
     */
    public static Placement proposed(ForgeKind kind, String namespacePath, String name, boolean personal) {
        if (personal) {
            return Placement.NONE;
        }
        String namespace = stripSlashes(Objects.requireNonNull(namespacePath, "namespacePath"));
        if (namespace.isEmpty()) {
            return Placement.NONE;
        }
        return switch (kind) {
            case GITLAB -> {
                int top = namespace.indexOf('/');
                yield top < 0
                        ? new Placement(namespace, namespace)
                        : new Placement(namespace.substring(0, top), namespace.substring(top + 1));
            }
            case GITHUB -> new Placement(namespace, Objects.requireNonNull(name, "name"));
        };
    }

    /**
     * Where the repository goes once the rules are applied.
     *
     * @return the placement, or a refusal naming what is missing — a project with no solution, or a solution with
     *     no project — which the preview shows against the repository and the import refuses
     */
    public Outcome place(ForgeKind kind, String forgeId, String namespacePath, String name, boolean personal) {
        Placement placed = proposed(kind, namespacePath, name, personal);
        String namespace = stripSlashes(namespacePath).toLowerCase(Locale.ROOT);
        List<Rule> covering = rules.stream()
                .filter(rule -> rule.namespacePath() != null && covers(rule.namespacePath(), namespace))
                .sorted(Comparator.comparingInt(rule -> rule.namespacePath().length()))
                .toList();
        for (Rule rule : covering) {
            placed = apply(placed, rule);
        }
        Optional<Rule> own = rules.stream().filter(rule -> forgeId.equals(rule.forgeId())).findFirst();
        if (own.isPresent()) {
            placed = apply(placed, own.get());
        }
        if (placed.project() != null && placed.solution() == null) {
            return new Outcome(placed, Optional.of("A project belongs to a solution: name the solution of project \""
                    + placed.project() + "\"."));
        }
        if (placed.solution() != null && placed.project() == null) {
            return new Outcome(placed, Optional.of("A repository is filed into a project of solution \""
                    + placed.solution() + "\": name the project, or choose no project."));
        }
        Placement result = placed;
        return new Outcome(result, BoundedText.tooLong(result.solution(), NAME_LENGTH, "The solution name")
                .or(() -> BoundedText.tooLong(result.project(), NAME_LENGTH, "The project name")));
    }

    /**
     * What {@link #place} decided.
     *
     * @param refusal why the import would refuse this placement; empty when it can be applied
     */
    public record Outcome(Placement placement, Optional<String> refusal) {}

    /** Whether the rule's namespace is this one or one of its ancestors, compared by whole segments. */
    private static boolean covers(String ruleNamespace, String namespace) {
        String rule = ruleNamespace.toLowerCase(Locale.ROOT);
        return namespace.equals(rule) || namespace.startsWith(rule + "/");
    }

    private static Placement apply(Placement placed, Rule rule) {
        if (Boolean.TRUE.equals(rule.noProject())) {
            return Placement.NONE;
        }
        return new Placement(
                rule.solution() != null ? rule.solution() : placed.solution(),
                rule.project() != null ? rule.project() : placed.project());
    }

    private static String name(String raw, String what) {
        return BoundedText.required(raw, NAME_LENGTH, what);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String stripSlashes(String value) {
        String trimmed = value.trim();
        int start = 0;
        int end = trimmed.length();
        while (start < end && trimmed.charAt(start) == '/') {
            start++;
        }
        while (end > start && trimmed.charAt(end - 1) == '/') {
            end--;
        }
        return trimmed.substring(start, end);
    }
}
