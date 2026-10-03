package com.asmolabs.vectispire.core.posture;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibleScope;
import com.asmolabs.vectispire.common.domain.access.VisibleTarget;
import com.asmolabs.vectispire.common.domain.licenses.LicenseEntry;
import com.asmolabs.vectispire.common.domain.scorecard.CandidateScore;
import com.asmolabs.vectispire.common.domain.scorecard.PortfolioScorecard;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityGrade;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityScorecard;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.inventory.LicenseGovernanceService;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.SlaService;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueFilters;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import com.asmolabs.vectispire.core.targets.TargetNaming;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Service;

/**
 * Computes security posture scorecards and letter grades (A+ to F) for repositories, containers,
 * projects and solutions, and the portfolio's distribution of them.
 *
 * <p><b>One formula, decision 0036's</b> ({@link CandidateScore} with {@link #WEIGHTS}), since 0.11.0:
 * every card, the ranking and the public badge read it here, and nowhere else. It replaced a hundred
 * less a fixed charge per issue that saturated at zero; there is no flag and no second formula live,
 * since two grades for one target on two screens is the defect the ranking's unification closed.
 */
@Service
public class SecurityScorecardService {

    /** The weights every grade is computed with — a contract (decision 0036), not a setting. */
    public static final CandidateScore.Weights WEIGHTS = CandidateScore.Weights.PROPOSED;

    private final IssueCatalog issuesRepo;
    private final TargetCatalog targets;
    private final ScanCatalog scansRepo;
    private final LicenseGovernanceService licenseService;
    private final SlaService sla;
    private final TargetNaming naming;

    public SecurityScorecardService(
            IssueCatalog issuesRepo,
            TargetCatalog targets,
            ScanCatalog scansRepo,
            LicenseGovernanceService licenseService,
            SlaService sla,
            TargetNaming naming) {
        this.issuesRepo = issuesRepo;
        this.targets = targets;
        this.scansRepo = scansRepo;
        this.licenseService = licenseService;
        this.sla = sla;
        this.naming = naming;
    }

    /**
     * A repository's scorecard, for a caller who may see it.
     *
     * <p><b>Refused here, before the row is read.</b> A scorecard is a target's posture in a number,
     * and the number is the interesting part to somebody who was not given the target: it says how
     * exposed a neighbouring team is. The route used to refuse and then call this with the bare id,
     * which answered whoever called it next. A hidden repository is refused as a hidden target — "Target
     * not found." — before any lookup could tell it from an absent one; an absent one the caller
     * could see is empty.
     */
    public Optional<SecurityScorecard> getRepositoryScorecard(long repoId, Visibility allowed) {
        VisibleTarget<ScanTarget.Repository> checked = RowVisibility.requireVisible(new ScanTarget.Repository(repoId), allowed);
        return targets.repository(repoId).map(repo -> {
            // This narrows the *read*, which used to be the whole table filtered down to one
            // repository afterwards.
            Terms open = Terms.of(issuesRepo.countForGradingByTarget(
                    openWithin(Visibility.only(List.of(new ScanTarget.Repository(repoId))))));

            // **The filter was passed to the stream and not to the query.** The unfiltered call
            // parsed every SBOM in the deployment to keep one repository's rows.
            List<LicenseEntry> licenses = licenseService.getInventory(checked).stream()
                    .filter(l -> Long.valueOf(repoId).equals(l.targetId()) && "repository".equalsIgnoreCase(l.targetKind()))
                    .toList();

            boolean hasAttestation = scansRepo.hasScanWithStatus(new ScanTarget.Repository(repoId), "completed");
            long overdue = sla.countOverdue(Visibility.only(List.of(new ScanTarget.Repository(repoId))));

            return targetCard(repoId, "repository", repo.name(), open, violations(licenses), hasAttestation, overdue);
        });
    }

    /** One target's card: its own backlog and licences, through the formula of decision 0036. */
    private SecurityScorecard targetCard(
            long id, String kind, String name, Terms open, long licences, boolean hasAttestation, long overdue) {
        return card(id, kind, name, open, licences, hasAttestation, overdue, Coverage.ofOne(hasAttestation),
                CandidateScore.of(open.weighed(licences), WEIGHTS).score(), null);
    }

    /** An image's scorecard, for a caller who may see it — refused as {@link #getRepositoryScorecard} is. */
    public Optional<SecurityScorecard> getContainerScorecard(long containerId, Visibility allowed) {
        VisibleTarget<ScanTarget.Container> checked = RowVisibility.requireVisible(new ScanTarget.Container(containerId), allowed);
        return targets.container(containerId).map(container -> {
            // The repository form was narrowed and this one was not, in the same change — which
            // is what a sweep is for and what reading the diff was not enough to catch.
            Terms open = Terms.of(issuesRepo.countForGradingByTarget(
                    openWithin(Visibility.only(List.of(new ScanTarget.Container(containerId))))));

            List<LicenseEntry> licenses = licenseService.getInventory(checked).stream()
                    .filter(l -> Long.valueOf(containerId).equals(l.targetId()) && "container".equalsIgnoreCase(l.targetKind()))
                    .toList();

            boolean hasAttestation = scansRepo.hasScanWithStatus(new ScanTarget.Container(containerId), "completed");
            long overdue = sla.countOverdue(Visibility.only(List.of(new ScanTarget.Container(containerId))));

            return targetCard(containerId, "container", container.imageName() + ":" + container.tag(), open,
                    violations(licenses), hasAttestation, overdue);
        });
    }

    /**
     * The portfolio's posture, <b>within the caller's allowance</b>: how many targets read each grade,
     * the weakest of them, and the risk points of everything open — no grade of its own (decision 0036,
     * {@link PortfolioScorecard}).
     *
     * <p>"Organization Portfolio" is a fair name for an administrator and a false one for a
     * reader assigned two repositories: the figures they were shown were the whole estate's, which
     * is both a leak and a set of numbers that means nothing about anything they can act on.
     *
     * <p><b>Each target is graded by {@link #gradeEach}</b>, the ranking's and so the card's own
     * computation: the distribution counts the grades the reader finds on the cards, and the weakest
     * target is the one the ranking lists last among the graded. A target the reader sees and nobody
     * scanned is a {@code NO_DATA}, counted as such — the coverage, said outright, where the old
     * single grade was capped by it.
     */
    public PortfolioScorecard getPortfolioScorecard(Visibility allowed) {
        List<ScanTarget> visible = new ArrayList<>();
        targets.repositories().forEach(repository -> visible.add(new ScanTarget.Repository(repository.id())));
        targets.containers().forEach(container -> visible.add(new ScanTarget.Container(container.id())));
        visible.removeIf(target -> !allowed.permits(target));
        visible.sort(LISTING);

        LicenseGovernanceService.Violations violations = licenseService.violations(allowed);
        Graded graded = grade(allowed, violations.byTarget());
        Map<SecurityGrade, Long> distribution = new EnumMap<>(SecurityGrade.class);
        for (SecurityGrade grade : SecurityGrade.values()) {
            distribution.put(grade, 0L);
        }
        // Over the targets the reader sees, never over the graded map's keys: those come from the
        // issue rows, and a row is keyed to its repository even when the reader was given only the
        // image it also names.
        ScanTarget weakest = null;
        TargetGrade weakestGrade = null;
        int observed = 0;
        for (ScanTarget target : visible) {
            TargetGrade grade = graded.grades().getOrDefault(target, TargetGrade.UNOBSERVED);
            distribution.merge(grade.grade(), 1L, Long::sum);
            if (grade.score() == null) {
                continue;
            }
            observed++;
            if (weakestGrade == null || WEAKER.compare(grade, weakestGrade) < 0) {
                weakest = target;
                weakestGrade = grade;
            }
        }

        // **The licence term is the tallies' sum, not the estate's inventory.** It read every scan,
        // every component and every licence finding of the deployment and narrowed to the allowance
        // afterwards — about 105,000 entities a call on two hundred targets of two scans, for an
        // administrator and for a reader granted five alike. The count is the same: the inventory's
        // refused entries over what the reader sees, the scans attached to no target included for a
        // reader who sees everything, as they were. Read once with the targets' own, which grade them.
        long licences = violations.total();
        Terms open = graded.whole();
        return new PortfolioScorecard(
                visible.size(),
                observed,
                distribution.entrySet().stream()
                        .map(entry -> new PortfolioScorecard.GradeCount(entry.getKey(), entry.getValue()))
                        .toList(),
                weakest == null ? null : named(weakest, weakestGrade.score(), weakestGrade.riskPoints()),
                CandidateScore.riskPoints(open.weighed(licences), WEIGHTS),
                open.critical(),
                open.high(),
                open.kev(),
                sla.countOverdue(allowed),
                licences);
    }

    /**
     * A project's or a solution's scorecard, over the scope's visible targets and nothing else, <b>graded
     * by its weakest link</b> (decision 0036): the lowest score among its observed targets, each as its
     * own card computes it, held at the scope's observed share; {@code NO_DATA} when none is observed.
     * The card names the target its grade is read from. A partial scope is graded on what the caller
     * sees, as the portfolio is for a restricted reader; the scope says {@code partial} beside it.
     *
     * <p><b>Why not the scope's summed backlog</b>, which this card graded until 0.11.0: it graded a
     * scope by its size as much as by its exposure — twenty repositories of four mediums each, every
     * one A+, made a D project, and adding a clean repository to a project lowered it. A scope is no
     * safer than its most exposed target, and no less safe for holding more of them. What the sum said
     * that the weakest link does not — how much is open in the scope — the risk points still say:
     * they are the scope's, each issue and each licence entry once.
     *
     * <p><b>Each licence entry once.</b> The card used to sum its targets' inventories, and an image's
     * inventory holds the components and licence findings of every scan naming it and a repository —
     * keyed to the repository, whose inventory holds them as well: a scope filing both charged those
     * entries twice. The term is now the sum of the targets' tallies ({@code
     * LicenseGovernanceService.violationsByTarget}), where every entry belongs to the one target its
     * scan is attributed to, as each target's ranking row already counted it.
     *
     * @return {@code targetKind} {@code project} or {@code solution}, {@code targetId} the scope's
     */
    public SecurityScorecard getScopeScorecard(VisibleScope scope) {
        Visibility allowed = scope.visibility();
        List<IssueAggregates.TargetGradingCount> rows = issuesRepo.countForGradingByTarget(openWithin(allowed));
        Map<ScanTarget, Terms> byTarget = byTarget(rows);
        Map<ScanTarget, Long> violations = licenseService.violationsByTarget(allowed);
        Set<ScanTarget> observed = completedAmong(new HashSet<>(scope.targets()));

        ScanTarget weakest = null;
        CandidateScore.Result weakestResult = null;
        long licences = 0;
        for (ScanTarget target : scope.targets().stream().sorted(LISTING).toList()) {
            long refused = violations.getOrDefault(target, 0L);
            licences += refused;
            if (!observed.contains(target)) {
                // A target never scanned does not compete, even holding issues an import left: it
                // has no grade of its own to lend the scope. Its issues are in the risk points.
                continue;
            }
            CandidateScore.Result result =
                    CandidateScore.of(byTarget.getOrDefault(target, Terms.NONE).weighed(refused), WEIGHTS);
            if (weakestResult == null || weaker(result, weakestResult)) {
                weakest = target;
                weakestResult = result;
            }
        }

        SecurityScorecard.WeakestTarget named = weakest == null
                ? null
                : named(weakest, weakestResult.score(), weakestResult.riskPoints());
        return card(scope.id(), scope.kind().wireName(), scope.name(), Terms.of(rows), licences,
                !observed.isEmpty(), sla.countOverdue(allowed), new Coverage(scope.targets().size(), observed.size()),
                named == null ? null : named.score(), named);
    }

    /**
     * A target's score and grade as its own scorecard gives them, and the open counts a ranking
     * prints beside them.
     *
     * @param score null exactly when {@code grade} is {@link SecurityGrade#NO_DATA}
     * @param riskPoints the card's; null exactly when {@code score} is
     * @param medium an issue with no severity is counted here, as the ranking always counted it, and
     *     weighs as a medium
     */
    public record TargetGrade(
            Integer score, SecurityGrade grade, Double riskPoints, long critical, long high, long medium, long low) {

        /** A target listed for what it closed, holding no completed scan and nothing open. */
        public static final TargetGrade UNOBSERVED = new TargetGrade(null, SecurityGrade.NO_DATA, null, 0, 0, 0, 0);
    }

    /**
     * Every target the caller may see that holds an open issue or a completed scan, graded
     * <b>by the computation its own card runs</b> — {@link #getRepositoryScorecard} and
     * {@link #getContainerScorecard} give the same score and grade for each.
     *
     * <p><b>Why the dashboard's ranking reads this.</b> It graded a target a hundred less its open
     * backlog, with weights of its own, and saturated at zero: fifty issues and five hundred both
     * read 0, F, while the card and the public badge of the same repository showed another number
     * and another letter. One target, one grade, on every screen.
     *
     * <p>Three reads, each once for the whole allowance and none bound per target: the grading counts
     * grouped by target (the allowance written into the statement, {@code IssueSpecifications.visible}),
     * the completed scans' targets narrowed in Java, and each target's licence violations. Those are the
     * inventory's own count, which parsed every SBOM of the estate at every load of the home page until
     * the inventory kept a tally per target, recounted when the target's scans move ({@code
     * LicenseGovernanceService.violationsByTarget}). Without the term a target's rank would disagree
     * with its card by a high's weight a violation.
     *
     * <p>A target holding neither an open issue nor a completed scan is absent from the map; a caller
     * listing one anyway — for what it closed — grades it {@link TargetGrade#UNOBSERVED}.
     */
    public Map<ScanTarget, TargetGrade> gradeEach(Visibility allowed) {
        return grade(allowed, licenseService.violationsByTarget(allowed)).grades();
    }

    /** Each target's grade, and the whole allowance's open backlog read from the same rows. */
    private record Graded(Map<ScanTarget, TargetGrade> grades, Terms whole) {}

    private Graded grade(Visibility allowed, Map<ScanTarget, Long> violations) {
        List<IssueAggregates.TargetGradingCount> rows = issuesRepo.countForGradingByTarget(openWithin(allowed));
        Map<ScanTarget, Terms> byTarget = byTarget(rows);

        // Narrowed here, since the scans' targets are the estate's: listing a clean target is
        // listing it, and a reader must not learn of one they were not given.
        Set<ScanTarget> observed = new HashSet<>();
        scansRepo.targetsWithStatus("completed").forEach(row -> {
            if (row.target() != null && allowed.permits(row.target())) {
                observed.add(row.target());
            }
        });

        Set<ScanTarget> graded = new LinkedHashSet<>(byTarget.keySet());
        graded.addAll(observed);

        Map<ScanTarget, TargetGrade> grades = new LinkedHashMap<>();
        for (ScanTarget target : graded) {
            Terms open = byTarget.getOrDefault(target, Terms.NONE);
            boolean scanned = observed.contains(target);
            long refused = violations.getOrDefault(target, 0L);
            // The card's own computation, not a copy of its arithmetic: the name and the overdue
            // figure enter the recommendations only, which the ranking does not show.
            SecurityScorecard card = card(null, null, null, open, refused, scanned, 0, Coverage.ofOne(scanned),
                    CandidateScore.of(open.weighed(refused), WEIGHTS).score(), null);
            grades.put(target, new TargetGrade(card.score(), card.grade(), card.riskPoints(),
                    open.critical(), open.high(), open.medium(), open.low()));
        }
        return new Graded(grades, Terms.of(rows));
    }

    /**
     * <b>For the score simulation only</b> ({@link ScoreSimulationService}): every visible target's
     * open backlog in the classes {@link CandidateScore} weighs, and its disallowed licences — the
     * counts {@link #gradeEach} grades, read the same way, so that the simulation's other weights are
     * compared on the same issues and licences.
     *
     * <p>A target with nothing open and no disallowed licence is absent; the caller reads it as
     * {@link CandidateScore.Counts#NONE}.
     */
    public Map<ScanTarget, CandidateScore.Counts> candidateCounts(Visibility allowed) {
        Map<ScanTarget, Terms> byTarget = byTarget(issuesRepo.countForGradingByTarget(openWithin(allowed)));
        Map<ScanTarget, Long> violations = licenseService.violationsByTarget(allowed);
        Set<ScanTarget> listed = new LinkedHashSet<>(byTarget.keySet());
        violations.forEach((target, refused) -> {
            if (refused > 0) {
                listed.add(target);
            }
        });
        Map<ScanTarget, CandidateScore.Counts> counts = new LinkedHashMap<>();
        for (ScanTarget target : listed) {
            counts.put(target, byTarget.getOrDefault(target, Terms.NONE).weighed(violations.getOrDefault(target, 0L)));
        }
        return counts;
    }

    /**
     * A project or a solution under the formula over its summed backlog, for the simulation only.
     *
     * @param counts the scope's open, unsettled backlog and its disallowed licences, each issue and each
     *     licence entry counted once
     * @param totalTargets the scope's visible targets, as its scorecard counts them
     * @param observedTargets those holding a completed scan, as its scorecard counts them
     * @param score null exactly when {@code grade} is {@code NO_DATA}; capped at the observed share as
     *     the scope's card is
     * @param exact the unrounded, uncapped score; null with no data
     * @param riskPoints the weighted backlog, uncapped; null with no data
     */
    public record ScopeCandidate(
            VisibleScope scope,
            CandidateScore.Counts counts,
            int totalTargets,
            int observedTargets,
            Integer score,
            SecurityGrade grade,
            Double exact,
            Double riskPoints) {}

    /**
     * <b>For the score simulation only</b>: each scope graded by the formula over its summed backlog —
     * the aggregation decision 0036 rejected, kept beside the weakest link the card now reads so that
     * the simulation still shows what the choice was between. The card's coverage cap and {@code
     * NO_DATA} are kept as they are ({@link #getScopeScorecard}), and so is its count: the licence term
     * is the sum of the targets' tallies, the issues the scope's grouped count, each once.
     */
    public List<ScopeCandidate> candidateScopes(List<VisibleScope> scopes, CandidateScore.Weights weights) {
        Set<ScanTarget> every = new LinkedHashSet<>();
        scopes.forEach(scope -> every.addAll(scope.targets()));
        // One read of the tallies and of the completed scans for every scope, both narrowed to the
        // scopes' visible targets — what each scope's own read would have been, summed.
        Map<ScanTarget, Long> violations = licenseService.violationsByTarget(Visibility.only(List.copyOf(every)));
        Set<ScanTarget> completed = completedAmong(every);

        List<ScopeCandidate> graded = new ArrayList<>();
        for (VisibleScope scope : scopes) {
            long licences = 0;
            for (ScanTarget target : scope.targets()) {
                licences += violations.getOrDefault(target, 0L);
            }
            CandidateScore.Counts counts =
                    Terms.of(issuesRepo.countForGradingByTarget(openWithin(scope.visibility()))).weighed(licences);
            Coverage coverage = new Coverage(
                    scope.targets().size(), (int) scope.targets().stream().filter(completed::contains).count());
            if (coverage.observed() == 0) {
                graded.add(new ScopeCandidate(scope, counts, coverage.total(), 0, null, SecurityGrade.NO_DATA, null, null));
                continue;
            }
            CandidateScore.Result result = CandidateScore.of(counts, weights);
            int score = cappedToCoverage(result.score(), coverage);
            graded.add(new ScopeCandidate(scope, counts, coverage.total(), coverage.observed(), score,
                    SecurityGrade.fromScore(score), CandidateScore.exact(counts, weights), result.riskPoints()));
        }
        return graded;
    }

    /** How many entries of an inventory the policy refuses: a high's weight each on the score. */
    private static long violations(List<LicenseEntry> licenses) {
        return licenses.stream().filter(l -> !l.compliant()).count();
    }

    /**
     * Which of two graded targets is the weaker: the lower score, then — both held at the same score,
     * at one deep in F or at the exploited cap — the more risk points. Neither: the first one listed
     * stays, so the answer does not move from one call to the next.
     */
    private static boolean weaker(CandidateScore.Result candidate, CandidateScore.Result current) {
        return candidate.score() < current.score()
                || (candidate.score() == current.score() && candidate.riskPoints() > current.riskPoints());
    }

    /** {@link #weaker} over graded targets, which hold a score. */
    private static final Comparator<TargetGrade> WEAKER = Comparator
            .comparing(TargetGrade::score)
            .thenComparing(TargetGrade::riskPoints, Comparator.reverseOrder());

    /** Repositories, then images, each by id — the order the ranking lists ties in. */
    private static final Comparator<ScanTarget> LISTING = Comparator
            .comparing((ScanTarget target) -> target instanceof ScanTarget.Container)
            .thenComparing(target -> switch (target) {
                case ScanTarget.Repository repository -> repository.id();
                case ScanTarget.Container container -> container.id();
            });

    /** The weakest target, named as the caller sees it named everywhere else. */
    private SecurityScorecard.WeakestTarget named(ScanTarget target, int score, double riskPoints) {
        Long repoId = target instanceof ScanTarget.Repository repository ? repository.id() : null;
        Long containerId = target instanceof ScanTarget.Container container ? container.id() : null;
        TargetNaming.Names names = naming.forIds(
                repoId == null ? List.of() : List.of(repoId), containerId == null ? List.of() : List.of(containerId));
        return new SecurityScorecard.WeakestTarget(names.kindOf(containerId), repoId != null ? repoId : containerId,
                names.of(repoId, containerId), score, SecurityGrade.fromScore(score), riskPoints);
    }

    /** Which of these targets hold a completed scan. */
    private Set<ScanTarget> completedAmong(Set<ScanTarget> among) {
        Set<ScanTarget> completed = new HashSet<>();
        scansRepo.targetsWithStatus("completed").forEach(row -> {
            if (row.target() != null && among.contains(row.target())) {
                completed.add(row.target());
            }
        });
        return completed;
    }

    /** The open rows, each under the one target the ranking files it under. */
    private static Map<ScanTarget, Terms> byTarget(List<IssueAggregates.TargetGradingCount> rows) {
        Map<ScanTarget, List<IssueAggregates.TargetGradingCount>> grouped = new LinkedHashMap<>();
        for (IssueAggregates.TargetGradingCount row : rows) {
            ScanTarget target = targetOf(row.repoId(), row.containerId());
            if (target != null && Terms.isOpen(row.state())) {
                grouped.computeIfAbsent(target, key -> new ArrayList<>()).add(row);
            }
        }
        Map<ScanTarget, Terms> terms = new LinkedHashMap<>();
        grouped.forEach((target, ofTarget) -> terms.put(target, Terms.of(ofTarget)));
        return terms;
    }

    /**
     * The open backlog, counted twice over the same rows: as the card shows it, and as the formula
     * weighs it.
     *
     * <p>An issue is open when its state is neither {@code closed} nor {@code resolved}, ignoring
     * case — a null state included; its severity is upper-cased. <b>Shown</b>: KEV is counted whatever
     * the severity and also under it, as the card and its recommendations always counted it — "two
     * criticals, one of them exploited". <b>Weighed</b> ({@link #weighed}): an exploited issue is in
     * its own class and in no severity; an issue with no severity is a medium, as the ranking counts
     * it; a severity neither critical, high nor medium is a low.
     */
    private record Terms(
            long critical, long high, long medium, long low, long kev,
            long exploitedWeighed, long criticalWeighed, long highWeighed, long mediumWeighed, long lowWeighed) {

        static final Terms NONE = new Terms(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

        static boolean isOpen(String state) {
            return !"closed".equalsIgnoreCase(state) && !"resolved".equalsIgnoreCase(state);
        }

        static Terms of(List<IssueAggregates.TargetGradingCount> rows) {
            long[] shown = new long[5];
            long[] weighed = new long[5];
            for (IssueAggregates.TargetGradingCount row : rows) {
                if (!isOpen(row.state())) {
                    continue;
                }
                String severity = row.severity() == null ? null : row.severity().toUpperCase(Locale.ROOT);
                int slot;
                if ("CRITICAL".equals(severity)) {
                    slot = 0;
                } else if ("HIGH".equals(severity)) {
                    slot = 1;
                } else if (severity == null || "MEDIUM".equals(severity)) {
                    slot = 2;
                } else {
                    slot = 3;
                }
                shown[slot] += row.count();
                if (row.kev()) {
                    shown[4] += row.count();
                    weighed[4] += row.count();
                } else {
                    weighed[slot] += row.count();
                }
            }
            return new Terms(shown[0], shown[1], shown[2], shown[3], shown[4],
                    weighed[4], weighed[0], weighed[1], weighed[2], weighed[3]);
        }

        /** The formula's classes, with the licence count the card charges. */
        CandidateScore.Counts weighed(long licences) {
            return new CandidateScore.Counts(
                    exploitedWeighed, criticalWeighed, highWeighed, mediumWeighed, lowWeighed, licences);
        }
    }

    /**
     * How much of the scope the backlog being graded was read from.
     *
     * <p><b>Observed means holding a completed scan</b>, the scan that produced the backlog graded
     * here — not the compliance summary's "the latest scan succeeded". A scan in flight or a later one
     * that failed does not erase the backlog the last completed one left, and a published badge must
     * not flip to "no data" every time a scan starts. A SARIF import alone does not make a target
     * observed, as it does not for compliance: it speaks for one tool, not for the target.
     *
     * <p><b>Not the freshness window</b> compliance also caps by: that window is a deployment setting,
     * and the grade is what a public badge carries — the reason the SLA deadlines are advised on here
     * and not scored. Two installations holding the same estate grade it the same.
     */
    private record Coverage(int total, int observed) {
        static Coverage ofOne(boolean observed) {
            return new Coverage(1, observed ? 1 : 0);
        }
    }

    /**
     * The same cap for the simulation's weakest-link variant, which picks its score from a target row
     * and holds it at the scope's observed share exactly as the card is held.
     */
    static int cappedToCoverage(int score, int totalTargets, int observedTargets) {
        return cappedToCoverage(score, new Coverage(totalTargets, observedTargets));
    }

    /**
     * A score held at the observed share of its scope, in the compliance summary's rounding — one copy
     * for the card and for the simulation's scopes, so the simulation caps as the card does.
     */
    private static int cappedToCoverage(int score, Coverage coverage) {
        int never = coverage.total() - coverage.observed();
        return never > 0
                ? Math.min(score, Math.round(((float) coverage.observed() / coverage.total()) * 100))
                : score;
    }

    /**
     * A card: the score handed in, held at the coverage, with the risk points of {@code open} and the
     * recommendations.
     *
     * @param uncapped the target's own score, or a scope's weakest target's; ignored with no data
     */
    private SecurityScorecard card(
            Long targetId,
            String targetKind,
            String targetName,
            Terms open,
            long licenseViolations,
            boolean hasAttestation,
            long overdueCount,
            Coverage coverage,
            Integer uncapped,
            SecurityScorecard.WeakestTarget weakest) {

        List<String> recommendations = new ArrayList<>();

        long criticalCount = open.critical();
        long highCount = open.high();
        long kevCount = open.kev();

        // **One weight for every critical, since nothing measures reachability.** A reachable
        // critical cost 15 and any other 8, read off a column no analysis writes: every issue reads
        // UNKNOWN, so the 15 was never charged and the term only promised a distinction the grade
        // could not make. Were it charged — a row edited by hand, an import that one day sets the
        // column — it would move a public badge on a claim nobody established.

        if (licenseViolations > 0) {
            recommendations.add("Remediate " + licenseViolations + " disallowed open source license violation(s).");
        }

        // **What "attestation" means here, and what the advice used to get wrong.** The in-toto
        // statement is issued on demand, from any completed scan, by `AttestationService`; nothing
        // is generated or stored beforehand. So the flag is true exactly when a scan has
        // completed, and the only way to earn it is to complete one. The recommendation told
        // people to "generate in-toto provenance attestations" — a step that does not exist in
        // this product, sending the reader to look for a button nobody built. It earns no points
        // since 0.11.0 (decision 0036): having a completed scan is the condition for a grade at all.
        if (!hasAttestation) {
            recommendations.add("Complete a scan: no in-toto attestation can be issued for a target never scanned.");
        }

        if (kevCount > 0) {
            recommendations.add("Urgent: Eliminate " + kevCount + " actively exploited CISA KEV vulnerability(ies).");
        }
        if (criticalCount > 0) {
            recommendations.add("Prioritize resolution of " + criticalCount + " critical severity issue(s).");
        }
        if (highCount > 0) {
            recommendations.add("Schedule remediation of " + highCount + " high severity issue(s).");
        }
        // Counted and advised on, not scored. The grade is what a public badge carries, and a
        // deadline is a deployment's own setting: two installs holding identical backlogs would
        // display different grades, and changing a window would move every badge overnight.
        // The figure is the one `SlaService` gives the dashboard and the overdue list, so the
        // three agree; it used to be declared here, never assigned, and reported as zero.
        if (overdueCount > 0) {
            recommendations.add("Resolve " + overdueCount + " issue(s) past their remediation deadline.");
        }
        // **The coverage cap, the compliance controls' own (`ComplianceEngine.withCoverage`).** A
        // target nobody scanned has no score to lend its scope, so the weakest observed target of ten
        // with one scanned clean would read A+ for nine that nobody looked at. Capped at the observed
        // share, in the compliance summary's rounding, so the card and the controls beside it on a
        // project's page tell the same story about the same coverage.
        int never = coverage.total() - coverage.observed();
        if (coverage.observed() > 0 && never > 0) {
            recommendations.add(0, "Scan the " + never + " target(s) never scanned: the score covers "
                    + coverage.observed() + "/" + coverage.total() + " target(s), and is capped at that share.");
        }
        if (recommendations.isEmpty()) {
            recommendations.add("Maintain current posture with continuous automated scanning.");
        }

        // **Nothing observed is no grade at all** (decision 0007), not the hundred the formula gives
        // an empty backlog: a scope whose only target was never scanned read 100/100, A+, on its card
        // and on the badge. The counts stay, being true of what was read; the risk points go with the
        // score, as a figure of a grade that does not exist.
        boolean noData = coverage.observed() == 0 || uncapped == null;
        Integer score = noData ? null : cappedToCoverage(uncapped, coverage);
        SecurityGrade grade = noData ? SecurityGrade.NO_DATA : SecurityGrade.fromScore(score);

        return new SecurityScorecard(
                targetId,
                targetKind,
                targetName,
                score,
                grade,
                noData ? null : CandidateScore.riskPoints(open.weighed(licenseViolations), WEIGHTS),
                coverage.total(),
                coverage.observed(),
                criticalCount,
                highCount,
                kevCount,
                overdueCount,
                licenseViolations,
                hasAttestation,
                noData ? null : weakest,
                recommendations);
    }

    /**
     * Every issue the caller may see that still weighs on the grade; the open test stays in Java
     * because it always was there.
     *
     * <p><b>A settled triage is left out</b> — {@code not_affected} or {@code fixed}, the two
     * decisions that already stop an issue failing the gate. Counting them kept a target's grade
     * down after its team had argued each finding away, so the one screen meant to reward triage
     * punished it, and disagreed with the gate about the same rows. {@code pending_approval}
     * still counts: a dismissal nobody has approved is a request, not a decision. Filtered in the
     * clause, as {@code SlaService.overdue} does, so the grade and the overdue figure on the same
     * card leave out the same issues.
     */
    private static IssueFilters openWithin(Visibility allowed) {
        return new IssueFilters(null, null, null, null, null, null, false, false, null, true, Map.of(), allowed);
    }


    /**
     * A row attached to neither target is unclassifiable, and ranks nowhere: there is no card to
     * agree with.
     */
    private static ScanTarget targetOf(Object repoId, Object containerId) {
        if (repoId != null) {
            return new ScanTarget.Repository(((Number) repoId).longValue());
        }
        return containerId == null ? null : new ScanTarget.Container(((Number) containerId).longValue());
    }

}
