package com.asmolabs.vectispire.core.posture;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibleScope;
import com.asmolabs.vectispire.common.domain.access.VisibleTarget;
import com.asmolabs.vectispire.common.domain.licenses.LicenseEntry;
import com.asmolabs.vectispire.common.domain.scorecard.CandidateScore;
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
import java.util.ArrayList;
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
 * Computes security posture scorecards and letter grades (A+ to F) for repositories, containers, and global portfolios.
 */
@Service
public class SecurityScorecardService {

    private final IssueCatalog issuesRepo;
    private final TargetCatalog targets;
    private final ScanCatalog scansRepo;
    private final LicenseGovernanceService licenseService;
    private final SlaService sla;

    public SecurityScorecardService(
            IssueCatalog issuesRepo,
            TargetCatalog targets,
            ScanCatalog scansRepo,
            LicenseGovernanceService licenseService,
            SlaService sla) {
        this.issuesRepo = issuesRepo;
        this.targets = targets;
        this.scansRepo = scansRepo;
        this.licenseService = licenseService;
        this.sla = sla;
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

            return computeScorecard(repoId, "repository", repo.name(), open, violations(licenses), hasAttestation,
                    overdue, Coverage.ofOne(hasAttestation));
        });
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

            return computeScorecard(containerId, "container", container.imageName() + ":" + container.tag(), open,
                    violations(licenses), hasAttestation, overdue, Coverage.ofOne(hasAttestation));
        });
    }

    /**
     * The portfolio's posture, <b>within the caller's allowance</b>.
     *
     * <p>"Organization Portfolio" is a fair name for an administrator and a false one for a
     * reader assigned two repositories: the score they were shown was the whole estate's, which
     * is both a leak and a number that means nothing about anything they can act on.
     */
    public SecurityScorecard getGlobalScorecard(Visibility allowed) {
        List<ScanTarget> visible = new ArrayList<>();
        targets.repositories().forEach(repository -> visible.add(new ScanTarget.Repository(repository.id())));
        targets.containers().forEach(container -> visible.add(new ScanTarget.Container(container.id())));
        visible.removeIf(target -> !allowed.permits(target));
        // **The licence term is the tallies' sum, not the estate's inventory.** It read every scan,
        // every component and every licence finding of the deployment and narrowed to the allowance
        // afterwards — about 105,000 entities a call on two hundred targets of two scans, for an
        // administrator and for a reader granted five alike. The count is the same: the inventory's
        // refused entries over what the reader sees, the scans attached to no target included for a
        // reader who sees everything, as they were.
        return portfolio(allowed, visible, licenseService.violationsWithin(allowed), null, "global",
                "Organization Portfolio");
    }

    /**
     * A project's or a solution's scorecard: the portfolio's computation, over the scope's visible
     * targets and nothing else — the same terms, the same weights, no formula of its own. A partial
     * scope is scored on what the caller sees, as the portfolio is for a restricted reader; the scope
     * says {@code partial} beside it.
     *
     * <p><b>The licences are read target by target</b>, each through the per-target inventory the
     * target's own scorecard reads, rather than through the portfolio's, which parses every SBOM of
     * the estate to keep a project's.
     *
     * <p><b>Known to count some licences twice</b>, kept until the formula's switch fixes it (decision
     * 0036): the lists are summed, not united, and an image's inventory holds the components and licence
     * findings of a scan naming it and a repository — keyed to the repository, whose list holds them as
     * well. A scope filing both targets charges those entries twice. {@link #candidateScopes} counts them
     * once, and {@code ScoreSimulationRoutesTest} pins both figures.
     *
     * @return {@code targetKind} {@code project} or {@code solution}, {@code targetId} the scope's
     */
    public SecurityScorecard getScopeScorecard(VisibleScope scope) {
        Visibility allowed = scope.visibility();
        List<LicenseEntry> licenses = scope.targets().stream()
                .flatMap(target -> licenseService.getInventory(RowVisibility.requireVisible(target, allowed)).stream())
                .toList();
        return portfolio(allowed, scope.targets(), violations(licenses), scope.id(), scope.kind().wireName(), scope.name());
    }

    /**
     * A target's score and grade as its own scorecard gives them, and the open counts a ranking
     * prints beside them.
     *
     * @param score null exactly when {@code grade} is {@link SecurityGrade#NO_DATA}
     * @param medium an issue with no severity is counted here, as the ranking always counted it; it
     *     weighs nothing on the score, which charges criticals, highs and KEV only
     */
    public record TargetGrade(
            Integer score, SecurityGrade grade, long critical, long high, long medium, long low) {

        /** A target listed for what it closed, holding no completed scan and nothing open. */
        public static final TargetGrade UNOBSERVED = new TargetGrade(null, SecurityGrade.NO_DATA, 0, 0, 0, 0);
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
     * <p>The same three reads as the portfolio's, each once for the whole allowance and none bound
     * per target: the grading counts grouped by target (the allowance written into the statement,
     * {@code IssueSpecifications.visible}), the completed scans' targets narrowed in Java, and each
     * target's licence violations. Those are the inventory's own count, which parsed every SBOM of the
     * estate at every load of the home page until the inventory kept a tally per target, recounted
     * when the target's scans move ({@code LicenseGovernanceService.violationsByTarget}). Without the
     * term a target's rank would disagree with its card by five points a violation.
     *
     * <p>A target holding neither an open issue nor a completed scan is absent from the map; a caller
     * listing one anyway — for what it closed — grades it {@link TargetGrade#UNOBSERVED}.
     */
    public Map<ScanTarget, TargetGrade> gradeEach(Visibility allowed) {
        Map<ScanTarget, List<IssueAggregates.TargetGradingCount>> rows = new LinkedHashMap<>();
        for (IssueAggregates.TargetGradingCount row : issuesRepo.countForGradingByTarget(openWithin(allowed))) {
            ScanTarget target = targetOf(row.repoId(), row.containerId());
            if (target != null && Terms.isOpen(row.state())) {
                rows.computeIfAbsent(target, key -> new ArrayList<>()).add(row);
            }
        }

        // Narrowed here, since the scans' targets are the estate's: listing a clean target is
        // listing it, and a reader must not learn of one they were not given.
        Set<ScanTarget> observed = new HashSet<>();
        scansRepo.targetsWithStatus("completed").forEach(row -> {
            if (row.target() != null && allowed.permits(row.target())) {
                observed.add(row.target());
            }
        });

        Map<ScanTarget, Long> violations = licenseService.violationsByTarget(allowed);

        Set<ScanTarget> graded = new LinkedHashSet<>(rows.keySet());
        graded.addAll(observed);

        Map<ScanTarget, TargetGrade> grades = new LinkedHashMap<>();
        for (ScanTarget target : graded) {
            Terms open = Terms.of(rows.getOrDefault(target, List.of()));
            boolean scanned = observed.contains(target);
            // The card's own computation, not a copy of its arithmetic: the name and the overdue
            // figure enter the recommendations only, which the ranking does not show.
            SecurityScorecard card = computeScorecard(null, null, null, open, violations.getOrDefault(target, 0L),
                    scanned, 0, Coverage.ofOne(scanned));
            grades.put(target, new TargetGrade(
                    card.score(), card.grade(), open.critical(), open.high(), open.medium(), open.low()));
        }
        return grades;
    }

    /**
     * <b>Experimental, for the score simulation only</b> ({@link ScoreSimulationService}): every
     * visible target's open backlog in the classes {@link CandidateScore} weighs — read through the
     * same grouped query, the same allowance and the same open-and-unsettled rule as {@link #gradeEach},
     * so that the two formulas are compared on the same issues. An exploited issue is counted as
     * exploited and under no severity; an issue with no severity is a medium, as the ranking counts it;
     * a severity neither critical, high nor medium is a low.
     *
     * <p><b>The licences are the card's own count</b>, read from the same tally {@link #gradeEach}
     * charges five points apiece ({@code LicenseGovernanceService.violationsByTarget}) — never counted
     * a second way here, or the two formulas would be compared on different licences.
     *
     * <p>A target with nothing open and no disallowed licence is absent; the caller reads it as
     * {@link CandidateScore.Counts#NONE}.
     */
    public Map<ScanTarget, CandidateScore.Counts> candidateCounts(Visibility allowed) {
        Map<ScanTarget, long[]> sums = new LinkedHashMap<>();
        for (IssueAggregates.TargetGradingCount row : issuesRepo.countForGradingByTarget(openWithin(allowed))) {
            ScanTarget target = targetOf(row.repoId(), row.containerId());
            if (target == null || !Terms.isOpen(row.state())) {
                continue;
            }
            sums.computeIfAbsent(target, key -> new long[6])[candidateSlot(row)] += row.count();
        }
        licenseService.violationsByTarget(allowed).forEach((target, refused) -> {
            if (refused > 0) {
                sums.computeIfAbsent(target, key -> new long[6])[5] += refused;
            }
        });
        Map<ScanTarget, CandidateScore.Counts> counts = new LinkedHashMap<>();
        sums.forEach((target, sum) ->
                counts.put(target, new CandidateScore.Counts(sum[0], sum[1], sum[2], sum[3], sum[4], sum[5])));
        return counts;
    }

    /**
     * The candidate's class of a grading row: 0 exploited, whatever its severity; 1 critical; 2 high;
     * 3 medium or no severity, as the ranking counts it; 4 anything else. Slot 5 is the licences'.
     */
    private static int candidateSlot(IssueAggregates.TargetGradingCount row) {
        String severity = row.severity() == null ? null : row.severity().toUpperCase(Locale.ROOT);
        if (row.kev()) {
            return 0;
        } else if ("CRITICAL".equals(severity)) {
            return 1;
        } else if ("HIGH".equals(severity)) {
            return 2;
        } else if (severity == null || "MEDIUM".equals(severity)) {
            return 3;
        }
        return 4;
    }

    /**
     * A project or a solution under the candidate, for the simulation only.
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
     * <b>Experimental, for the score simulation only</b>: each scope graded by the candidate, the
     * scope's card's coverage cap and {@code NO_DATA} kept as they are ({@link #getScopeScorecard}).
     *
     * <p><b>Counted once per scope, which the scope's card does not do.</b> The card sums its targets'
     * inventories, and the inventory of an image includes the components and licence findings of every
     * scan naming that image <em>and</em> a repository — keyed to the repository, which lists them as
     * well. A project filing both counts those entries twice, five points apiece. Here the licence term
     * is the sum of the targets' tallies ({@code LicenseGovernanceService.violationsByTarget}, which
     * {@link #gradeEach} and so each target's ranking charge): every entry belongs to exactly one target,
     * the one its scan is attributed to. The issues are the scope's grouped count, one row per issue
     * however many of the scope's targets it names — as the card already reads them.
     *
     * <p>The production path is left as it is until the formula is switched (decision 0036), which
     * fixes it there; the simulation shows both figures beside each other.
     */
    public List<ScopeCandidate> candidateScopes(List<VisibleScope> scopes, CandidateScore.Weights weights) {
        Set<ScanTarget> every = new LinkedHashSet<>();
        scopes.forEach(scope -> every.addAll(scope.targets()));
        // One read of the tallies and of the completed scans for every scope, both narrowed to the
        // scopes' visible targets — what each scope's own read would have been, summed.
        Map<ScanTarget, Long> violations = licenseService.violationsByTarget(Visibility.only(List.copyOf(every)));
        Set<ScanTarget> completed = new HashSet<>();
        scansRepo.targetsWithStatus("completed").forEach(row -> {
            if (row.target() != null && every.contains(row.target())) {
                completed.add(row.target());
            }
        });

        List<ScopeCandidate> graded = new ArrayList<>();
        for (VisibleScope scope : scopes) {
            long[] sum = new long[6];
            for (IssueAggregates.TargetGradingCount row : issuesRepo.countForGradingByTarget(openWithin(scope.visibility()))) {
                if (Terms.isOpen(row.state())) {
                    sum[candidateSlot(row)] += row.count();
                }
            }
            for (ScanTarget target : scope.targets()) {
                sum[5] += violations.getOrDefault(target, 0L);
            }
            CandidateScore.Counts counts = new CandidateScore.Counts(sum[0], sum[1], sum[2], sum[3], sum[4], sum[5]);
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

    /** How many entries of an inventory the policy refuses: five points each on the score. */
    private static long violations(List<LicenseEntry> licenses) {
        return licenses.stream().filter(l -> !l.compliant()).count();
    }

    /**
     * The open backlog's terms, counted as the card has always counted its rows.
     *
     * <p>An issue is open when its state is neither {@code closed} nor {@code resolved}, ignoring
     * case — a null state included; its severity is upper-cased, and only {@code CRITICAL} and
     * {@code HIGH} weigh. KEV is counted whatever the severity, on top of it.
     */
    private record Terms(long critical, long high, long medium, long low, long kev) {

        static boolean isOpen(String state) {
            return !"closed".equalsIgnoreCase(state) && !"resolved".equalsIgnoreCase(state);
        }

        static Terms of(List<IssueAggregates.TargetGradingCount> rows) {
            long critical = 0;
            long high = 0;
            long medium = 0;
            long low = 0;
            long kev = 0;
            for (IssueAggregates.TargetGradingCount row : rows) {
                if (!isOpen(row.state())) {
                    continue;
                }
                if (row.kev()) {
                    kev += row.count();
                }
                String severity = row.severity() == null ? null : row.severity().toUpperCase(Locale.ROOT);
                if ("CRITICAL".equals(severity)) {
                    critical += row.count();
                } else if ("HIGH".equals(severity)) {
                    high += row.count();
                } else if (severity == null || "MEDIUM".equals(severity)) {
                    medium += row.count();
                } else {
                    low += row.count();
                }
            }
            return new Terms(critical, high, medium, low, kev);
        }
    }

    private SecurityScorecard portfolio(
            Visibility allowed, List<ScanTarget> visible, long licenseViolations, Long id, String kind, String name) {
        Terms open = Terms.of(issuesRepo.countForGradingByTarget(openWithin(allowed)));

        // The targets in scope holding a completed scan — which is also what the attestation flag
        // asked, over the same allowance, so the two cannot disagree.
        Set<ScanTarget> inScope = new HashSet<>(visible);
        Set<ScanTarget> observed = new HashSet<>();
        scansRepo.targetsWithStatus("completed").forEach(row -> {
            if (row.target() != null && inScope.contains(row.target())) {
                observed.add(row.target());
            }
        });

        long overdue = sla.countOverdue(allowed);

        return computeScorecard(id, kind, name, open, licenseViolations, !observed.isEmpty(), overdue,
                new Coverage(inScope.size(), observed.size()));
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
     * and holds it at the scope's observed share exactly as the card and the summed candidate are held.
     */
    static int cappedToCoverage(int score, int totalTargets, int observedTargets) {
        return cappedToCoverage(score, new Coverage(totalTargets, observedTargets));
    }

    /**
     * A score held at the observed share of its scope, in the compliance summary's rounding — one copy
     * for the card and for the candidate's scopes, so the simulation caps as the card does.
     */
    private static int cappedToCoverage(int score, Coverage coverage) {
        int never = coverage.total() - coverage.observed();
        return never > 0
                ? Math.min(score, Math.round(((float) coverage.observed() / coverage.total()) * 100))
                : score;
    }

    private SecurityScorecard computeScorecard(
            Long targetId,
            String targetKind,
            String targetName,
            Terms open,
            long licenseViolations,
            boolean hasAttestation,
            long overdueCount,
            Coverage coverage) {

        // A long until it is clamped: the terms are counts the estate sizes, summed before the clamp
        // rather than subtracted issue by issue, and an int would wrap long before a long does.
        long score = 100;
        List<String> recommendations = new ArrayList<>();

        long criticalCount = open.critical();
        long highCount = open.high();
        long kevCount = open.kev();

        score -= kevCount * 25 + criticalCount * 8 + highCount * 4;
        // **One weight for every critical, since nothing measures reachability.** A reachable
        // critical cost 15 and any other 8, read off a column no analysis writes: every issue reads
        // UNKNOWN, so the 15 was never charged and the term only promised a distinction the grade
        // could not make. Were it charged — a row edited by hand, an import that one day sets the
        // column — it would move a public badge on a claim nobody established.

        if (licenseViolations > 0) {
            score -= licenseViolations * 5;
            recommendations.add("Remediate " + licenseViolations + " disallowed open source license violation(s).");
        }

        // **What "attestation" means here, and what the advice used to get wrong.** The in-toto
        // statement is issued on demand, from any completed scan, by `AttestationService`; nothing
        // is generated or stored beforehand. So the flag is true exactly when a scan has
        // completed, and the only way to earn it is to complete one. The recommendation told
        // people to "generate in-toto provenance attestations" — a step that does not exist in
        // this product, sending the reader to look for a button nobody built.
        if (hasAttestation) {
            score += 5;
        } else {
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
        // **The coverage cap, the compliance controls' own (`ComplianceEngine.withCoverage`).** The
        // score is a hundred less what was found, so a target nobody scanned weighs as a clean one:
        // ten targets with one scanned clean read A+ for nine that nobody looked at. Capped at the
        // observed share, in the compliance summary's rounding, so the card and the controls beside
        // it on a project's page tell the same story about the same coverage.
        int never = coverage.total() - coverage.observed();
        if (coverage.observed() > 0 && never > 0) {
            recommendations.add(0, "Scan the " + never + " target(s) never scanned: the score covers "
                    + coverage.observed() + "/" + coverage.total() + " target(s), and is capped at that share.");
        }
        if (recommendations.isEmpty()) {
            recommendations.add("Maintain current posture with continuous automated scanning.");
        }

        int clamped = cappedToCoverage((int) Math.max(0, Math.min(100, score)), coverage);
        // **Nothing observed is no grade at all** (decision 0007), not the hundred the formula gives
        // an empty backlog: a scope whose only target was never scanned read 100/100, A+, on its card
        // and on the badge. The counts stay, being true of what was read.
        boolean noData = coverage.observed() == 0;
        SecurityGrade grade = noData ? SecurityGrade.NO_DATA : SecurityGrade.fromScore(clamped);

        return new SecurityScorecard(
                targetId,
                targetKind,
                targetName,
                noData ? null : clamped,
                grade,
                coverage.total(),
                coverage.observed(),
                criticalCount,
                highCount,
                kevCount,
                overdueCount,
                licenseViolations,
                hasAttestation,
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
