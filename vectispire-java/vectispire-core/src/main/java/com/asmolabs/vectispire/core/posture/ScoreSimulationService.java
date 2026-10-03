package com.asmolabs.vectispire.core.posture;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibleScope;
import com.asmolabs.vectispire.common.domain.scorecard.CandidateScore;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityGrade;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityScorecard;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.targets.SolutionQueryService;
import com.asmolabs.vectispire.core.targets.TargetNaming;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * <b>Experimental: a side-by-side of the production score and a candidate, so that changing the
 * formula is decided on figures.</b> Nothing here grades anything a card, a badge or the ranking
 * shows — they read {@link SecurityScorecardService} alone — and nothing is written: the parameters
 * live in the request and the answer is computed from the backlog as it stands.
 *
 * <p><b>Since 0.11.0 the production score is the candidate</b> (decision 0036, accepted): with every
 * parameter left out, a target's {@code current…} and {@code candidate…} columns agree, and a scope's
 * {@code current…} and {@code weakest…} do — the card grades a scope by its weakest link now. The
 * route stays for one release, for whoever still wants to try other weights on the estate, and is
 * retired in the next with the candidate's name.
 *
 * <p>Every target the caller may see that its card grades ({@link SecurityScorecardService#gradeEach})
 * is listed with both scores. The current one is that computation's, not a copy of it; the candidate
 * is {@link CandidateScore} over the same open, unsettled issues. A target its card reads {@code
 * NO_DATA} is {@code NO_DATA} under both — the candidate changes the arithmetic, not what counts as
 * observed. The candidate weighs the disallowed licences the card counts, as a term of the backlog:
 * the counts beside each row are what it weighs, and the risk points their weighted sum.
 *
 * <p><b>Every project and solution the caller sees is listed too</b>, as the tree would list it: the
 * current score its scope card gives ({@link SecurityScorecardService#getScopeScorecard}) beside the
 * candidate over the scope's backlog, with the card's coverage cap and {@code NO_DATA}. Both count a
 * scope's licences once ({@link SecurityScorecardService#candidateScopes}); until 0.11.0 the card
 * counted twice those of a scan naming one of the scope's images and one of its repositories, and
 * {@code currentDoubleCounted} said so — it reads false since the switch fixed it.
 *
 * <p><b>Both aggregations of a scope stay on each row</b>, as they were when decision 0036 chose
 * between them. The <em>sum</em> ({@code candidate…}, rejected) scores the scope's summed backlog, so a
 * scope of many reasonable targets reads lower than each of them — its grade depends on its size. The
 * <em>weakest link</em> ({@code weakest…}, the card's since 0.11.0) is the score of the scope's
 * lowest-scoring observed target, exactly as that target's own row reads it, then held at the scope's
 * observed share like the sum: a scope is no safer than its most exposed target, and ten clean targets
 * do not hide the one with an exploited critical. The risk points are the sum's under both — each issue
 * and each licence once — since they state what is open in the scope, not how it is graded.
 */
@Service
public class ScoreSimulationService {

    private final SecurityScorecardService scorecards;
    private final TargetNaming naming;
    private final SolutionQueryService solutions;

    public ScoreSimulationService(
            SecurityScorecardService scorecards, TargetNaming naming, SolutionQueryService solutions) {
        this.scorecards = scorecards;
        this.naming = naming;
        this.solutions = solutions;
    }

    /** The parameters the simulation ran with — the request's, the proposed ones where it set none. */
    public record ScoreSimulationWeights(
            double exploited, double critical, double high, double medium, double low, double licence, double k) {}

    /**
     * One target under both formulas.
     *
     * @param currentScore null exactly when {@code currentGrade} is {@code NO_DATA}, as on the card
     * @param candidateExact the candidate's unrounded, uncapped score, which still orders two targets
     *     both rounded to one; null with no data
     * @param candidateRiskPoints the weighted backlog {@code Σ wₛ·nₛ} the candidate score is computed
     *     from — what still moves inside F, where every score reads one; null with no data
     * @param exploited open, unsettled issues listed in CISA KEV, whatever their severity; counted in
     *     no severity column
     * @param medium an issue with no severity is counted here, as the ranking counts it
     * @param licences disallowed licence entries, the count the card charges
     */
    public record ScoreSimulationTarget(
            String targetKind,
            long targetId,
            String targetName,
            Integer currentScore,
            SecurityGrade currentGrade,
            Integer candidateScore,
            SecurityGrade candidateGrade,
            Double candidateExact,
            Double candidateRiskPoints,
            long exploited,
            long critical,
            long high,
            long medium,
            long low,
            long licences) {}

    /**
     * One project or solution under both formulas, over the targets of it the caller sees.
     *
     * @param kind {@code project} or {@code solution}
     * @param partial the scope holds targets the caller does not see; both scores cover the visible ones
     * @param observedTargets the visible targets holding a completed scan; below {@code targetCount} both
     *     scores are capped at the observed share
     * @param currentScore the scope card's, null exactly when {@code currentGrade} is {@code NO_DATA}
     * @param candidateRiskPoints uncapped; null with no data
     * @param licences the scope's disallowed licence entries, each counted once — the candidate's term
     * @param currentLicences the same entries as the scope card counts them today
     * @param currentDoubleCounted the card's licence count differs from the candidate's. Until 0.11.0
     *     the card summed its targets' inventories, and an image's includes the entries of scans naming
     *     a repository too, which that repository's inventory lists as well. False since the switch,
     *     which made the card count as the candidate does; kept so that a regression would show here
     * @param weakestScore the weakest-link variant: the lowest candidate score among the scope's
     *     observed visible targets, held at the observed share as {@code candidateScore} is; null
     *     exactly when {@code weakestGrade} is {@code NO_DATA}, which is when nothing is observed
     * @param weakestTarget the target that score is read from; null with no data. Among targets of one
     *     score, the one with the more risk points, as the card chooses; then the first in the {@code
     *     targets} order
     */
    public record ScoreSimulationScope(
            String kind,
            long id,
            String name,
            boolean partial,
            int targetCount,
            int observedTargets,
            Integer currentScore,
            SecurityGrade currentGrade,
            Integer candidateScore,
            SecurityGrade candidateGrade,
            Double candidateExact,
            Double candidateRiskPoints,
            long exploited,
            long critical,
            long high,
            long medium,
            long low,
            long licences,
            long currentLicences,
            boolean currentDoubleCounted,
            Integer weakestScore,
            SecurityGrade weakestGrade,
            ScoreSimulationWeakestTarget weakestTarget) {}

    /**
     * The target a scope's weakest-link score is read from — one of the scope's targets the caller
     * sees, listed among the response's {@code targets} with the same kind, id and name.
     */
    public record ScoreSimulationWeakestTarget(String targetKind, long targetId, String targetName) {}

    /** How many of the listed targets read this grade under each formula. */
    public record ScoreSimulationGrade(SecurityGrade grade, long current, long candidate) {}

    /**
     * @param grades the targets' — every grade, {@code NO_DATA} included, in the scale's order; a zero
     *     row stays
     * @param scopes projects, then solutions, each by name
     */
    public record ScoreSimulation(
            ScoreSimulationWeights weights,
            List<ScoreSimulationTarget> targets,
            List<ScoreSimulationGrade> grades,
            List<ScoreSimulationScope> scopes) {}

    /**
     * Both scores for every target, project and solution the caller may see.
     *
     * <p>Each parameter left out takes its value in {@link CandidateScore.Weights#PROPOSED}; one that
     * is negative, not finite, or a {@code k} that is not positive is refused in words.
     */
    public ScoreSimulation simulate(
            VisibilityService.Allowance allowance,
            Double exploited,
            Double critical,
            Double high,
            Double medium,
            Double low,
            Double licence,
            Double k) {
        CandidateScore.Weights proposed = CandidateScore.Weights.PROPOSED;
        CandidateScore.Weights weights = new CandidateScore.Weights(
                Objects.requireNonNullElse(exploited, proposed.exploited()),
                Objects.requireNonNullElse(critical, proposed.critical()),
                Objects.requireNonNullElse(high, proposed.high()),
                Objects.requireNonNullElse(medium, proposed.medium()),
                Objects.requireNonNullElse(low, proposed.low()),
                Objects.requireNonNullElse(licence, proposed.licence()),
                Objects.requireNonNullElse(k, proposed.k()));

        Visibility allowed = allowance.visibility();
        Map<ScanTarget, SecurityScorecardService.TargetGrade> current = scorecards.gradeEach(allowed);
        Map<ScanTarget, CandidateScore.Counts> counts = scorecards.candidateCounts(allowed);

        List<ScanTarget> listed = current.keySet().stream()
                .sorted(Comparator.comparing((ScanTarget target) -> target instanceof ScanTarget.Container)
                        .thenComparing(ScoreSimulationService::idOf))
                .toList();
        TargetNaming.Names names = naming.forIds(
                listed.stream().map(t -> t instanceof ScanTarget.Repository r ? r.id() : null).filter(Objects::nonNull).toList(),
                listed.stream().map(t -> t instanceof ScanTarget.Container c ? c.id() : null).filter(Objects::nonNull).toList());

        Map<SecurityGrade, long[]> tally = new EnumMap<>(SecurityGrade.class);
        for (SecurityGrade grade : SecurityGrade.values()) {
            tally.put(grade, new long[2]);
        }

        List<ScoreSimulationTarget> rows = new ArrayList<>();
        for (ScanTarget target : listed) {
            SecurityScorecardService.TargetGrade before = current.get(target);
            CandidateScore.Counts open = counts.getOrDefault(target, CandidateScore.Counts.NONE);
            boolean noData = before.grade() == SecurityGrade.NO_DATA;
            CandidateScore.Result after = noData ? null : CandidateScore.of(open, weights);
            SecurityGrade afterGrade = noData ? SecurityGrade.NO_DATA : after.grade();
            tally.get(before.grade())[0]++;
            tally.get(afterGrade)[1]++;

            Long repoId = target instanceof ScanTarget.Repository r ? r.id() : null;
            Long containerId = target instanceof ScanTarget.Container c ? c.id() : null;
            rows.add(new ScoreSimulationTarget(
                    names.kindOf(containerId),
                    idOf(target),
                    names.of(repoId, containerId),
                    before.score(),
                    before.grade(),
                    noData ? null : after.score(),
                    afterGrade,
                    noData ? null : CandidateScore.exact(open, weights),
                    noData ? null : after.riskPoints(),
                    open.exploited(),
                    open.critical(),
                    open.high(),
                    open.medium(),
                    open.low(),
                    open.licences()));
        }

        List<ScoreSimulationGrade> grades = new ArrayList<>();
        tally.forEach((grade, pair) -> grades.add(new ScoreSimulationGrade(grade, pair[0], pair[1])));
        return new ScoreSimulation(
                new ScoreSimulationWeights(weights.exploited(), weights.critical(), weights.high(), weights.medium(),
                        weights.low(), weights.licence(), weights.k()),
                rows,
                grades,
                scopes(allowance, weights, targetRows(listed, rows)));
    }

    /** Each listed target's row, under its target — what the weakest link is chosen among. */
    private static Map<ScanTarget, ScoreSimulationTarget> targetRows(List<ScanTarget> listed, List<ScoreSimulationTarget> rows) {
        Map<ScanTarget, ScoreSimulationTarget> byTarget = new LinkedHashMap<>();
        for (int i = 0; i < listed.size(); i++) {
            byTarget.put(listed.get(i), rows.get(i));
        }
        return byTarget;
    }

    /**
     * The scope's lowest-scoring observed target, its row as the {@code targets} list carries it.
     *
     * <p>Only an observed target competes — a row with no candidate score is {@code NO_DATA}, never a
     * hundred — so a scope nothing of which is observed has no weakest link and reads {@code NO_DATA},
     * as under the sum. Chosen among the rows of the caller's own listing, and only for the scope's
     * targets that listing holds: the scope's targets are already the visible ones, and reading them
     * through the rows as well means the name returned is one the same response already shows — never
     * a target the scope's tree knows and the caller was not given.
     *
     * <p>Compared on the rounded, capped score, not the exact one: an exploited issue holds a target
     * at 54 whatever its exponent says, and the weakest link is the score a reader sees. A tie goes to
     * the target with the more risk points, as the scope's card breaks it, then to the first in the
     * listing's order, so the answer does not move from one call to the next.
     */
    private static Optional<ScoreSimulationTarget> weakestOf(
            VisibleScope scope, Map<ScanTarget, ScoreSimulationTarget> targetRows) {
        ScoreSimulationTarget weakest = null;
        for (Map.Entry<ScanTarget, ScoreSimulationTarget> entry : targetRows.entrySet()) {
            ScoreSimulationTarget row = entry.getValue();
            if (!scope.targets().contains(entry.getKey()) || row.candidateScore() == null) {
                continue;
            }
            if (weakest == null
                    || row.candidateScore() < weakest.candidateScore()
                    || (row.candidateScore().equals(weakest.candidateScore())
                            && row.candidateRiskPoints() > weakest.candidateRiskPoints())) {
                weakest = row;
            }
        }
        return Optional.ofNullable(weakest);
    }

    private List<ScoreSimulationScope> scopes(
            VisibilityService.Allowance allowance,
            CandidateScore.Weights weights,
            Map<ScanTarget, ScoreSimulationTarget> targetRows) {
        List<ScoreSimulationScope> rows = new ArrayList<>();
        for (SecurityScorecardService.ScopeCandidate after : scorecards.candidateScopes(solutions.visibleScopes(allowance), weights)) {
            VisibleScope scope = after.scope();
            // The weakest observed target's score, held at the scope's observed share as the sum is:
            // one scanned clean target beside nine nobody looked at is not an A+ under either.
            Optional<ScoreSimulationTarget> weakest = weakestOf(scope, targetRows);
            Integer weakestScore = weakest.map(row -> SecurityScorecardService.cappedToCoverage(
                            row.candidateScore(), after.totalTargets(), after.observedTargets()))
                    .orElse(null);
            // The scope card itself, as its compliance route serves it: the current figure is that
            // computation's, never a copy of its arithmetic.
            SecurityScorecard before = scorecards.getScopeScorecard(scope);
            CandidateScore.Counts open = after.counts();
            rows.add(new ScoreSimulationScope(
                    scope.kind().wireName(),
                    scope.id(),
                    scope.name(),
                    scope.partial(),
                    after.totalTargets(),
                    after.observedTargets(),
                    before.score(),
                    before.grade(),
                    after.score(),
                    after.grade(),
                    after.exact(),
                    after.riskPoints(),
                    open.exploited(),
                    open.critical(),
                    open.high(),
                    open.medium(),
                    open.low(),
                    open.licences(),
                    before.licenseViolationCount(),
                    before.licenseViolationCount() != open.licences(),
                    weakestScore,
                    weakestScore == null ? SecurityGrade.NO_DATA : SecurityGrade.fromScore(weakestScore),
                    weakest.map(row -> new ScoreSimulationWeakestTarget(row.targetKind(), row.targetId(), row.targetName()))
                            .orElse(null)));
        }
        rows.sort(Comparator.comparing((ScoreSimulationScope row) -> "solution".equals(row.kind()))
                .thenComparing(row -> row.name().toLowerCase(Locale.ROOT))
                .thenComparingLong(ScoreSimulationScope::id));
        return rows;
    }

    private static long idOf(ScanTarget target) {
        return switch (target) {
            case ScanTarget.Repository repository -> repository.id();
            case ScanTarget.Container container -> container.id();
        };
    }
}
