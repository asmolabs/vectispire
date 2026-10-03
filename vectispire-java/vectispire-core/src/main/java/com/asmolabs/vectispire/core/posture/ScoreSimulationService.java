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
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.Objects;
import org.springframework.stereotype.Service;

/**
 * <b>Experimental: a side-by-side of the production score and a candidate, so that changing the
 * formula is decided on figures.</b> Nothing here grades anything a card, a badge or the ranking
 * shows — they read {@link SecurityScorecardService} alone — and nothing is written: the parameters
 * live in the request and the answer is computed from the backlog as it stands.
 *
 * <p>Every target the caller may see that its card grades ({@link SecurityScorecardService#gradeEach})
 * is listed with both scores. The current one is that computation's, not a copy of it; the candidate
 * is {@link CandidateScore} over the same open, unsettled issues. A target its card reads {@code
 * NO_DATA} is {@code NO_DATA} under both — the candidate changes the arithmetic, not what counts as
 * observed. The candidate weighs the disallowed licences the card counts, as a term of the backlog,
 * and drops the production bonus for a completed scan: the counts beside each row are what it weighs,
 * and the risk points their weighted sum.
 *
 * <p><b>Every project and solution the caller sees is listed too</b>, as the tree would list it: the
 * current score its scope card gives ({@link SecurityScorecardService#getScopeScorecard}) beside the
 * candidate over the scope's backlog, with the card's coverage cap and {@code NO_DATA}. The candidate
 * counts a scope's licences once ({@link SecurityScorecardService#candidateScopes}); the card counts
 * twice those of a scan naming one of the scope's images and one of its repositories, and the row says
 * so, so that the switch fixes it knowingly.
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
     * @param currentDoubleCounted the card's licence count differs from the candidate's: it sums its
     *     targets' inventories, and an image's includes the entries of scans naming a repository too,
     *     which that repository's inventory lists as well — or, its repository outside the scope, which
     *     the candidate leaves to the repository they belong to. The switch to the candidate fixes it
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
            boolean currentDoubleCounted) {}

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
                scopes(allowance, weights));
    }

    private List<ScoreSimulationScope> scopes(VisibilityService.Allowance allowance, CandidateScore.Weights weights) {
        List<ScoreSimulationScope> rows = new ArrayList<>();
        for (SecurityScorecardService.ScopeCandidate after : scorecards.candidateScopes(solutions.visibleScopes(allowance), weights)) {
            VisibleScope scope = after.scope();
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
                    before.licenseViolationCount() != open.licences()));
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
