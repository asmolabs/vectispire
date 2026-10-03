package com.asmolabs.vectispire.core.checklists;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

/**
 * A rule bound to a checklist line, as the API states it — the one shape of every kind, each kind
 * taking its own fields and refusing the others' (decision 0032 §6). It is the stored canonical form's
 * shape too: a version's items carry that form as {@code boundRule}, which reads as this record.
 *
 * <ul>
 *   <li>{@code dependency_analysis}: {@code maxAgeDays}, {@code requireSchedule}, optional {@code thresholds}
 *       on the open vulnerabilities;
 *   <li>{@code findings_threshold}: {@code maxAgeDays}, {@code scopes} ({@code builtin:sast}, {@code
 *       builtin:secret}, {@code builtin:iac}, {@code builtin:vulnerability}, {@code builtin:quality}, {@code
 *       builtin:eol}, {@code builtin:license}, {@code plugin:<id>}, {@code import:<source>/<tool>}) and {@code
 *       thresholds};
 *   <li>{@code coverage_threshold}: {@code maxAgeDays}, {@code metric} ({@code line} or {@code branch}), {@code
 *       minimumRatio} (above 0, to 1), {@code aggregation} ({@code per_repository} or {@code project_weighted}) and
 *       an optional {@code scope} — the packages measured, {@code include} and {@code exclude} patterns over
 *       package paths; absent, the whole report;
 *   <li>{@code test_suite_passed}: {@code maxAgeDays}, {@code suitePattern} (a glob, {@code *} and {@code ?}) and
 *       {@code minimumTests};
 *   <li>{@code component_versions}: {@code maxAgeDays} and {@code components}, each a {@code purlPrefix} and its
 *       allowed {@code versions} — exact, or Maven ranges ({@code [1.17,2.0)}) on a {@code pkg:maven/} prefix;
 *   <li>{@code component_present}: {@code maxAgeDays} and {@code components}, each a {@code purlPrefix} alone —
 *       present whatever its version;
 *   <li>{@code change_review}: {@code maxAgeDays} — how old the forge's reading may be — {@code minimumApprovals}
 *       (approvals by people other than the author, 1 to 10), {@code windowDays} (how far back merged changes are
 *       counted, 1 to 366), {@code minimumRatio} (the share of them that must have the approvals, above 0 to 1)
 *       and an optional {@code branch}; absent, the default branch the forge names.
 * </ul>
 *
 * @param maxAgeDays how old the evidence may be, 1 to 366 — required of every kind
 * @param thresholds by severity ({@code critical}, {@code high}, {@code medium}, {@code low}, {@code negligible},
 *     {@code unknown}): {@code maxOpen} and/or {@code minResolvedRatio}, settled triage left out of both
 */
public record ChecklistRuleForm(
        String kind,
        Integer maxAgeDays,
        Boolean requireSchedule,
        List<String> scopes,
        Map<String, ThresholdForm> thresholds,
        String metric,
        BigDecimal minimumRatio,
        String aggregation,
        String suitePattern,
        Integer minimumTests,
        List<ComponentForm> components,
        CoverageScopeForm scope,
        Integer minimumApprovals,
        Integer windowDays,
        String branch) {

    /** @param minResolvedRatio resolved ÷ (resolved + open), 0 to 1, four decimals at most */
    public record ThresholdForm(Integer maxOpen, BigDecimal minResolvedRatio) {}

    /**
     * The packages a coverage rule measures: those an {@code include} pattern matches — every package
     * when none is given — and no {@code exclude} pattern does. Patterns are over package paths
     * ({@code org/example/service}, an lcov file's directory): {@code **} any number of whole segments,
     * {@code *} characters within one; nothing else is a wildcard. At least one pattern, at most twenty
     * in each list.
     */
    public record CoverageScopeForm(List<String> include, List<String> exclude) {}

    /**
     * @param purlPrefix a package URL without its version, {@code pkg:maven/com.example/ledger-core}, or a namespace,
     *     {@code pkg:maven/com.example}
     * @param versions the allowed versions of a {@code component_versions} rule; absent from a {@code
     *     component_present} one
     */
    public record ComponentForm(String purlPrefix, List<String> versions) {}
}
