package com.asmolabs.vectispire.core.compliance;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.compliance.ScopeCoverage;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.persistence.queries.LatestScanRow;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * How much of the certified scope carries current evidence.
 *
 * <p>The reasoning is on {@link ScopeCoverage}; what is here is the reading. Two things are worth
 * saying about it.
 *
 * <p><b>The declared count is not narrowed by the caller's allowance, and the rest is.</b> A scope
 * statement covers what it covers whoever is looking, so a restricted reader is shown the same
 * denominator and their own slice of the numerator — which makes their figure worse than the
 * estate's, and that is correct: a reader who cannot see two thirds of the scope has not been told
 * that two thirds of it is fine.
 *
 * <p><b>A target with no scan row at all is counted apart from a stale one.</b> Folded together
 * they read as "not current", and the two are different states: a target scanned a year ago
 * produced evidence once and can be shown to have been looked at, while one never scanned has
 * never been examined and is the row an assessment picks out.
 */
@Service
public class CertifiedScopeService {

    private final TargetCatalog targets;
    private final ScanCatalog scans;
    private final SettingsService settings;
    private final Clock clock;
    private final AuditLogService audit;

    public CertifiedScopeService(
            TargetCatalog targets,
            ScanCatalog scans,
            SettingsService settings,
            Clock clock,
            AuditLogService audit) {
        this.targets = targets;
        this.scans = scans;
        this.settings = settings;
        this.clock = clock;
        this.audit = audit;
    }

    /** What the scope statement says, verbatim, or empty when nobody has written one. */
    public String statement() {
        return settings.get(Setting.ISMS_SCOPE_STATEMENT);
    }

    /**
     * The coverage of the certified scope, within the caller's allowance.
     *
     * <p>The freshness window is the one the compliance evaluation already uses, so the two agree
     * on what "recently" means. Zero there disables the cap for the frameworks; here it would
     * leave nothing to measure, so it falls back to the setting's own default rather than
     * reporting every target as current.
     */
    @Transactional(readOnly = true)
    public ScopeCoverage coverage(Visibility allowed) {
        Set<ScanTarget> inScope = inScope(allowed);

        Map<ScanTarget, Instant> lastScan = new HashMap<>();
        collect(scans.latestPerRepository(), ScanTarget.Repository::new, lastScan);
        collect(scans.latestPerContainer(), ScanTarget.Container::new, lastScan);

        Instant cutoff = clock.instant().minus(Duration.ofDays(freshnessDays()));

        int fresh = 0;
        int stale = 0;
        int never = 0;
        for (ScanTarget target : inScope) {
            Instant last = lastScan.get(target);
            if (last == null) {
                never++;
            } else if (last.isBefore(cutoff)) {
                stale++;
            } else {
                fresh++;
            }
        }

        return new ScopeCoverage(
                Math.max(0, settings.asInt(Setting.ISMS_SCOPE_ASSETS)), inScope.size(), fresh, stale, never);
    }

    /** The targets marked as belonging to the certified scope that the caller may see. */
    @Transactional(readOnly = true)
    public Set<ScanTarget> inScope(Visibility allowed) {
        return java.util.stream.Stream.concat(
                        targets.repositories().stream()
                                .filter(row -> row.inCertifiedScope())
                                .<ScanTarget>map(row -> new ScanTarget.Repository(row.id())),
                        targets.containers().stream()
                                .filter(row -> row.inCertifiedScope())
                                .<ScanTarget>map(row -> new ScanTarget.Container(row.id())))
                .filter(allowed::permits)
                .collect(Collectors.toCollection(java.util.LinkedHashSet::new));
    }

    /**
     * Puts one target in or out of the certified scope, and records who did when the flag moved.
     *
     * <p><b>No transaction here</b>, and that is the point: the write commits in {@code
     * TargetCatalog}'s own before the entry is written, since the audit log opens its own and on
     * SQLite would wait on the write's file lock. A no-op leaves no entry, as a setting saved
     * unchanged leaves none.
     *
     * <p>A target that does not exist is refused in the words a hidden one gets — the route has
     * already refused those — so an id nobody registered is a 404, not a 200 for a write to nothing.
     *
     * @return whether the flag changed
     */
    public boolean setInScope(ScanTarget target, boolean inScope, RequestActor actor) {
        TargetCatalog.ScopeChange outcome = targets.setInCertifiedScope(target, inScope);
        if (outcome == TargetCatalog.ScopeChange.ABSENT) {
            // Handed to the guard as an absent row, so it throws the one sentence it has.
            RowVisibility.requireVisible(Optional.empty(), target, Visibility.everything());
        }
        boolean changed = outcome == TargetCatalog.ScopeChange.CHANGED;
        if (changed) {
            audit.record(actor.entry(
                    AuditOperation.CERTIFIED_SCOPE_CHANGED,
                    String.valueOf(idOf(target)),
                    describe(target) + (inScope ? " put in the certified scope" : " taken out of the certified scope")));
        }
        return changed;
    }

    private static long idOf(ScanTarget target) {
        return switch (target) {
            case ScanTarget.Repository repository -> repository.id();
            case ScanTarget.Container container -> container.id();
        };
    }

    private static String describe(ScanTarget target) {
        return switch (target) {
            case ScanTarget.Repository repository -> "Repository " + repository.id();
            case ScanTarget.Container container -> "Image " + container.id();
        };
    }

    private int freshnessDays() {
        int configured = settings.asInt(Setting.COMPLIANCE_FRESHNESS_DAYS);
        return configured > 0 ? configured : 30;
    }

    private static void collect(
            List<LatestScanRow> rows,
            java.util.function.LongFunction<ScanTarget> target,
            Map<ScanTarget, Instant> into) {
        for (LatestScanRow row : rows) {
            if (row.targetId() != null && row.createdAt() != null) {
                into.merge(
                        target.apply(row.targetId()),
                        row.createdAt(),
                        (first, second) -> first.isAfter(second) ? first : second);
            }
        }
    }
}
