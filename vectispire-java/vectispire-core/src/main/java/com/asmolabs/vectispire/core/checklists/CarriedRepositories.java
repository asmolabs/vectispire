package com.asmolabs.vectispire.core.checklists;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.checklists.Measurement;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistMeasurementEntity;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

/**
 * The repositories a revision's stored measurements carry, and who may read what was frozen over them.
 *
 * <p><b>A submission and a sign-off are evidence of a moment, and the project moves after it.</b> Their
 * measurements were stored with the evidence of every repository the project held then — each one's
 * scan, its date, its figures — and the signed package, the frozen measurements and the statement a
 * project export embeds were served to whoever saw the project whole <em>now</em>. A repository taken out
 * of the project since left its evidence in all three, for a reader who was never shown it. The project's
 * rule still applies; this is the second one, as for a report run's document (decision 0042).
 *
 * <p><b>Read from the evidence, not from a second record.</b> Each stored measurement names, in the
 * evidence its digest covers, every repository it read: a measurement's figures and its summary are
 * gathered repository by repository, each one entered in the evidence as it is read
 * ({@code RuleEvaluation}), so the repositories a row names are exactly the ones whose data it carries. A
 * column written beside it would say the same thing twice, and would have had nothing to say for the
 * revisions submitted before it — which their evidence answers like any other.
 */
final class CarriedRepositories {

    private CarriedRepositories() {}

    /**
     * Every repository the rows' evidence names, or empty when one of them cannot be read back.
     *
     * <p>An unreadable evidence is not "no repository" (decision 0007): it says nothing of what it
     * carried, and reading it as fewer repositories would serve it to readers it was never shown to.
     */
    static Optional<Set<Long>> of(Collection<ChecklistMeasurementEntity> rows) {
        Set<Long> repositories = new LinkedHashSet<>();
        for (ChecklistMeasurementEntity row : rows) {
            try {
                Measurement.read(row.getEvidence()).repositories()
                        .forEach(repository -> repositories.add(repository.repositoryId()));
            } catch (RuntimeException unreadable) {
                return Optional.empty();
            }
        }
        return Optional.of(Set.copyOf(repositories));
    }

    /**
     * Whether this reader sees every repository carried — or, when that cannot be told, sees everything
     * through a credential that narrows nothing.
     */
    static boolean seenBy(Optional<Set<Long>> carried, VisibilityService.Allowance allowance) {
        Visibility visibility = allowance.visibility();
        if (carried.isEmpty()) {
            return visibility instanceof Visibility.Everything && !allowance.narrowedByCredential();
        }
        return carried.get().stream().map(ScanTarget.Repository::new).allMatch(visibility::permits);
    }
}
