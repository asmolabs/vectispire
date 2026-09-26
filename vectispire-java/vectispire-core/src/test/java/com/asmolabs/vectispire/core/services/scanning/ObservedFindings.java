package com.asmolabs.vectispire.core.services.scanning;

import com.asmolabs.vectispire.core.persistence.FindingEntity;
import java.util.List;

/**
 * Finding rows as the backlog receives them, for the backlog's tests.
 *
 * <p>Those tests built {@code FindingEntity} fixtures and handed them to the sync, which read them;
 * since the sync receives {@link ObservedFinding} records (decision 0029) the fixtures go through the
 * one conversion the ingestion itself uses, so a test and a scan cannot hand the backlog two
 * different shapes of the same finding.
 */
public final class ObservedFindings {

    private ObservedFindings() {}

    public static ObservedFinding of(FindingEntity finding) {
        return ObservedFinding.of(finding);
    }

    public static List<ObservedFinding> of(List<FindingEntity> findings) {
        return findings.stream().map(ObservedFinding::of).toList();
    }
}
