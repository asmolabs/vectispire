package com.asmolabs.zanshin.common.domain.gate;

import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;

/**
 * The slice of an issue a verdict looks at.
 *
 * <p>Deliberately not the persistence entity. The evaluation is a pure calculation and must
 * stay testable by writing eight fields down, not by standing up a database.
 *
 * @param open whether the issue is still open; a closed one never counts
 * @param triage where it stands with the humans, or {@code null} if nobody has looked
 * @param fixVersions the published fix, if any; blank and absent mean the same thing
 */
public record GateIssue(
        long id,
        boolean open,
        FindingType type,
        Severity severity,
        String identifier,
        String packageName,
        String fixVersions,
        boolean kev,
        TriageStatus triage) {

    public GateIssue {
        severity = severity == null ? Severity.UNKNOWN : severity;
    }

    boolean hasPublishedFix() {
        return fixVersions != null && !fixVersions.isBlank();
    }
}
