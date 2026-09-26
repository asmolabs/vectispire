package com.asmolabs.vectispire.core.services.issues;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.core.repositories.IssueAggregates;
import com.asmolabs.vectispire.core.repositories.IssueFilters;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.OpenIssueCount;
import com.asmolabs.vectispire.core.services.targets.TargetBacklog;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** {@code targets}' {@link TargetBacklog}: the grouped counts its listings and its tree ran. */
@Service
public class TargetBacklogFigures implements TargetBacklog {

    private final Issues issues;

    public TargetBacklogFigures(Issues issues) {
        this.issues = issues;
    }

    @Override
    @Transactional(readOnly = true)
    public Map<Long, Long> openPerRepository() {
        return byTarget(issues.countOpenByRepository(IssueState.OPEN.wireName()));
    }

    @Override
    @Transactional(readOnly = true)
    public Map<Long, Long> openPerContainer() {
        return byTarget(issues.countOpenByContainer(IssueState.OPEN.wireName()));
    }

    /**
     * Through the scoreboard's own grouped count, so the tree and the scoreboard agree on what "open"
     * leaves out; a row attributed to no repository is an image's, and no image is in a project.
     */
    @Override
    @Transactional(readOnly = true)
    public Map<Long, Map<Severity, Long>> openBySeverityPerRepository(Visibility narrowed) {
        Map<Long, Map<Severity, Long>> counts = new HashMap<>();
        for (IssueAggregates.TargetSeverityCount row : issues.countOpenByTargetAndSeverity(
                new IssueFilters(null, null, null, null, null, null, false, false, null, true, Map.of(), narrowed)
                        .toSpecification())) {
            if (row.repoId() == null) {
                continue;
            }
            counts.computeIfAbsent(row.repoId(), id -> new EnumMap<>(Severity.class))
                    .merge(Severity.of(row.severity()), row.count(), Long::sum);
        }
        return counts;
    }

    private static Map<Long, Long> byTarget(List<OpenIssueCount> rows) {
        Map<Long, Long> counts = new HashMap<>();
        for (OpenIssueCount row : rows) {
            counts.put(row.targetId(), row.count());
        }
        return counts;
    }
}
