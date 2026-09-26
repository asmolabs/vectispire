package com.asmolabs.vectispire.core.targets;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import java.util.Map;

/**
 * The open-issue figures the target screens show beside each row and in the solutions tree.
 *
 * <p><b>A port, implemented by {@code issues}</b>, for the reason {@link TargetScans} gives: the
 * listings counted issues through the issues' repository while {@code issues} reads the targets for
 * their names — the two used each other. {@code issues} → {@code targets} is the direction kept
 * (decision 0029); the figures are asked here.
 */
public interface TargetBacklog {

    /** Open issues per repository, settled triage included — the count the repository list shows. */
    Map<Long, Long> openPerRepository();

    /** The same per image. */
    Map<Long, Long> openPerContainer();

    /**
     * The open backlog per repository and severity, <b>settled triage left out</b> — the solutions
     * tree's figures — for the repositories {@code narrowed} permits. Containers are not counted: no
     * image is in a project.
     */
    Map<Long, Map<Severity, Long>> openBySeverityPerRepository(Visibility narrowed);
}
