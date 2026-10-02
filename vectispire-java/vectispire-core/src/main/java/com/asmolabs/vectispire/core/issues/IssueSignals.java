package com.asmolabs.vectispire.core.issues;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.siem.CefEvent;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventType;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import java.time.Duration;
import java.time.Instant;

/**
 * The SIEM events the backlog itself raises, as the SOC reads them.
 *
 * <p><b>What an event says about an issue, and what it leaves out.</b> The issue's number, its
 * target ({@code cs1}, named as the KEV event names it — {@code repository 12}), its identifier
 * ({@code cs3}: the CVE, or the secret's rule) and its package ({@code cs4}). Never the issue's
 * description: for a secret it is the scanner's prose, and nothing on this path should come near the
 * matched value. A SOC that needs more opens the issue.
 */
final class IssueSignals {

    private IssueSignals() {}

    /**
     * Whether a newly created issue is a leak a SOC is told about: a secret, high or critical. Every
     * secret the shipped scanner reports is graded high; the bound is written down so that a scanner
     * grading some lower does not page anyone for them.
     */
    static boolean isLeak(IssueEntity issue) {
        return FindingType.SECRET.wireName().equals(issue.getType())
                && Severity.of(issue.getSeverity()).isAtLeast(Severity.HIGH);
    }

    static CefEvent secretLeak(IssueEntity issue) {
        String path = issue.getFilePath() == null ? "" : " in " + issue.getFilePath();
        return CefEvent.builder(SecurityEventType.SECRET_LEAK_DETECTED)
                .timestamp(issue.getFirstSeenAt())
                .message("Secret matching rule " + issue.getIdentifier() + " found" + path + " (issue " + issue.getId()
                        + ")")
                .target(targetOf(issue))
                .identifier(issue.getIdentifier())
                .build();
    }

    /**
     * @param dueAt when the window closed — the event's time, which is when the breach happened and
     *     not when the hourly turn noticed it
     */
    static CefEvent slaBreach(IssueEntity issue, Severity severity, Duration window, Instant dueAt) {
        return CefEvent.builder(SecurityEventType.SLA_BREACHED)
                .issueSeverity(severity)
                .timestamp(dueAt)
                .message(severity.name() + " issue " + issue.getId() + " (" + issue.getIdentifier() + ") passed its "
                        + window.toDays() + "-day remediation deadline, open since " + issue.getFirstSeenAt())
                .target(targetOf(issue))
                .identifier(issue.getIdentifier())
                .component(issue.getPackageName())
                .build();
    }

    private static String targetOf(IssueEntity issue) {
        if (issue.getRepoId() != null) {
            return "repository " + issue.getRepoId();
        }
        return issue.getContainerId() == null ? null : "container " + issue.getContainerId();
    }
}
