package com.asmolabs.vectispire.common.domain.notifications;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.notifications.NotificationPayload.NotifiableIssue;
import java.util.List;

/**
 * Which of the new or reappeared issues deserve a message.
 *
 * <p><b>Only on change, and only above a threshold.</b> One notification per scan teaches
 * people to filter the channel, and a filtered channel is worth less than no channel at all.
 */
public final class NotificationSelection {

    private NotificationSelection() {}

    public static final Severity DEFAULT_MIN_SEVERITY = Severity.HIGH;

    /**
     * @param alwaysOnKev let an actively exploited vulnerability through <b>whatever its
     *     severity</b> — that is the whole point of the KEV signal, and a threshold alone
     *     discards a "medium" being exploited today
     */
    public record Options(Severity minSeverity, boolean alwaysOnKev) {}

    /**
     * <b>Quality findings never qualify</b>, whatever their severity.
     *
     * <p>Semgrep maps its {@code ERROR} level to {@code high}, which clears the default
     * threshold: the first scan of a repository with the SAST step on would fire a webhook
     * announcing several hundred issues. Excluding the type is the honest fix — lowering their
     * severity to silence them would be a lie about severity, and would also move them in the
     * backlog's ordering.
     */
    public static List<NotifiableIssue> notable(List<NotifiableIssue> issues, Options options) {
        return issues.stream()
                .filter(issue -> issue.type() != FindingType.QUALITY)
                .filter(issue -> (options.alwaysOnKev() && issue.kev())
                        || severityOf(issue).isAtLeast(options.minSeverity()))
                .toList();
    }

    private static Severity severityOf(NotifiableIssue issue) {
        // A finding can arrive with no severity, and absence must rank lowest rather than
        // becoming an alert nobody can act on.
        return issue.severity() == null ? Severity.UNKNOWN : issue.severity();
    }
}
