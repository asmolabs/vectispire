package com.asmolabs.zanshin.common.domain.gate;

import com.asmolabs.zanshin.common.domain.issues.Severity;

/**
 * What a caller considers unacceptable.
 *
 * @param failOnSeverity fail as soon as an open issue reaches this severity; {@code null}
 *     disables the severity rule entirely, which is useful for blocking on KEV alone
 */
public record GatePolicy(
        Severity failOnSeverity,
        boolean failOnKev,
        boolean fixableOnly,
        boolean includeTriaged,
        boolean includeAiReview) {

    /**
     * The default, and every element of it is an argued choice.
     *
     * <ul>
     *   <li><b>Triaged issues do not count.</b> An argued exemption is the point of triage.
     *   <li><b>KEV fails the build, independently of severity.</b> A "medium" exploited in the
     *       wild outranks a "critical" that never has been.
     *   <li><b>"Fixable only" is off.</b> Failing only on what has a published fix is a
     *       reasonable setting and a dangerous default: it would silently tolerate an actively
     *       exploited vulnerability with no fix — exactly the case that needs a human.
     *   <li><b>AI review findings are excluded.</b> They come from a local model handed the
     *       repository's source: a hostile repository can steer it, and an invented "critical"
     *       would fail somebody's build.
     * </ul>
     */
    public static final GatePolicy BUILT_IN = new GatePolicy(Severity.HIGH, true, false, false, false);

    public boolean flag(PolicyFlag flag) {
        return switch (flag) {
            case FAIL_ON_KEV -> failOnKev;
            case INCLUDE_TRIAGED -> includeTriaged;
            case INCLUDE_AI_REVIEW -> includeAiReview;
            case FIXABLE_ONLY -> fixableOnly;
        };
    }

    public GatePolicy with(PolicyFlag flag, boolean value) {
        return switch (flag) {
            case FAIL_ON_KEV -> new GatePolicy(failOnSeverity, value, fixableOnly, includeTriaged, includeAiReview);
            case INCLUDE_TRIAGED -> new GatePolicy(failOnSeverity, failOnKev, fixableOnly, value, includeAiReview);
            case INCLUDE_AI_REVIEW -> new GatePolicy(failOnSeverity, failOnKev, fixableOnly, includeTriaged, value);
            case FIXABLE_ONLY -> new GatePolicy(failOnSeverity, failOnKev, value, includeTriaged, includeAiReview);
        };
    }

    public GatePolicy withFailOnSeverity(Severity severity) {
        return new GatePolicy(severity, failOnKev, fixableOnly, includeTriaged, includeAiReview);
    }
}
