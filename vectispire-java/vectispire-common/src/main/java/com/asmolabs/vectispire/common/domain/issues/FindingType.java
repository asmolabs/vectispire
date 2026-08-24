package com.asmolabs.vectispire.common.domain.issues;

import java.util.Arrays;
import java.util.Optional;

/**
 * The finding types, and what each one is allowed to do to a build.
 *
 * <p>Three behaviours, not two, and the middle one is easy to miss:
 *
 * <ul>
 *   <li><b>{@code QUALITY} never fails a build</b>, and carries no flag to change that. A
 *       quality backlog is voluminous by nature, and a gate that turns red the day somebody
 *       switches on a linter is a gate that gets switched off. The absence of an option is the
 *       decision — an option would make "quality never blocks" a sentence with an asterisk.
 *   <li><b>{@code AI_REVIEW} counts only when asked for.</b> It comes from a local model handed
 *       the repository's own source: a hostile repository can steer it, and an invented
 *       "critical" would fail somebody's build. Off by default, available on request.
 *   <li>Everything else always counts, and is what a security posture is made of.
 * </ul>
 *
 * <p>An enum rather than the original's string constants plus a hand-maintained
 * {@code SECURITY_TYPES} list plus a separate {@code QUALITY_TYPES} list plus a standalone
 * {@code AI_REVIEW_TYPE}. Four declarations over one set, which could disagree: a type added to
 * one and not the others would appear in a counter meant to exclude it, and nothing would fail.
 */
public enum FindingType {
    VULNERABILITY("vulnerability", GateParticipation.ALWAYS),
    SECRET("secret", GateParticipation.ALWAYS),
    IAC("iac", GateParticipation.ALWAYS),
    LICENSE("license", GateParticipation.ALWAYS),
    EOL("eol", GateParticipation.ALWAYS),
    SAST("sast", GateParticipation.ALWAYS),
    AI_REVIEW("ai_review", GateParticipation.ON_REQUEST),
    QUALITY("quality", GateParticipation.NEVER);

    /** Whether findings of a type may fail a build, and under what condition. */
    public enum GateParticipation {
        ALWAYS,
        ON_REQUEST,
        NEVER
    }

    private final String wireName;
    private final GateParticipation gateParticipation;

    FindingType(String wireName, GateParticipation gateParticipation) {
        this.wireName = wireName;
        this.gateParticipation = gateParticipation;
    }

    /**
     * The form stored in the database and sent over the API.
     *
     * <p>Held separately from {@link #name()} so renaming a constant is a refactor, not a data
     * migration.
     */
    public String wireName() {
        return wireName;
    }

    public GateParticipation gateParticipation() {
        return gateParticipation;
    }

    /**
     * Whether the type counts towards a security posture.
     *
     * <p>Only {@link GateParticipation#ALWAYS}: AI review is excluded here even when a policy
     * lets it fail a build, because the counters at the top of a screen must mean the same
     * thing for everybody.
     */
    public boolean isSecurity() {
        return gateParticipation == GateParticipation.ALWAYS;
    }

    public static Optional<FindingType> fromWireName(String value) {
        return value == null
                ? Optional.empty()
                : Arrays.stream(values()).filter(type -> type.wireName.equals(value)).findFirst();
    }
}
