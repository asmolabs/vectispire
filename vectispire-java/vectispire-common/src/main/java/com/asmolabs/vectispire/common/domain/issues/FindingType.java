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
 *   <li><b>{@code PLUGIN} and {@code IMPORTED} count only when asked for, too</b>, on their own
 *       flag. A plugin is third-party code that read the repository; an import is a report another
 *       tool made. Neither may invent a "critical" that fails a build nobody warned (decision 0017).
 *   <li>Everything else always counts, and is what a security posture is made of.
 * </ul>
 *
 * <p><b>Two types for the two provenances, not one.</b> The type is the first thing every screen,
 * filter and export shows, so "analysed by Vectispire, through a plugin it ran" and "declared by a
 * CI that uploaded a report" cannot be mistaken for each other by anybody who reads only that.
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
    /** Found by a plugin Vectispire ran, in the built-in worker or on an agent. */
    PLUGIN("plugin", GateParticipation.ON_REQUEST, true),
    /** Declared by an internal tool's SARIF report, uploaded through a declared source. */
    IMPORTED("imported", GateParticipation.ON_REQUEST, true),
    QUALITY("quality", GateParticipation.NEVER);

    /** Whether findings of a type may fail a build, and under what condition. */
    public enum GateParticipation {
        ALWAYS,
        ON_REQUEST,
        NEVER
    }

    private final String wireName;
    private final GateParticipation gateParticipation;
    private final boolean toolScoped;

    FindingType(String wireName, GateParticipation gateParticipation) {
        this(wireName, gateParticipation, false);
    }

    FindingType(String wireName, GateParticipation gateParticipation, boolean toolScoped) {
        this.wireName = wireName;
        this.gateParticipation = gateParticipation;
        this.toolScoped = toolScoped;
    }

    /**
     * Whether an issue of this type belongs to one tool among several — a plugin, an import source's
     * tool — rather than to the type as a whole.
     *
     * <p><b>This is what decides what a clean run resolves.</b> Semgrep reporting no SAST finding
     * resolves the target's SAST issues. One plugin reporting nothing must resolve <em>its</em>
     * issues only, not those of every other plugin and import on the target — so a tool-scoped type
     * is never resolved by type, only by tool key ({@link IssueFingerprint#ofTool}), and its tool key
     * sits in the fingerprint where the package would.
     */
    public boolean toolScoped() {
        return toolScoped;
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
