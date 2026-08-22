package com.asmolabs.zanshin.common.domain.audit;

/**
 * What the audit log records.
 *
 * <p>An enum, where the NestJS tree had a frozen object of string constants. The column stays
 * a string — an operation removed from this list must not make an old row unreadable — but the
 * <em>writers</em> now name a constant, which is what stops a typo becoming an entry nobody
 * will ever find by filtering.
 *
 * <p>Deliberately limited to administration and security actions: authentication, account
 * management, API-key lifecycle, settings changes, triage, scan triggering, authorization
 * refusals. Recording page views would add noise, and a noisy log is a log nobody reads.
 */
public enum AuditOperation {
    LOGIN_SUCCESS,
    LOGIN_FAILURE,

    /** Refused by the throttle, before any password verification. */
    LOGIN_BLOCKED,

    PASSWORD_CHANGED,
    USER_CREATED,
    USER_UPDATED,
    USER_PASSWORD_RESET,
    USER_DELETED,
    API_KEY_CREATED,
    API_KEY_DELETED,
    SETTING_UPDATED,

    /** A triage can dismiss a finding: that is a security decision. */
    ISSUE_TRIAGED,

    SCAN_TRIGGERED,

    /**
     * A model was asked for a report about a target.
     *
     * <p>Audited because it is an outbound send: the target's finding list — identifiers, file
     * paths, descriptions — leaves this process towards a host an operator configured. That the
     * host is usually localhost is a deployment fact, not a property of the operation.
     */
    AI_REVIEW_REQUESTED,
    TICKET_CREATED,
    GATE_POLICY_UPDATED,

    /**
     * A team was created, renamed or deleted.
     *
     * <p>Audited for the same reason as a role change: it decides what a group of people can
     * read. Deleting a team is the sharpest of the three — every member loses everything the
     * team owned, in one gesture, and the entry is what says who made it.
     */
    TEAM_UPDATED,

    /**
     * A team's members or targets changed.
     *
     * <p>Separate from {@link #TEAM_UPDATED} because it is the frequent one and the interesting
     * one: adding a member grants that person everything the team owns, and adding a target
     * grants it to everybody already in the team. Both are quiet gestures with wide reach.
     */
    TEAM_ACCESS_CHANGED,

    /** Without it, sweeping every endpoint leaves no trace at all. */
    ACCESS_DENIED,

    /** A deployment key left the control plane (delegated mode). */
    AGENT_CREDENTIAL_SENT,

    AGENT_RESULT_SUBMITTED,
    RULE_SET_UPLOADED,

    /**
     * A Semgrep rule set was activated.
     *
     * <p>It changes what the scanner looks for, and the rules that disappear take their open
     * issues — and their triage — with them. The entry carries what the operator had in front
     * of them when they confirmed.
     */
    RULE_SET_ACTIVATED,

    RULE_SET_DEACTIVATED,
    AGENT_CREATED,
    AGENT_UPDATED,
    AGENT_DELETED,

    /**
     * A weekly posture report left the deployment.
     *
     * <p><b>This entry is also the bookkeeping.</b> The digest job asks "has one gone out since
     * Monday" by looking for this operation, rather than keeping a last-sent timestamp of its own:
     * the audit log is append-only and never purged, which is a stronger ledger than a settings row
     * an operator can edit — and it means the answer to "why did two arrive" is visible to whoever
     * asks, instead of living in a column no screen shows.
     */
    POSTURE_DIGEST_SENT;

    /** The value stored in the column. The enum name is the wire name, here deliberately. */
    public String wireName() {
        return name();
    }
}
