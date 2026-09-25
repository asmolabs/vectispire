package com.asmolabs.vectispire.common.domain.audit;

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

    /**
     * A compliance report or an evidence bundle left the deployment.
     *
     * <p>Both were recorded as {@link #AI_REVIEW_REQUESTED}: filtering the log for model reviews
     * listed every PDF anybody downloaded, and filtering for exports found none. An export is its own
     * gesture — the estate's figures, or its whole audit log, handed to somebody outside.
     */
    REPORT_EXPORTED,

    TICKET_CREATED,

    /**
     * An operator attached an existing tracker ticket to an issue by hand.
     *
     * <p>It was recorded as {@link #USER_UPDATED}, which says an account changed; an assessor looking
     * for who linked which ticket found it among password resets.
     */
    TICKET_LINKED,

    TICKET_CLOSED,
    TICKET_SYNCED,
    GATE_POLICY_UPDATED,

    /**
     * A line of the declaration of applicability was written or revised.
     *
     * <p>Audited because it is the one place where somebody states, on the record, that a control
     * is in place — or that it does not apply. The estate's measurement is recomputed from data
     * and can always be re-derived; a declaration is a claim, and a claim without an author and a
     * date is not evidence of anything. It is also the field an assessor is most likely to ask
     * about when the declaration and the measurement disagree.
     */
    CONTROL_DECLARED,

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

    /**
     * A result was refused because its attestation did not verify.
     *
     * <p><b>The one entry nobody may miss.</b> An agent whose signing key is pinned and whose
     * result does not verify is either misconfigured or is not the agent — and the second reading
     * is an attempt to declare a target clean with a stolen API key. It is recorded even though
     * the request is refused, because a refusal that leaves no trace is how a probe goes
     * unnoticed.
     */
    AGENT_RESULT_REFUSED,

    /**
     * An operator pinned, replaced or removed an agent's result-signing key.
     *
     * <p>Removing one is the entry that matters: it takes the agent back to being trusted on its
     * bearer token alone, and that has to be a visible act rather than a quiet one.
     */
    AGENT_SIGNING_KEY_PINNED,

    /**
     * A repository's security grade was published as a public badge, or that publication revoked.
     *
     * <p>Its own operation rather than a setting change, because it is the one gesture in the
     * product that moves a fact from behind the visibility model to in front of it: whoever holds
     * the badge URL reads that grade with no account at all.
     */
    BADGE_PUBLISHED,
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
