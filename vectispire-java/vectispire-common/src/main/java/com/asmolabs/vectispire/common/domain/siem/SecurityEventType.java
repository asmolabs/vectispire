package com.asmolabs.vectispire.common.domain.siem;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import java.util.Optional;

/**
 * The security events Vectispire forwards to a SOC, and the catalogue a correlation rule is written
 * against.
 *
 * <p><b>The signature identifier is a data contract.</b> A SOC writes its rules on the CEF
 * {@code Signature ID}, not on the name and not on this constant: renaming a constant is free,
 * changing an identifier silently disarms every rule written against it, in somebody else's SIEM,
 * with nothing on this side to notice. An identifier that is retired is never reused for another
 * meaning — {@code ZAN-SEC-001} (secret leak) and {@code ZAN-SEC-004} (SLA breach) were declared
 * and never emitted, and are kept out of circulation for that reason. See decision 0025.
 *
 * <p><b>Only what is actually emitted is listed.</b> The previous catalogue declared seven events
 * and one of them was ever sent; a SOC reading the list would have written rules for alarms that
 * could not fire, which is worse than no list — it reads as coverage.
 *
 * <p>The CEF severity follows the usual bands — 0–3 low, 4–6 medium, 7–8 high, 9–10 very high —
 * which is what {@link SiemSeverityFilter} maps the configured minimum onto.
 */
public enum SecurityEventType {

    /** A finding under watch was newly listed by CISA as exploited in the wild. */
    CRITICAL_KEV_DETECTED("ZAN-SEC-002", "Actively exploited vulnerability (KEV) detected", 10, Outcome.DETECTED),

    /** A CI pipeline asked the gate and was refused: a build was blocked by policy. */
    SECURITY_GATE_FAILED("ZAN-SEC-003", "Security gate refused a build", 7, Outcome.FAILURE),

    /**
     * A triage decision took a finding out of the way — not affected, or declared fixed — without
     * going through an approval. The decision that makes a dashboard look better is the one a SOC
     * wants to be able to question.
     */
    TRIAGE_SETTLED("ZAN-SEC-005", "Finding settled by triage", 5, Outcome.SUCCESS),

    /** An emergency MFA recovery code was consumed: either a lost phone or a stolen code sheet. */
    MFA_BACKUP_CODE_USED("ZAN-SEC-006", "MFA backup code consumed", 6, Outcome.SUCCESS),

    /** The password sign-in throttle refused an attempt: the failure ceiling was reached. */
    SIGN_IN_THROTTLED("ZAN-SEC-007", "Sign-in failure ceiling reached", 7, Outcome.FAILURE),

    /** A second-factor challenge was destroyed after too many wrong codes. */
    MFA_FAILURE_CEILING("ZAN-SEC-008", "MFA failure ceiling reached", 7, Outcome.FAILURE),

    /** An address presented too many refused bearer tokens and is answered 429 until the window refills. */
    BEARER_TOKEN_THROTTLED("ZAN-SEC-009", "Bearer token failure ceiling reached", 7, Outcome.FAILURE),

    /** An account was created, deleted, changed role, activation, password, second factor or visible targets. */
    ACCOUNT_CHANGED("ZAN-SEC-010", "Account privileges or credentials changed", 6, Outcome.SUCCESS),

    /** A team's members or targets changed: somebody gained or lost access to part of the estate. */
    ACCESS_GRANT_CHANGED("ZAN-SEC-011", "Team access grant changed", 6, Outcome.SUCCESS),

    /** An integration API key was issued. */
    API_KEY_ISSUED("ZAN-SEC-012", "API key issued", 5, Outcome.SUCCESS),

    /** An integration API key was revoked. */
    API_KEY_REVOKED("ZAN-SEC-013", "API key revoked", 4, Outcome.SUCCESS),

    /** A remote agent was declared, enabled, disabled, deleted, or its signing key pinned or removed. */
    AGENT_CHANGED("ZAN-SEC-014", "Agent declared or its credentials changed", 6, Outcome.SUCCESS),

    /** An agent's result was refused because its attestation did not verify. */
    AGENT_RESULT_REFUSED("ZAN-SEC-015", "Agent result refused: attestation did not verify", 8, Outcome.FAILURE),

    /** A four-eyes request was approved by a second person: the finding is now settled. */
    TRIAGE_APPROVED("ZAN-SEC-016", "Four-eyes triage request approved", 5, Outcome.SUCCESS),

    /** A four-eyes request was sent back rather than approved. */
    TRIAGE_REFUSED("ZAN-SEC-017", "Four-eyes triage request refused", 4, Outcome.FAILURE),

    /** The audit log's hash chain, or its mirror, no longer agrees with itself. */
    AUDIT_CHAIN_BROKEN("ZAN-SEC-018", "Audit log integrity verification failed", 10, Outcome.FAILURE),

    /** A setting that governs security changed: SIEM export, four-eyes, visibility, a gate policy, a credential. */
    SECURITY_SETTING_CHANGED("ZAN-SEC-019", "Security-relevant setting changed", 6, Outcome.SUCCESS),

    /** The connection test. Sent whatever the severity filter says, since it tests the filter's destination. */
    PING_TEST("ZAN-SEC-999", "SIEM connector health check", 1, Outcome.SUCCESS);

    /**
     * The CEF {@code outcome} an event of this type carries.
     *
     * <p>A property of the type and not of each call site: a throttle is a failure by definition,
     * and letting every emitter spell it would give a SOC {@code failure}, {@code failed} and
     * {@code FAIL} for the same thing.
     */
    public enum Outcome {
        SUCCESS("success"),
        FAILURE("failure"),
        DETECTED("detected");

        private final String wireName;

        Outcome(String wireName) {
            this.wireName = wireName;
        }

        public String wireName() {
            return wireName;
        }
    }

    private final String signatureId;
    private final String description;
    private final int cefSeverity;
    private final Outcome outcome;

    SecurityEventType(String signatureId, String description, int cefSeverity, Outcome outcome) {
        this.signatureId = signatureId;
        this.description = description;
        this.cefSeverity = cefSeverity;
        this.outcome = outcome;
    }

    public String signatureId() {
        return signatureId;
    }

    public String description() {
        return description;
    }

    public int cefSeverity() {
        return cefSeverity;
    }

    public Outcome outcome() {
        return outcome;
    }

    /**
     * The event an audit entry signals on its own, when its operation says enough.
     *
     * <p><b>Only the unambiguous operations are here.</b> {@code LOGIN_BLOCKED} is written by the
     * throttle and also when password sign-in is switched off; {@code SETTING_UPDATED} covers a
     * repository's branch as well as the four-eyes switch; {@code ISSUE_TRIAGED} a ticket link as
     * well as a dismissal. Mapping those by operation would either flood a SOC or miss what it
     * wants, so their writers name the event themselves ({@code Record#signalling}) and this answers
     * empty.
     */
    public static Optional<SecurityEventType> signalledBy(AuditOperation operation) {
        if (operation == null) {
            return Optional.empty();
        }
        return switch (operation) {
            case USER_CREATED, USER_UPDATED, USER_DELETED, USER_PASSWORD_RESET, PASSWORD_CHANGED ->
                    Optional.of(ACCOUNT_CHANGED);
            // Filing or moving a repository moves it in or out of every project grant at once
            // (decision 0023): who may see it changes, with no grant row touched.
            case TEAM_ACCESS_CHANGED, PROJECT_REPOSITORIES_CHANGED -> Optional.of(ACCESS_GRANT_CHANGED);
            case API_KEY_CREATED -> Optional.of(API_KEY_ISSUED);
            case API_KEY_DELETED -> Optional.of(API_KEY_REVOKED);
            case AGENT_CREATED, AGENT_UPDATED, AGENT_DELETED, AGENT_SIGNING_KEY_PINNED -> Optional.of(AGENT_CHANGED);
            case AGENT_RESULT_REFUSED -> Optional.of(AGENT_RESULT_REFUSED);
            case GATE_POLICY_UPDATED -> Optional.of(SECURITY_SETTING_CHANGED);
            // Listed rather than defaulted: a new operation has to be placed here, on one side or
            // the other, by whoever adds it — a default would decide for them, silently.
            case LOGIN_SUCCESS, LOGIN_FAILURE, LOGIN_BLOCKED, SETTING_UPDATED, ISSUE_TRIAGED,
                    SCAN_TRIGGERED, AI_REVIEW_REQUESTED, REPORT_EXPORTED, TICKET_CREATED, TICKET_LINKED,
                    TICKET_CLOSED, TICKET_SYNCED, CONTROL_DECLARED, TEAM_UPDATED, ACCESS_DENIED,
                    AGENT_CREDENTIAL_SENT, AGENT_RESULT_SUBMITTED, BADGE_PUBLISHED, RULE_SET_UPLOADED,
                    RULE_SET_ACTIVATED, RULE_SET_DEACTIVATED, POSTURE_DIGEST_SENT,
                    // A name or a description; a project deleted with grants on it names the event
                    // itself, since only its writer knows whether any were revoked.
                    SOLUTION_UPDATED, PROJECT_UPDATED -> Optional.empty();
        };
    }
}
