package com.asmolabs.vectispire.common.domain.siem;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import java.util.Optional;

/**
 * The security events Vectispire forwards to a SOC, and the catalogue a correlation rule is written
 * against.
 *
 * <p><b>The signature identifier is a data contract.</b> A SOC writes its rules on the CEF
 * {@code Signature ID}, not on the name and not on this constant: renaming a constant is free,
 * changing an identifier silently disarms every rule written against it, in somebody else's SIEM,
 * with nothing on this side to notice. An identifier that is retired is never reused for another
 * meaning — {@code VECTI-SEC-001} (secret leak) and {@code VECTI-SEC-004} (SLA breach) were declared
 * and never emitted, and are kept out of circulation for that reason. See decision 0025. When those
 * two alarms were finally emitted, they took new numbers ({@code 029}, {@code 030}) rather than the
 * old ones: a rule a SOC wrote against {@code 001} in the days it was declared was written for a
 * definition nobody can now reconstruct — its trigger, its severity, its deduplication — and
 * reviving the number would arm that rule on a meaning it was not written for.
 *
 * <p><b>Only what is actually emitted is listed.</b> The previous catalogue declared seven events
 * and one of them was ever sent; a SOC reading the list would have written rules for alarms that
 * could not fire, which is worse than no list — it reads as coverage.
 *
 * <p>The CEF severity follows the usual bands — 0–3 low, 4–6 medium, 7–8 high, 9–10 very high —
 * which is what {@link SiemSeverityFilter} maps the configured minimum onto. <b>It is the event's, not
 * always the type's</b>: a type that {@linkplain #followsIssueSeverity() follows the issue} it reports
 * on carries that issue's band ({@link #cefSeverityOf(Severity)}), and the filter reads the event. The
 * severity declared here is then the default, which only an event queued before its type followed
 * the issue still carries.
 */
public enum SecurityEventType {

    /** A finding under watch was newly listed by CISA as exploited in the wild. */
    CRITICAL_KEV_DETECTED("VECTI-SEC-002", "Actively exploited vulnerability (KEV) detected", 10, Outcome.DETECTED),

    /** A CI pipeline asked the gate and was refused: a build was blocked by policy. */
    SECURITY_GATE_FAILED("VECTI-SEC-003", "Security gate refused a build", 7, Outcome.FAILURE),

    /**
     * A triage decision took a finding out of the way — not affected, or declared fixed — without
     * going through an approval. The decision that makes a dashboard look better is the one a SOC
     * wants to be able to question.
     */
    TRIAGE_SETTLED("VECTI-SEC-005", "Finding settled by triage", 5, Outcome.SUCCESS),

    /** An emergency MFA recovery code was consumed: either a lost phone or a stolen code sheet. */
    MFA_BACKUP_CODE_USED("VECTI-SEC-006", "MFA backup code consumed", 6, Outcome.SUCCESS),

    /** The password sign-in throttle refused an attempt: the failure ceiling was reached. */
    SIGN_IN_THROTTLED("VECTI-SEC-007", "Sign-in failure ceiling reached", 7, Outcome.FAILURE),

    /** A second-factor challenge was destroyed after too many wrong codes. */
    MFA_FAILURE_CEILING("VECTI-SEC-008", "MFA failure ceiling reached", 7, Outcome.FAILURE),

    /** An address presented too many refused bearer tokens and is answered 429 until the window refills. */
    BEARER_TOKEN_THROTTLED("VECTI-SEC-009", "Bearer token failure ceiling reached", 7, Outcome.FAILURE),

    /** An account was created, deleted, changed role, activation, password, second factor or visible targets. */
    ACCOUNT_CHANGED("VECTI-SEC-010", "Account privileges or credentials changed", 6, Outcome.SUCCESS),

    /** A team's members or targets changed: somebody gained or lost access to part of the estate. */
    ACCESS_GRANT_CHANGED("VECTI-SEC-011", "Team access grant changed", 6, Outcome.SUCCESS),

    /** An integration API key was issued. */
    API_KEY_ISSUED("VECTI-SEC-012", "API key issued", 5, Outcome.SUCCESS),

    /** An integration API key was revoked. */
    API_KEY_REVOKED("VECTI-SEC-013", "API key revoked", 4, Outcome.SUCCESS),

    /**
     * A remote agent was declared, enabled, disabled, deleted, its signing key pinned or removed, or
     * its sealing key reset.
     */
    AGENT_CHANGED("VECTI-SEC-014", "Agent declared or its credentials changed", 6, Outcome.SUCCESS),

    /** An agent's result was refused because its attestation did not verify. */
    AGENT_RESULT_REFUSED("VECTI-SEC-015", "Agent result refused: attestation did not verify", 8, Outcome.FAILURE),

    /** A four-eyes request was approved by a second person: the finding is now settled. */
    TRIAGE_APPROVED("VECTI-SEC-016", "Four-eyes triage request approved", 5, Outcome.SUCCESS),

    /** A four-eyes request was sent back rather than approved. */
    TRIAGE_REFUSED("VECTI-SEC-017", "Four-eyes triage request refused", 4, Outcome.FAILURE),

    /** The audit log's hash chain, or its mirror, no longer agrees with itself. */
    AUDIT_CHAIN_BROKEN("VECTI-SEC-018", "Audit log integrity verification failed", 10, Outcome.FAILURE),

    /** A setting that governs security changed: SIEM export, four-eyes, visibility, a gate policy, a credential. */
    SECURITY_SETTING_CHANGED("VECTI-SEC-019", "Security-relevant setting changed", 6, Outcome.SUCCESS),

    /**
     * An agent's sealing key was refused: its signature did not verify against the key pinned for
     * the agent, or it was older than the key already accepted. No credential is sealed for it.
     */
    AGENT_SEALING_KEY_REFUSED("VECTI-SEC-020", "Agent sealing key refused: signature or generation did not verify", 8,
            Outcome.FAILURE),

    /**
     * A plugin was registered, changed, enabled, disabled, switched on or off for a project, or let
     * run unsigned — or no longer: third-party code gained or lost read access to some of the estate's
     * source, or the platform's check on who built it was waived for it.
     */
    PLUGIN_CHANGED("VECTI-SEC-021", "Analysis plugin registered, changed or activated", 6, Outcome.SUCCESS),

    /** A SARIF source was declared, changed or removed: who may deposit findings, and for what. */
    SARIF_SOURCE_CHANGED("VECTI-SEC-022", "SARIF import source declared or changed", 6, Outcome.SUCCESS),

    /**
     * A SARIF upload was refused for what it claimed: an undeclared key, a repository outside its
     * source's scope, a tool its source is not declared for. Either a misconfigured pipeline or a
     * key used for something it was not issued for.
     */
    SARIF_IMPORT_REFUSED("VECTI-SEC-023", "SARIF import refused: undeclared source, scope or tool", 5, Outcome.FAILURE),

    /**
     * A checklist template version was published, or a published one retired: what every project's
     * checklist attests to has changed (decision 0032 §9). A draft set aside, never published, changes
     * nothing any project attests to and is not this event.
     */
    CHECKLIST_TEMPLATE_CHANGED("VECTI-SEC-024", "Checklist template version published or retired", 6, Outcome.SUCCESS),

    /**
     * A project's checklist was signed off: a release attestation was given, and by whom (decision
     * 0032 §9). The entry states whether four-eyes required the signer to differ from its authors.
     */
    CHECKLIST_SIGNED_OFF("VECTI-SEC-025", "Checklist signed off", 5, Outcome.SUCCESS),

    /**
     * A checklist's sign-off was refused — its signer one of its authors while four-eyes is on, or a
     * proof that stopped holding between submission and signature — or a submitted checklist was
     * returned to its authors. Either a four-eyes refusal or evidence that stopped holding.
     */
    CHECKLIST_SIGN_OFF_REFUSED("VECTI-SEC-026", "Checklist sign-off refused or returned", 5, Outcome.FAILURE),

    /**
     * A coverage or test report was refused for what it claimed: an undeclared or disabled key, a kind
     * its source is not declared for, a repository outside its scope — {@code VECTI-SEC-023}'s twin for
     * the reports a checklist reads (decision 0032). {@code 025} and {@code 026} are the checklists'.
     */
    REPORT_IMPORT_REFUSED("VECTI-SEC-027", "Report import refused: undeclared source, kind or scope", 5, Outcome.FAILURE),

    /**
     * The export was switched off, or pointed at another collector: this collector will receive
     * nothing more, on purpose. Sent synchronously to the collector that is being left, after the
     * change commits and whatever the severity filter says — queued, it would be read at delivery
     * against the configuration that no longer names this collector, and dropped. Its writer also
     * records whether it was delivered in the change's audit entry.
     */
    SIEM_EXPORT_STOPPED("VECTI-SEC-028", "SIEM export switched off or redirected", 7, Outcome.SUCCESS),

    /**
     * A secret scan found a credential of high or critical severity that the backlog did not hold:
     * once per issue, when it is created — a leak seen again by the next scan is the same leak, and
     * one that comes back after being resolved reopens its issue rather than announcing a new one.
     */
    SECRET_LEAK_DETECTED("VECTI-SEC-029", "Secret leaked in source code", 8, Outcome.DETECTED),

    /**
     * An open, unsettled issue passed its remediation deadline ({@code RemediationSla}): once per
     * issue, by the hourly maintenance turn that notices the crossing.
     *
     * <p><b>As severe as the late issue</b> — 8 for a critical, 7 for a high, 5 and 3 below. At a fixed
     * 6 it sat under the factory minimum ({@code HIGH}, 7 and above), so out of the box no breach ever
     * reached the SOC, a critical, exploited issue's included. The 6 stays as the default for an event
     * queued before the upgrade, whose stored form carries no severity of its own.
     */
    SLA_BREACHED("VECTI-SEC-030", "Remediation deadline passed", 6, Outcome.DETECTED, true),

    /**
     * A report plugin was registered, given another manifest, approved, enabled or disabled, switched on or
     * off for a project, or had a manifest withdrawn (decision 0035 §4): third-party code gained or lost
     * access to a project's whole triaged state, or the right to produce documents under the installation's
     * key.
     */
    REPORT_PLUGIN_CHANGED("VECTI-SEC-031", "Report plugin registered, changed, approved, activated or withdrawn", 6,
            Outcome.SUCCESS),

    /**
     * A project's whole triaged state left the platform as an export (decision 0035 §4): who took it, of
     * which project, and its digest. {@code 033} is reserved for the report plugins' refusals, by the same
     * decision, and is not to be taken by anything else.
     */
    PROJECT_EXPORTED("VECTI-SEC-032", "Project export left the platform", 4, Outcome.SUCCESS),

    /**
     * A forge connection was created, given another token or another trust — a pinned CA, a network
     * statement — or deleted (decision 0037 §2): a standing read access to an organisation's whole list of
     * repositories appeared, changed hands or went. A renaming is audited and not signalled. {@code 035}
     * is reserved for the imports from a forge, by the same decision, and is not to be taken by anything
     * else.
     */
    FORGE_CONNECTION_CHANGED("VECTI-SEC-034", "Forge connection created, its token or trust replaced, or deleted", 6,
            Outcome.SUCCESS),

    /**
     * A forge connection was refused because its address is one the outbound guard blocks, or its token is
     * broader than read-only (decision 0037 §2) — how an SSRF or a credential-harvesting attempt through the
     * connection form shows itself. Lot D2 adds a next page pointing at another host.
     */
    FORGE_CONNECTION_REFUSED("VECTI-SEC-036", "Forge connection refused: blocked destination, write scope, or a "
            + "credential presented to another host", 5, Outcome.FAILURE),

    /** The connection test. Sent whatever the severity filter says, since it tests the filter's destination. */
    PING_TEST("VECTI-SEC-999", "SIEM connector health check", 1, Outcome.SUCCESS);

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
    private final boolean followsIssueSeverity;

    SecurityEventType(String signatureId, String description, int cefSeverity, Outcome outcome) {
        this(signatureId, description, cefSeverity, outcome, false);
    }

    SecurityEventType(
            String signatureId, String description, int cefSeverity, Outcome outcome, boolean followsIssueSeverity) {
        this.signatureId = signatureId;
        this.description = description;
        this.cefSeverity = cefSeverity;
        this.outcome = outcome;
        this.followsIssueSeverity = followsIssueSeverity;
    }

    public String signatureId() {
        return signatureId;
    }

    public String description() {
        return description;
    }

    /** The type's own severity: every event's, unless the type {@linkplain #followsIssueSeverity() follows the issue}. */
    public int cefSeverity() {
        return cefSeverity;
    }

    /**
     * Whether an event of this type takes its CEF severity from the issue it reports on
     * ({@link #cefSeverityOf(Severity)}) rather than from the type. Only such a type accepts an
     * issue's severity ({@link CefEvent.Builder#issueSeverity}): the others keep the one a SOC's rules
     * were written against.
     */
    public boolean followsIssueSeverity() {
        return followsIssueSeverity;
    }

    /**
     * An issue's severity as the CEF severity of an event about it — the one place it is decided.
     *
     * <p>Inside the CEF band of the same name and below its top, so that the configured minimum
     * ({@link SiemSeverityFilter}) lets an issue's event through exactly from the issue's own
     * severity: {@code HIGH} forwards a high or critical issue's, {@code MEDIUM} a medium one's too.
     * A critical takes 8 and not 9: 9–10 is kept for what is exploited or broken now (a KEV, the
     * audit chain), and a late fix is neither. {@code NEGLIGIBLE} and {@code UNKNOWN} rank with
     * {@code LOW}. A switch without a default, so a severity added to {@link Severity} has to be
     * placed here.
     */
    public static int cefSeverityOf(Severity issueSeverity) {
        return switch (issueSeverity) {
            case CRITICAL -> 8;
            case HIGH -> 7;
            case MEDIUM -> 5;
            case LOW, NEGLIGIBLE, UNKNOWN -> 3;
        };
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
            // Filing or moving a repository or an image moves it in or out of every project grant at
            // once (decision 0023): who may see it changes, with no grant row touched.
            case TEAM_ACCESS_CHANGED, PROJECT_REPOSITORIES_CHANGED, PROJECT_CONTAINERS_CHANGED ->
                    Optional.of(ACCESS_GRANT_CHANGED);
            case API_KEY_CREATED -> Optional.of(API_KEY_ISSUED);
            case API_KEY_DELETED -> Optional.of(API_KEY_REVOKED);
            case AGENT_CREATED, AGENT_UPDATED, AGENT_DELETED, AGENT_SIGNING_KEY_PINNED, AGENT_SEALING_KEY_RESET ->
                    Optional.of(AGENT_CHANGED);
            case AGENT_RESULT_REFUSED -> Optional.of(AGENT_RESULT_REFUSED);
            case AGENT_SEALING_KEY_REFUSED -> Optional.of(AGENT_SEALING_KEY_REFUSED);
            case GATE_POLICY_UPDATED -> Optional.of(SECURITY_SETTING_CHANGED);
            case PLUGIN_REGISTERED, PLUGIN_UPDATED, PLUGIN_ENABLED_CHANGED, PLUGIN_ACTIVATED, PLUGIN_DEACTIVATED,
                    PLUGIN_SIGNATURE_WAIVED, PLUGIN_SIGNATURE_WAIVER_REVOKED -> Optional.of(PLUGIN_CHANGED);
            case SARIF_SOURCE_CHANGED -> Optional.of(SARIF_SOURCE_CHANGED);
            case SARIF_IMPORT_REFUSED -> Optional.of(SARIF_IMPORT_REFUSED);
            case REPORT_IMPORT_REFUSED -> Optional.of(REPORT_IMPORT_REFUSED);
            case PROJECT_EXPORTED -> Optional.of(PROJECT_EXPORTED);
            case FORGE_CONNECTION_REFUSED -> Optional.of(FORGE_CONNECTION_REFUSED);
            case REPORT_PLUGIN_REGISTERED, REPORT_PLUGIN_UPDATED, REPORT_PLUGIN_APPROVED, REPORT_PLUGIN_ENABLED_CHANGED,
                    REPORT_PLUGIN_ACTIVATED, REPORT_PLUGIN_DEACTIVATED, REPORT_PLUGIN_WITHDRAWN ->
                    Optional.of(REPORT_PLUGIN_CHANGED);
            case CHECKLIST_TEMPLATE_PUBLISHED -> Optional.of(CHECKLIST_TEMPLATE_CHANGED);
            case CHECKLIST_SIGNED_OFF -> Optional.of(CHECKLIST_SIGNED_OFF);
            // Returned is refused by another name: what was submitted for signature did not get it.
            case CHECKLIST_SIGN_OFF_REFUSED, CHECKLIST_RETURNED -> Optional.of(CHECKLIST_SIGN_OFF_REFUSED);
            // Listed rather than defaulted: a new operation has to be placed here, on one side or
            // the other, by whoever adds it — a default would decide for them, silently.
            case LOGIN_SUCCESS, LOGIN_FAILURE, LOGIN_BLOCKED, SETTING_UPDATED, ISSUE_TRIAGED,
                    SCAN_TRIGGERED, AI_REVIEW_REQUESTED, REPORT_EXPORTED, TICKET_CREATED, TICKET_LINKED,
                    TICKET_CLOSED, TICKET_SYNCED, CONTROL_DECLARED, TEAM_UPDATED, ACCESS_DENIED,
                    // Compliance's record, like a declaration: who drew the scope, not an access
                    // change; and a feed refresh anybody with the lead role may ask for at will.
                    CERTIFIED_SCOPE_CHANGED, THREAT_INTEL_SYNCED,
                    AGENT_CREDENTIAL_SENT, AGENT_RESULT_SUBMITTED, BADGE_PUBLISHED,
                    // A clone refused, a workspace not made: the operator's to read on the scan. An
                    // unsigned report from an agent whose key is pinned is AGENT_RESULT_REFUSED.
                    AGENT_SCAN_FAILED,
                    // Bookkeeping of an upgrade: counters given back, nothing anybody did.
                    SCAN_ATTEMPTS_REPAIRED,
                    // Every restart of every agent: the refusal is the event, the rotation is routine.
                    AGENT_SEALING_KEY_ACCEPTED, RULE_SET_UPLOADED,
                    RULE_SET_ACTIVATED, RULE_SET_DEACTIVATED, POSTURE_DIGEST_SENT,
                    // A name or a description; a project deleted with grants on it names the event
                    // itself, since only its writer knows whether any were revoked.
                    SOLUTION_UPDATED, PROJECT_UPDATED,
                    // Routine: a pipeline's upload, as frequent as its builds. What it did is in the
                    // entry; a refusal is the event.
                    SARIF_IMPORTED, COVERAGE_IMPORTED, TEST_REPORT_IMPORTED,
                    // A draft being written changes nothing any project attests to: publishing it does.
                    CHECKLIST_TEMPLATE_IMPORTED, CHECKLIST_TEMPLATE_LAYOUT_CONFIRMED, CHECKLIST_TEMPLATE_ITEMS_PAIRED,
                    CHECKLIST_TEMPLATE_EVIDENCE_SET, CHECKLIST_TEMPLATE_RULES_BOUND, CHECKLIST_TEMPLATE_DERIVED,
                    // A published version retired is the event, and a draft set aside is not: its writer
                    // knows which, and names the event itself.
                    CHECKLIST_TEMPLATE_RETIRED,
                    // A checklist being filled is work, not a security event (§9): the sign-off is one.
                    CHECKLIST_OPENED, CHECKLIST_MOVED_TO_VERSION, CHECKLIST_ANSWERED, CHECKLIST_EVIDENCE_ADDED,
                    CHECKLIST_EVIDENCE_WITHDRAWN, CHECKLIST_SUBMITTED, CHECKLIST_REOPENED,
                    // A download of what was attested, like REPORT_EXPORTED: the sign-off was the event.
                    CHECKLIST_EXPORTED,
                    // A renaming is a forge connection's change too, and not an event: the writer names
                    // VECTI-SEC-034 on the creation, the new token or trust, and the deletion.
                    FORGE_CONNECTION_CHANGED -> Optional.empty();
        };
    }
}
