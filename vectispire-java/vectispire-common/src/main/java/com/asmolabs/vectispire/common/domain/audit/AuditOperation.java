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
     * A repository or an image was put in or taken out of the certified scope.
     *
     * <p>Audited for the reason a declaration is: the scope is what an assessment measures the
     * evidence against, and taking a target out of it is the quietest way to improve the coverage
     * figure — the target that had no current scan stops counting against it. Nothing recorded who
     * did it until this; the flag changed on the target's row and left no trace.
     */
    CERTIFIED_SCOPE_CHANGED,

    /**
     * A threat-intelligence feed was synchronised — the CISA KEV catalogue or FIRST's EPSS file, one
     * entry per feed — asked from the threat intelligence screen or the EPSS one, which run the same
     * synchronisation, or run by the maintenance schedule under the actor {@code system}.
     *
     * <p>An outbound call, and one that re-evaluates the whole open backlog; a failed attempt is
     * recorded as one, with its reason. The first route recorded it as {@link #SETTING_UPDATED}, which
     * it is not, and the second recorded nothing.
     */
    THREAT_INTEL_SYNCED,

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

    /**
     * A solution was created, renamed, described or deleted (decision 0023).
     *
     * <p>No grant names a solution, so this changes nobody's access; it is audited because the
     * solutions are the frame every per-project report is read in.
     */
    SOLUTION_UPDATED,

    /**
     * A project was created, renamed, described or deleted.
     *
     * <p>Deleting one is the entry that matters: it revokes every grant naming the project and
     * returns its repositories to "no project", in one gesture, and the entry carries both counts.
     */
    PROJECT_UPDATED,

    /**
     * A repository was filed into a project, moved to another, or taken out of one.
     *
     * <p><b>An access change, though no grant row moves.</b> A project grant is resolved at each
     * request into the project's repositories, so moving a repository moves its visibility for
     * the project's grantees at once, in both directions — the entry says so, because nobody
     * reading "moved to Payments" would otherwise think to look here for why somebody gained or
     * lost a repository.
     */
    PROJECT_REPOSITORIES_CHANGED,

    /**
     * A container image was filed into a project, moved to another, or taken out of one (decision 0023,
     * amendment of 2026-09-30).
     *
     * <p>An access change for the reason {@link #PROJECT_REPOSITORIES_CHANGED} is. <b>An operation of its
     * own rather than that one reused</b>: the entry's target is the image's identifier, and a repository
     * and an image may carry the same number — under the repositories' operation, "42" would name the
     * wrong target to whoever filtered the log by it.
     */
    PROJECT_CONTAINERS_CHANGED,

    /** Without it, sweeping every endpoint leaves no trace at all. */
    ACCESS_DENIED,

    /** A deployment key left the control plane (delegated mode). */
    AGENT_CREDENTIAL_SENT,

    /**
     * The upgrade gave back the attempts that withheld claims had counted on scans never delivered.
     *
     * <p>Until the claim of an agent without a usable sealing key left the scans carrying a credential
     * out of its selection, each of its polls took such a scan — one attempt — and put it back; a scan
     * nothing had tried then failed for good at its first real takeover. Written once per database,
     * whatever it repaired, and that is also its bookkeeping: the repair runs while no such entry
     * exists, and never again.
     */
    SCAN_ATTEMPTS_REPAIRED,

    AGENT_RESULT_SUBMITTED,

    /**
     * An agent reported that it could not run a scan it had claimed, and one of the scan's attempts
     * was spent on its word: requeued, or failed for good at the last.
     *
     * <p>Beside {@link #AGENT_RESULT_SUBMITTED} because it is the other way an agent ends its hold on
     * a scan, and a scan that failed "on an agent's say-so" is a question somebody asks afterwards. A
     * report whose attestation does not verify is recorded as {@link #AGENT_RESULT_REFUSED}.
     */
    AGENT_SCAN_FAILED,

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
     * An agent's sealing key was accepted: its signature verified against the pinned key, and it is
     * newer than the one it replaces.
     *
     * <p>Written when the key changes — at every start of the agent, since the pair lives as long as
     * the process — so that "which key were this agent's credentials sealed for, and since when" has
     * an answer in the log.
     */
    AGENT_SEALING_KEY_ACCEPTED,

    /**
     * A sealing key was refused: its signature did not verify against the pinned key, or it was older
     * than the one already accepted.
     *
     * <p>The agent that holds the pinned key signs every key it announces. An announcement that does
     * not verify is a misconfigured agent, or a key that the agent did not make; an older one is a
     * clock put back, or an announcement recorded and sent again. The credential it would have
     * received is withheld either way, and the entry is what makes the attempt visible.
     */
    AGENT_SEALING_KEY_REFUSED,

    /**
     * An administrator made the control plane forget an agent's sealing key — deliberately, or by
     * pinning its signing key anew.
     *
     * <p>The one way back from a key that can no longer be replaced forwards: an agent whose clock was
     * put back, a host suspected of having leaked the key. It withholds every delegated credential
     * until the agent proves a new key, and it is a change of trust like pinning, so it is recorded
     * as one.
     */
    AGENT_SEALING_KEY_RESET,

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
    POSTURE_DIGEST_SENT,

    /**
     * A plugin was registered by the platform governor: a third-party image, pinned by digest, that
     * will read the source of every project it is activated for. The entry carries the image, the
     * languages, and the network exception with its justification when there is one.
     */
    PLUGIN_REGISTERED,

    /** A plugin's manifest changed — a new image digest, arguments, the network — under the same id. */
    PLUGIN_UPDATED,

    /** A plugin was disabled or enabled: every activation stops, or resumes, at the next scan. */
    PLUGIN_ENABLED_CHANGED,

    /** A plugin was switched on for a project: it now reads that project's repositories. */
    PLUGIN_ACTIVATED,

    PLUGIN_DEACTIVATED,

    /**
     * An internal SARIF source was declared, changed or removed — which key may deposit findings, for
     * which project or repository, from which tools. A declaration is the platform saying "this
     * producer is inside the organisation", so it is the governor's and it is audited.
     */
    SARIF_SOURCE_CHANGED,

    /** A declared source's SARIF report was accepted and folded into a repository's backlog. */
    SARIF_IMPORTED,

    /**
     * An import was refused for what it claimed rather than for its form: no declared source for the
     * key, a repository outside the source's scope, a tool the source is not declared for.
     */
    SARIF_IMPORT_REFUSED,

    /**
     * A declared source's coverage report was accepted for a repository: the figure a checklist
     * reads, bound to the key that sent it and the document's SHA-256 (decision 0032 §7).
     */
    COVERAGE_IMPORTED,

    /** A declared source's test report was accepted for a repository, with its totals. */
    TEST_REPORT_IMPORTED,

    /**
     * A coverage or test report was refused for what it claimed rather than for its form: no enabled
     * source for the key, a kind its source is not declared for, a repository outside its scope.
     */
    REPORT_IMPORT_REFUSED,

    /**
     * A checklist template's workbook was imported as a new draft version (decision 0032 §3). The
     * entry carries the file's SHA-256, which a delivered checklist is compared with.
     */
    CHECKLIST_TEMPLATE_IMPORTED,

    /**
     * A draft's layout and answer words were confirmed, and its items read from the workbook by them.
     * The words are what the renderer will write into every document, so who chose them is recorded.
     */
    CHECKLIST_TEMPLATE_LAYOUT_CONFIRMED,

    /**
     * A draft's items were paired by hand with the previous version's: "same control, reworded".
     * A pair decides which of a project's answers follow into the new version, to be confirmed.
     */
    CHECKLIST_TEMPLATE_ITEMS_PAIRED,

    /**
     * What proof some of a draft's lines ask for, and how long a proof holds, was set. A requirement
     * decides what every project must attach before it can submit, so who set it is recorded — an
     * operation of its own, not a layout confirmation: nothing of the workbook was read again.
     */
    CHECKLIST_TEMPLATE_EVIDENCE_SET,

    /**
     * Rules were bound to some of a draft's lines, or unbound from them (decision 0032 §6). A binding
     * decides what a line is measured by and what a "yes" against it may claim, so who wrote which
     * parameters is recorded — an operation of its own, as the evidence requirement is.
     */
    CHECKLIST_TEMPLATE_RULES_BOUND,

    /** A new draft was derived from a published version: same workbook, same layout, same items. */
    CHECKLIST_TEMPLATE_DERIVED,

    /** A template version was published: what projects attest to from now on. */
    CHECKLIST_TEMPLATE_PUBLISHED,

    /** A published version was retired — no new checklist opens on it — or a draft was set aside. */
    CHECKLIST_TEMPLATE_RETIRED,

    /** A project's first checklist was opened on a published template version (decision 0032 §5). */
    CHECKLIST_OPENED,

    /**
     * A project's checklist was moved to another template version: a new revision, the answers carried
     * from the previous one — as current where the line is unchanged, to be confirmed where it changed.
     */
    CHECKLIST_MOVED_TO_VERSION,

    /** A line was answered, or a carried answer confirmed: a new row of its history, never an edit. */
    CHECKLIST_ANSWERED,

    /** A proof — a link or a file, with its SHA-256 — was attached to a line. */
    CHECKLIST_EVIDENCE_ADDED,

    /** A proof was withdrawn from a draft's line; the row is kept, dated and attributed. */
    CHECKLIST_EVIDENCE_WITHDRAWN,

    /** A revision was submitted for sign-off: every line answered, commented and proven as it asks. */
    CHECKLIST_SUBMITTED,

    /** A submitted revision was returned to its authors, with a reason. */
    CHECKLIST_RETURNED,

    /** A submitted revision was signed off — the release attestation, and who gave it. */
    CHECKLIST_SIGNED_OFF,

    /**
     * A sign-off was refused for what the revision or the signer is — the signer one of its authors
     * while four-eyes is on, or a proof that stopped holding since the submission — rather than for
     * the request's form.
     */
    CHECKLIST_SIGN_OFF_REFUSED,

    /** A signed-off revision was reopened: the next revision, on the same version, every answer carried. */
    CHECKLIST_REOPENED,

    /**
     * A revision's document was downloaded (decision 0032 §9): a signed-off revision's stored, signed
     * package, or a revision not signed off rendered unsigned for the request. The entry names which, and
     * the package's SHA-256.
     */
    CHECKLIST_EXPORTED;

    /** The value stored in the column. The enum name is the wire name, here deliberately. */
    public String wireName() {
        return name();
    }
}
