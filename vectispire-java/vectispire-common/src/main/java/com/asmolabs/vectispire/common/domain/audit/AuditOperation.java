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
     * The platform governor let a plugin run although its manifest declares no signer, with a written
     * justification the entry carries — the waiver of the signature requirement every executor applies
     * by default (decision 0017 §9.1). Code nobody vouched for now reads the source of every project the
     * plugin is on for, which is why it is a gesture of its own and not a setting.
     */
    PLUGIN_SIGNATURE_WAIVED,

    /** The waiver was withdrawn: from the next scan the plugin runs only once a declared signer verifies. */
    PLUGIN_SIGNATURE_WAIVER_REVOKED,

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
     * A declared source's build SBOM — CycloneDX JSON — was accepted for a repository and completes its
     * scans' inventories (decision 0039); the entry carries the document's SHA-256 and the scan completed.
     */
    BUILD_SBOM_IMPORTED,

    /**
     * A coverage report, a test report or a build SBOM was refused for what it claimed rather than for its
     * form: no enabled source for the key, a kind its source is not declared for, a repository outside its
     * scope.
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
    CHECKLIST_EXPORTED,

    /**
     * A project's export — its whole triaged state as one signed JSON document (decision 0035 §1) — left
     * the platform: downloaded by an account or an integration key. The entry names the project, the
     * schema version, how many issues and components it carried, and its SHA-256.
     */
    PROJECT_EXPORTED,

    /**
     * The platform governor registered a report plugin (decision 0035 §4): the entry names the manifest's
     * digest, its image, its export major, its output and its signer, and whether it serves at once
     * (four-eyes off) or waits for a second person's approval.
     */
    REPORT_PLUGIN_REGISTERED,

    /** A report plugin was given another manifest — pending approval, or serving at once. */
    REPORT_PLUGIN_UPDATED,

    /**
     * A second person approved a report plugin's manifest digest — or, four-eyes off, anybody who writes
     * governance: code may now produce documents under the installation's key.
     */
    REPORT_PLUGIN_APPROVED,

    REPORT_PLUGIN_ENABLED_CHANGED,

    /** A report plugin was switched on for a project: it may be given that project's whole export. */
    REPORT_PLUGIN_ACTIVATED,

    REPORT_PLUGIN_DEACTIVATED,

    /**
     * The platform governor withdrew a report plugin's manifest digest, with a justification the entry
     * carries: it never runs again, and every document it produced is served as withdrawn.
     */
    REPORT_PLUGIN_WITHDRAWN,

    /**
     * A forge connection (decision 0037 §2) was created, renamed, given another token, another pinned CA or
     * another network statement, or deleted: a standing read access to an organisation's whole list of
     * repositories. Its own operation rather than {@code SETTING_UPDATED}, so an auditor finds it without
     * reading every settings change. The entry names the forge, the address, the credential the forge
     * identified and whether it can write — never the token.
     */
    FORGE_CONNECTION_CHANGED,

    /**
     * A forge connection was refused for what its address or its token is — a destination the outbound
     * guard blocks, or a token broader than read-only (decision 0037 §2). The refusals an administrator
     * simply fixes (a mistyped token, a server too old) are not recorded.
     */
    FORGE_CONNECTION_REFUSED,

    /**
     * A discovery of a forge connection was queued (decision 0037 §3): an administrator asked for the list of
     * every repository the connection's token can read. Written when the run is queued, never on a refusal (a
     * discovery already running answers with that one). The entry names the connection and the run — never the
     * token.
     */
    FORGE_DISCOVERY_REQUESTED,

    /**
     * Repositories were imported from a forge connection's discovery (decision 0037 §5): the one entry summarising
     * the gesture — the connection, the discovery, how many targets, solutions and projects were created, how many
     * repositories were skipped and why, and the first scans queued. Each target, solution and project created
     * has its own entry beside it, as the forms write them.
     */
    FORGE_IMPORT_APPLIED,

    /**
     * A report was requested of a report plugin for a project (decision 0035 §2): queued for the control plane's
     * executor. The entry names the plugin and the run.
     */
    REPORT_REQUESTED,

    /**
     * A report run produced: its plugin exited {@code 0}, wrote its file, the file passed its declared type's
     * check, and its package was signed and stored. The entry names the run, the output's and the package's
     * SHA-256, the manifest and image digests, the export's SHA-256 and the signing key.
     */
    REPORT_PRODUCED,

    /** A report run failed — an exit code, a timeout, a full output, a lost executor — with its reason. */
    REPORT_FAILED,

    /**
     * A report plugin was not started for want of a verified signer, or of the export major it reads; or it ran and
     * its output was not what its manifest declares, and was discarded unsigned. The entry carries the reason, the
     * refused output's SHA-256 where there was one, and cosign's or the check's words.
     */
    REPORT_REFUSED,

    /**
     * A produced report's package — the document, its signature and its provenance — was downloaded (decision 0035
     * §4). The entry names the run, the output's and the package's SHA-256.
     */
    REPORT_DOWNLOADED,

    /**
     * The platform governor switched an integration on or off (decision 0040): a forge kind, a SIEM
     * transport, an AI provider, a notification channel or a tracker. The resource is the integration's
     * key; the entry says which way. Its own operation rather than {@code SETTING_UPDATED}, so an auditor
     * finds what the installation was allowed to reach, and when, without reading every settings change.
     */
    INTEGRATION_ENABLED_CHANGED;

    /** The value stored in the column. The enum name is the wire name, here deliberately. */
    public String wireName() {
        return name();
    }
}
