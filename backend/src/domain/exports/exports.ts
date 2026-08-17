import { QUALITY_TYPES } from '../gate/policy-gate';
import { canonical } from '../common/timestamp';

/**
 * Issue export formats: SARIF, OpenVEX and CSV.
 *
 * VEX is the reason triage decisions are stored in the standard's vocabulary rather than
 * as free text — this is therefore a serialization, not a translation. Every field an
 * OpenVEX statement needs is already on the issue; nothing here has to infer or invent,
 * and that is what makes the document trustworthy enough to hand to a customer or an
 * auditor.
 *
 * SARIF has another purpose: OpenVEX and CSV address people outside the pipeline, SARIF
 * exists so that a finding stops living only inside Zanshin. It is what GitHub code
 * scanning, GitLab and Azure DevOps ingest natively, and therefore what puts an issue in
 * front of the person who introduced it, annotated on the line, in the merge request —
 * instead of a dashboard they have no reason to open.
 *
 * Pure functions: the HTTP layer decides how to deliver them, and a download button in
 * the UI reuses them unchanged.
 *
 * Checked against `test/vectors/exports.json`, produced by the real Python module.
 */

export const OPENVEX_CONTEXT = 'https://openvex.dev/ns/v0.2.0';
export const SARIF_VERSION = '2.1.0';
export const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';

const STATE_RESOLVED = 'resolved';
const TRIAGE_UNDER_REVIEW = 'under_review';
const TRIAGE_AFFECTED = 'affected';
const TRIAGE_NOT_AFFECTED = 'not_affected';
const TRIAGE_FIXED = 'fixed';

/**
 * Zanshin's triage vocabulary is already OpenVEX's, with one exception: `under_review` is
 * spelled `under_investigation` in the specification.
 */
const VEX_STATUS: Record<string, string> = {
    [TRIAGE_UNDER_REVIEW]: 'under_investigation',
    [TRIAGE_AFFECTED]: 'affected',
    [TRIAGE_NOT_AFFECTED]: 'not_affected',
    [TRIAGE_FIXED]: 'fixed'
};

/**
 * SARIF has four levels and no notion of "critical". Anything a security tool would call
 * critical or high has to land on `error`, because `warning` is what a reviewer scrolls
 * past without reading.
 */
const SARIF_LEVEL: Record<string, string> = {
    critical: 'error',
    high: 'error',
    medium: 'warning',
    low: 'note',
    negligible: 'note',
    unknown: 'warning'
};

/**
 * GitHub sorts and filters on this property, **not** on `level`: it is what keeps a
 * critical distinguishable from a high once both are `error`. The values follow the CVSS
 * bands GitHub documents.
 */
const SECURITY_SEVERITY: Record<string, string> = {
    critical: '9.5',
    high: '8.0',
    medium: '5.5',
    low: '3.0',
    negligible: '1.0'
};

const ISSUE_TYPE_LABEL: Record<string, string> = {
    vulnerability: 'Vulnerability',
    secret: 'Exposed secret',
    iac: 'Infrastructure configuration',
    license: 'License',
    eol: 'End of life',
    ai_review: 'AI review',
    sast: 'Vulnerable code',
    quality: 'Code quality'
};

export const CSV_COLUMNS = [
    'id',
    'type',
    'identifier',
    'severity',
    'cvss_score',
    'epss_score',
    'is_kev',
    'package_name',
    'package_version',
    'purl',
    'dependency',
    'file_path',
    'line',
    'fix_state',
    'fix_versions',
    'state',
    'triage_status',
    'triage_justification',
    'triaged_by',
    'triaged_at',
    'triage_expires_at',
    'first_seen_at',
    'last_seen_at',
    'times_seen',
    'link'
] as const;

/**
 * An issue as the exports read it.
 *
 * Timestamps are canonicalized on the way out — never rendered by the driver's own
 * formatting, which loses the microsecond and applies a timezone (see
 * `common/timestamp.ts`).
 */
export interface ExportableIssue {
    id: number;
    fingerprint: string | null;
    type: string | null;
    identifier: string | null;
    severity: string | null;
    cvssScore: number | null;
    epssScore: number | null;
    isKev: boolean | null;
    packageName: string | null;
    packageVersion: string | null;
    purl: string | null;
    isDirectDependency: boolean | null;
    filePath: string | null;
    line: number | null;
    fixState: string | null;
    fixVersions: string | null;
    link: string | null;
    description: string | null;
    state: string | null;
    triageStatus: string | null;
    triageJustification: string | null;
    triageComment: string | null;
    triagedBy: string | null;
    triagedAt: Date | null;
    triageExpiresAt: Date | null;
    firstSeenAt: Date | null;
    lastSeenAt: Date | null;
    timesSeen: number | null;
}

// --------------------------------------------------------------------------- OpenVEX

export interface OpenVexOptions {
    author: string;
    productId: string;
    documentId: string;
    /** Supplied by the caller: a VEX document is an assertion about who said what and
     *  when, which belongs to whoever publishes it, not to a utility function. */
    timestamp: Date;
    version?: number;
}

/**
 * An OpenVEX document for a product, from its vulnerability issues.
 *
 * Only `vulnerability` issues are included: VEX is defined over vulnerability
 * identifiers, and a hardcoded secret or a failed IaC check has no CVE to make a
 * statement about. Issues with no identifier are discarded for the same reason — an
 * anonymous statement is not one.
 */
export function buildOpenVexDocument(issues: Iterable<ExportableIssue>, options: OpenVexOptions): Record<string, unknown> {
    const statements: Record<string, unknown>[] = [];

    for (const issue of issues) {
        if (issue.type !== 'vulnerability' || !issue.identifier) continue;

        let status = VEX_STATUS[issue.triageStatus ?? ''] ?? 'under_investigation';
        // An issue that is resolved and was never triaged is factually fixed: the
        // scanner stopped seeing it. Saying "under investigation" about something that has
        // gone would be misleading in a document made to answer exactly that.
        if (issue.state === STATE_RESOLVED && issue.triageStatus === TRIAGE_UNDER_REVIEW) {
            status = 'fixed';
        }

        const statement: Record<string, unknown> = {
            vulnerability: { name: issue.identifier },
            products: [{ '@id': options.productId }],
            status
        };

        if (status === 'not_affected') {
            // Required by the specification for this status, and guaranteed present by
            // the triage service.
            statement.justification = issue.triageJustification;
            if (issue.triageComment) statement.impact_statement = issue.triageComment;
        } else if (status === 'affected' && issue.triageComment) {
            // For "affected", the free text belongs to the action statement.
            statement.action_statement = issue.triageComment;
        }

        if (issue.purl) {
            statement.products = [{ '@id': options.productId, identifiers: { purl: issue.purl } }];
        }
        // RFC 3339, as the OpenVEX specification requires. The previous document carried
        // "2026-08-10T08:00:00" with no timezone, which is not a valid instant under that
        // standard: a strict consumer was entitled to refuse it.
        if (issue.triagedAt) statement.timestamp = canonical(issue.triagedAt);
        else if (issue.lastSeenAt) statement.timestamp = canonical(issue.lastSeenAt);

        statements.push(statement);
    }

    return {
        '@context': OPENVEX_CONTEXT,
        '@id': options.documentId,
        author: options.author,
        timestamp: canonical(options.timestamp),
        version: options.version ?? 1,
        tooling: 'Zanshin',
        statements
    };
}

// ----------------------------------------------------------------------------- SARIF

export interface SarifOptions {
    targetName: string;
    toolVersion?: string;
    informationUri?: string | null;
}

/**
 * A SARIF 2.1.0 log for a target's issues.
 *
 * Decisions worth stating, because SARIF is permissive enough that a technically valid
 * document can still be useless in a code scanning interface:
 *
 * - **Triaged issues are `suppressions`, not omissions.** Removing them would make a
 *   platform report them as new on the next upload, undoing the triage work; and a
 *   suppression carries its justification, so the reviewer sees *why* it is set aside.
 *   `not_affected` and `fixed` are suppressed, `affected` is not — deciding that an issue
 *   is real must stay visible.
 * - **Resolved issues are excluded.** They are gone; SARIF's job is the current state of
 *   the branch being built.
 * - **`partialFingerprints` carries Zanshin's fingerprint**, which lets the platform
 *   match an issue from one upload to the next even if the file moves or the line shifts.
 * - **Every result has a location**, falling back to the repository root when a
 *   dependency issue has no file. GitHub silently discards results with no location, so
 *   an "honestly empty" location would make the vulnerability findings disappear — that
 *   is, most of them.
 *
 * Rules are emitted per distinct identifier rather than per issue: that is what the SARIF
 * model means by a rule, and what lets a platform group them.
 */
export function buildSarifDocument(issues: Iterable<ExportableIssue>, options: SarifOptions): Record<string, unknown> {
    const current = [...issues].filter((issue) => issue.state !== STATE_RESOLVED);

    // A `Map` and not an object: the rules' insertion order determines `ruleIndex`, and
    // an object would reorder keys that look like integers.
    const rules = new Map<string, Record<string, unknown>>();
    const ruleIndex = new Map<string, number>();
    const results: Record<string, unknown>[] = [];

    for (const issue of current) {
        const ruleId = sarifRuleId(issue);
        if (!rules.has(ruleId)) {
            ruleIndex.set(ruleId, rules.size);
            rules.set(ruleId, sarifRule(issue, ruleId));
        }

        const properties: Record<string, unknown> = {
            zanshinIssueId: issue.id,
            type: issue.type,
            firstSeen: issue.firstSeenAt ? canonical(issue.firstSeenAt) : '',
            timesSeen: issue.timesSeen || 1
        };
        if (issue.isDirectDependency !== null && issue.isDirectDependency !== undefined) {
            properties.dependency = issue.isDirectDependency ? 'direct' : 'transitive';
        }

        const result: Record<string, unknown> = {
            ruleId,
            ruleIndex: ruleIndex.get(ruleId),
            level: SARIF_LEVEL[(issue.severity || 'unknown').toLowerCase()] ?? 'warning',
            message: { text: sarifMessage(issue) },
            locations: [sarifLocation(issue)],
            partialFingerprints: { zanshinIssueFingerprint: issue.fingerprint },
            properties
        };

        if (isSuppressed(issue)) {
            result.suppressions = [
                {
                    // "external": the decision was taken in Zanshin, not in a source
                    // annotation, which is what this kind of suppression documents.
                    kind: 'external',
                    justification: suppressionJustification(issue)
                }
            ];
        }
        results.push(result);
    }

    const driver: Record<string, unknown> = {
        name: 'Zanshin',
        version: options.toolVersion ?? '1.0.0'
    };
    // Absent rather than null when not supplied: `**({...} if x else {})`.
    if (options.informationUri) driver.informationUri = options.informationUri;
    driver.rules = [...rules.values()];

    return {
        $schema: SARIF_SCHEMA,
        version: SARIF_VERSION,
        runs: [
            {
                tool: { driver },
                results,
                properties: { target: options.targetName }
            }
        ]
    };
}

/** `security` only for what is genuinely a security finding. */
function sarifTags(issue: ExportableIssue): string[] {
    if (issue.type != null && QUALITY_TYPES.includes(issue.type)) return ['quality', issue.type];
    return ['security', issue.type as string];
}

/**
 * Stable, and partitioned by type.
 *
 * A gitleaks rule and a checkov check can collide on an identifier, and a platform
 * indexed on `ruleId` would then merge two unrelated classes of issue under one title.
 */
function sarifRuleId(issue: ExportableIssue): string {
    return `zanshin/${issue.type}/${issue.identifier || 'unspecified'}`;
}

function sarifRule(issue: ExportableIssue, ruleId: string): Record<string, unknown> {
    const label = (issue.type != null ? ISSUE_TYPE_LABEL[issue.type] : undefined) ?? issue.type;
    const properties: Record<string, unknown> = { tags: sarifTags(issue) };

    const rule: Record<string, unknown> = {
        id: ruleId,
        name: (issue.identifier || issue.type || '').replace(/ /g, ''),
        shortDescription: { text: `${label}: ${issue.identifier || 'unidentified'}` },
        properties
    };

    if (issue.description) rule.fullDescription = { text: issue.description.slice(0, 1000) };
    if (issue.link) rule.helpUri = issue.link;

    const severity = (issue.severity || '').toLowerCase();
    if (severity in SECURITY_SEVERITY) properties['security-severity'] = SECURITY_SEVERITY[severity];

    return rule;
}

/**
 * What the developer reads in the merge request, hence what says what to do.
 *
 * The fixed version is the most useful thing to put in front of someone who has thirty
 * seconds: it turns "there is a CVE" into "change this line".
 */
function sarifMessage(issue: ExportableIssue): string {
    const parts: string[] = [];
    if (issue.packageName) {
        parts.push(issue.packageVersion ? `${issue.packageName} ${issue.packageVersion}` : issue.packageName);
    }
    parts.push(issue.identifier || (issue.type != null ? ISSUE_TYPE_LABEL[issue.type] : undefined) || (issue.type as string));

    let message = parts.join(' — ');
    if (issue.fixVersions) message += ` — fixed in ${issue.fixVersions}`;
    else if (issue.fixState === 'not-fixed') message += ' — no published fix';
    if (issue.isKev) message += ' — known active exploitation (CISA KEV)';
    if (issue.isDirectDependency === false) message += ' — transitive dependency';
    return message;
}

function sarifLocation(issue: ExportableIssue): Record<string, unknown> {
    const physicalLocation: Record<string, unknown> = {
        // A relative URI, as SARIF requires for source the consumer resolves against the
        // repository it has just checked out.
        artifactLocation: { uri: issue.filePath || '.' }
    };
    if (issue.line) physicalLocation.region = { startLine: Math.trunc(issue.line) };

    const location: Record<string, unknown> = { physicalLocation };
    if (issue.purl) location.logicalLocations = [{ name: issue.purl, kind: 'package' }];
    return location;
}

function isSuppressed(issue: ExportableIssue): boolean {
    return issue.triageStatus === TRIAGE_NOT_AFFECTED || issue.triageStatus === TRIAGE_FIXED;
}

function suppressionJustification(issue: ExportableIssue): string {
    const parts: string[] = [issue.triageStatus as string];
    if (issue.triageJustification) parts.push(issue.triageJustification);
    if (issue.triageComment) parts.push(issue.triageComment);
    if (issue.triagedBy) parts.push(`decided by ${issue.triagedBy}`);
    // `.date().isoformat()` in Python: the date part alone, hence the first ten
    // characters of an isoformat.
    if (issue.triageExpiresAt) parts.push(`to review on ${issue.triageExpiresAt.toISOString().slice(0, 10)}`);
    return parts.join(' — ');
}

// ------------------------------------------------------------------------------- CSV

/**
 * Flat CSV of the issues, one row each, for reporting and spreadsheets.
 *
 * Deliberately one column per stored field rather than a chosen subset: the people who
 * ask for CSV are the ones who want to cross-reference it themselves.
 */
export function buildIssuesCsv(issues: Iterable<ExportableIssue>): string {
    const rows: string[] = [CSV_COLUMNS.join(',')];

    for (const issue of issues) {
        rows.push(
            [
                String(issue.id),
                issue.type ?? '',
                issue.identifier || '',
                issue.severity || '',
                pythonNumber(issue.cvssScore),
                pythonNumber(issue.epssScore),
                issue.isKev ? 'true' : 'false',
                issue.packageName || '',
                issue.packageVersion || '',
                issue.purl || '',
                dependencyLabel(issue.isDirectDependency),
                issue.filePath || '',
                issue.line ? String(issue.line) : '',
                issue.fixState || '',
                issue.fixVersions || '',
                issue.state ?? '',
                issue.triageStatus ?? '',
                issue.triageJustification || '',
                issue.triagedBy || '',
                // Canonicalized as everywhere else: a CSV compared byte for byte must not
                // depend on the timezone of the machine that produced it.
                issue.triagedAt ? canonical(issue.triagedAt) : '',
                issue.triageExpiresAt ? canonical(issue.triageExpiresAt) : '',
                issue.firstSeenAt ? canonical(issue.firstSeenAt) : '',
                issue.lastSeenAt ? canonical(issue.lastSeenAt) : '',
                String(issue.timesSeen || 1),
                issue.link || ''
            ]
                .map(quoteCsvField)
                .join(',')
        );
    }

    // Python's `csv.writer` terminates its rows with CRLF (the "excel" dialect),
    // including the last one. Using `\n` would produce a file most tools would read
    // anyway — hence a divergence nobody would notice until a strict consumer refused
    // it.
    return rows.map((row) => `${row}\r\n`).join('');
}

/**
 * The characters by which a spreadsheet decides a cell is a **formula**.
 *
 * Excel, LibreOffice and Google Sheets evaluate a cell starting with any of them. Tab and
 * carriage return are in the list because Excel skips them before resuming its parse:
 * `\t=cmd|…` is evaluated as `=cmd|…`.
 */
const FORMULA_PREFIX = /^[=+\-@\t\r]/;

/**
 * Quoting in the manner of `QUOTE_MINIMAL`, **preceded by formula neutralization**.
 *
 * **This file's content comes from scanned repositories**, hence from outside the trust
 * boundary: a package name, a file path, a rule identifier are chosen by whoever can
 * commit to the target. The reader, meanwhile, is a security operator opening the file in
 * a spreadsheet — which is the whole point of the CSV export.
 *
 * A package named `=cmd|'/c calc'!A1` executes on open; `=HYPERLINK(...&A1&B1)` exfiltrates
 * the neighbouring cells — that is, the rest of the backlog — to a host of the attacker's
 * choosing, with no prompt at all. The apostrophe forces text mode.
 *
 * **Quoting does not protect**: the spreadsheet strips the quotes before evaluating.
 * Neutralization must therefore precede quoting, not stand in for it.
 */
function quoteCsvField(value: string): string {
    const safe = FORMULA_PREFIX.test(value) ? `'${value}` : value;
    if (!/[",\r\n]/.test(safe)) return safe;
    return `"${safe.replace(/"/g, '""')}"`;
}

/**
 * Empty rather than "unknown": a column filled with the word "unknown" reads as a finding
 * about the dependency, when the honest statement is that we have nothing to say about it.
 */
function dependencyLabel(isDirect: boolean | null | undefined): string {
    if (isDirect === null || isDirect === undefined) return '';
    return isDirect ? 'direct' : 'transitive';
}

/**
 * Python's `str(float)`, which keeps the decimal on whole values: `str(9.0)` returns
 * "9.0", where `String(9)` returns "9" in JavaScript.
 *
 * On a CVSS score column, half the values are whole numbers — the divergence would
 * therefore touch every other row of an export handed to an auditor.
 */
function pythonNumber(value: number | null | undefined): string {
    if (value === null || value === undefined) return '';
    return Number.isInteger(value) ? `${value}.0` : String(value);
}
