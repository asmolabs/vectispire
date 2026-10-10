import document from '../../../../openapi.json';
import type { components } from '../api.generated';

type Schemas = components['schemas'];

/**
 * Checks a test fixture against the schema it claims to be, from the control plane's own document.
 *
 * <h2>The hole this closes</h2>
 *
 * <p><b>A fixture is a belief about the server that nothing confronts with the server.</b> Three
 * layers already stand between a screen and the API: {@code ClientContractSpecTest} pins the
 * document to the routes, {@code Refine} pins the client's types to the document, and Angular's
 * template checker pins a screen to its types. All three check <em>types</em>. A fixture is a
 * literal, written by hand, and a literal that is wrong is simply a different test passing.
 *
 * <p>That is not hypothetical here. The scan detail screen read `detail.id` where the server
 * nests the summary under `scan`, and ten fields of its header rendered blank — while the smoke
 * fixture spread the summary flat, so the test agreed with the screen and both were wrong. The
 * gate policy fixtures went on passing after a field was added to the request, because they
 * described a policy the server had stopped sending. Neither was caught by a type.
 *
 * <h2>What it checks, and why it stops there</h2>
 *
 * <ul>
 *   <li><b>Every property the fixture carries exists in the schema.</b> This is the one that
 *       catches a shape flattened, a field renamed, or a key invented — the failures above.
 *   <li><b>Every property the document marks required is present.</b> Which is the primitives:
 *       springdoc marks nothing else, and the client's own claims live in `api.models.ts`.
 *   <li><b>Scalars hold the declared type.</b> A number where a string is documented is a
 *       fixture that would have to be wrong on the wire too.
 *   <li><b>A closed vocabulary holds one of its words</b> — a declared enum, or one of the
 *       {@link VOCABULARIES} the server closes and the document leaves open (roles, scan
 *       statuses, an issue's state, severity, type and triage status).
 * </ul>
 *
 * <p><b>`null` is accepted everywhere, and that is not laxity.</b> The document marks nothing
 * nullable while this server sends `displayName: null`, so refusing null here would reject
 * fixtures that are exactly right. Nullability is claimed in `api.models.ts`, per field, where
 * a person can be held to it.
 *
 * <p>Unknown schema names fail rather than pass: a fixture pointing at a schema the document does
 * not have is a fixture nobody can check, and silently accepting it would be the failure this
 * whole file is about.
 */
export function asSchema<K extends keyof Schemas, T>(name: K, fixture: T): T {
    const problems = check(name, fixture, name);
    if (problems.length > 0) {
        throw new Error(
            `The fixture does not match the schema "${String(name)}" the control plane publishes:\n` +
                problems.map((problem) => `  · ${problem}`).join('\n') +
                '\n\nIf the change is intended, regenerate the contract, then the types built from it:\n' +
                "  ./gradlew :vectispire-core:test --tests '*ClientContractSpecTest*' " +
                '-Dvectispire.openapi.write=true\n' +
                '  npm run generate:api   (in vectispire-angular — CI refuses a stale api.generated.ts)'
        );
    }
    return fixture;
}

/**
 * The same, for a route that answers with a list.
 *
 * <p><b>The fixture comes back as itself, not as the schema's type.</b> Every property the document
 * declares is optional — springdoc marks only primitives — so returning `Schemas[K]` would hand
 * every call site a shape where nothing is known to be present, and the specs would spend their
 * lines asserting away a looseness that is an artefact of the generator. The literal already has
 * the better type; what this adds is the check that it is also the true one.
 */
export function asSchemaList<K extends keyof Schemas, T>(name: K, fixtures: T[]): T[] {
    return fixtures.map((fixture) => asSchema(name, fixture));
}

interface JsonSchema {
    $ref?: string;
    type?: string;
    format?: string;
    required?: string[];
    properties?: Record<string, JsonSchema>;
    items?: JsonSchema;
    additionalProperties?: JsonSchema | boolean;
    enum?: unknown[];
}

const SCHEMAS = (document as { components: { schemas: Record<string, JsonSchema> } }).components.schemas;

/**
 * The vocabularies the server closes and the document leaves open.
 *
 * <p>These fields are Java `String`s on the wire, filled from an enum's wire name, so springdoc
 * types them `string` and nothing else — and the enum check below never sees them. That is how a
 * login fixture came to sign in as `ADMINISTRATOR` and the account screen to demote to `READER`:
 * neither role exists, both passed, and a screen keyed to `ADMIN` would have been tested against a
 * role it can never receive. Each list is copied from the enum named beside it; a value added to
 * the enum without being added here fails a fixture loudly, which is the direction to err in.
 */
const ROLES = ['SUPERUSER', 'ADMIN', 'CISO', 'SECURITY_CHAMPION', 'AUDITOR', 'USER']; // Role
const SCAN_STATUSES = ['pending', 'scanning', 'completed', 'failed']; // ScanStatus
const ISSUE_STATES = ['open', 'resolved']; // IssueState
const ISSUE_SEVERITIES = ['critical', 'high', 'medium', 'low', 'negligible', 'unknown']; // Severity
const FINDING_TYPES = [
    'vulnerability',
    'secret',
    'iac',
    'license',
    'eol',
    'sast',
    'ai_review',
    'plugin',
    'imported',
    'quality'
]; // FindingType
const PLUGIN_STATES = ['produced', 'not_applicable', 'absent', 'refused']; // PluginOutcome.State
const PLUGIN_REFUSALS = ['unsigned', 'signature_unverified', 'registry_authentication_required']; // PluginStep.Refusal
const PLUGIN_SIGNATURES = ['verified', 'waived', 'not_required']; // PluginStep.Signature
const TRIAGE_STATUSES = ['under_review', 'affected', 'pending_approval', 'not_affected', 'will_not_fix', 'fixed']; // TriageStatus
const CHECKLIST_VERSION_STATUSES = ['draft', 'published', 'retired']; // TemplateVersionStatus
const CHECKLIST_CHANGES = ['unchanged', 'changed', 'added', 'removed']; // ChecklistTemplateService.change
const CHECKLIST_STATUSES = ['draft', 'submitted', 'signed_off', 'superseded']; // ChecklistStatus
const CHECKLIST_ANSWERS = ['yes', 'no', 'not_applicable']; // ChecklistAnswer
const CHECKLIST_EVIDENCE_KINDS = ['none', 'link_or_file', 'file']; // EvidenceRequirement.Kind
const CHECKLIST_PROOF_KINDS = ['link', 'file']; // t_checklist_evidence.kind
const RULE_KINDS = [
    'dependency_analysis',
    'findings_threshold',
    'coverage_threshold',
    'test_suite_passed',
    'component_versions',
    'component_present',
    'change_review'
]; // ChecklistRule.Kind
const COVERAGE_METRICS = ['line', 'branch']; // ChecklistRule.Metric
const COVERAGE_AGGREGATIONS = ['per_repository', 'project_weighted']; // ChecklistRule.Aggregation
const MEASUREMENT_OUTCOMES = ['pass', 'fail', 'no_data']; // MeasurementOutcome
const NO_DATA_REASONS = [
    'no_repository',
    'never_examined',
    'forge_unlinked',
    'forge_unreadable',
    'step_absent',
    'plugin_unsigned',
    'plugin_signature_unverified',
    'plugin_registry_authentication_required',
    'language_not_analysed',
    'examination_unrecorded',
    'languages_unrecorded',
    'inventory_absent',
    'version_unrecorded',
    'packages_unrecorded',
    'packages_not_kept',
    'scope_matches_nothing',
    'review_incomplete',
    'no_change_merged',
    'stale',
    'not_applicable_anywhere',
    'suite_not_found',
    'no_test_ran'
]; // NoDataReason
const RECONCILIATIONS = [
    'consistent',
    'contradicted',
    'declared_not_measured',
    'understated',
    'excluded',
    'not_measured_here',
    'unanswered'
]; // Reconciliation
const MEASUREMENT_PURPOSES = ['read', 'answer', 'submission', 'sign_off']; // MeasurementPurpose
const EVIDENCE_SOURCES = ['scan', 'sarif_import', 'coverage_import', 'test_report_import', 'forge_review']; // MeasurementFacts.Source
/**
 * A target's criticality — `AssetTier.name()`. The screenshot fixture sent `TIER_1` and `TIER_3`,
 * which the server has never written, and both repositories were captured as tier 2: the screen
 * falls back on it, as `AssetTier.parse` does.
 */
const ASSET_TIERS = ['TIER_1_MISSION_CRITICAL', 'TIER_2_BUSINESS_OPERATIONAL', 'TIER_3_INTERNAL']; // AssetTier
/** A verdict's target, as `GateController.view` spells it — upper case, unlike everywhere else. */
const VERDICT_TARGET_KINDS = ['REPOSITORY', 'CONTAINER']; // GateController.RegisteredVerdict
/** A repository's status in a measurement: examined, not applicable, or the reason it has no data. */
const LOOK_STATUSES = ['examined', 'not_applicable', ...NO_DATA_REASONS]; // Measurement.RepositoryEvidence

const ISSUE = { state: ISSUE_STATES, severity: ISSUE_SEVERITIES, type: FINDING_TYPES, triageStatus: TRIAGE_STATUSES };

const VOCABULARIES: Record<string, Record<string, readonly string[]>> = {
    UserSummary: { role: ROLES },
    UserAdminSummary: { role: ROLES },
    UserCreateRequest: { role: ROLES },
    UserUpdateRequest: { role: ROLES },
    LastScan: { status: SCAN_STATUSES },
    QueuedScan: { status: SCAN_STATUSES },
    RecentScan: { status: SCAN_STATUSES },
    Scan: { status: SCAN_STATUSES },
    ScanSummary: { status: SCAN_STATUSES },
    IssueDetail: ISSUE,
    IssueView: ISSUE,
    ObservedIssue: ISSUE,
    BacklogEntry: ISSUE,
    FindingView: { type: FINDING_TYPES },
    PluginOutcome: { state: PLUGIN_STATES, refusal: PLUGIN_REFUSALS, signature: PLUGIN_SIGNATURES },
    TriageRequest: { status: TRIAGE_STATUSES },
    BulkTriageRequest: { status: TRIAGE_STATUSES },
    ChecklistVersionSummary: { status: CHECKLIST_VERSION_STATUSES },
    PairingChange: { change: CHECKLIST_CHANGES },
    ChecklistRevisionSummary: { status: CHECKLIST_STATUSES },
    ChecklistAnswerView: { value: CHECKLIST_ANSWERS },
    ChecklistAnswerRequest: { value: CHECKLIST_ANSWERS },
    ChecklistLineView: { evidenceKind: CHECKLIST_EVIDENCE_KINDS },
    ChecklistItemView: { evidenceKind: CHECKLIST_EVIDENCE_KINDS },
    ChecklistItemEvidence: { evidenceKind: CHECKLIST_EVIDENCE_KINDS },
    ChecklistEvidenceView: { kind: CHECKLIST_PROOF_KINDS },
    ChecklistRuleForm: { kind: RULE_KINDS, metric: COVERAGE_METRICS, aggregation: COVERAGE_AGGREGATIONS },
    ChecklistMeasurementView: {
        purpose: MEASUREMENT_PURPOSES,
        ruleKind: RULE_KINDS,
        outcome: MEASUREMENT_OUTCOMES,
        reason: NO_DATA_REASONS,
        answerValue: CHECKLIST_ANSWERS,
        reconciliation: RECONCILIATIONS
    },
    MeasuredLineView: { answer: CHECKLIST_ANSWERS, reconciliation: RECONCILIATIONS },
    ChecklistMeasurementsView: { status: CHECKLIST_STATUSES },
    RepositoryLook: { status: LOOK_STATUSES, source: EVIDENCE_SOURCES },
    MeasuredFigure: { severity: [...ISSUE_SEVERITIES] },
    RepositorySummary: { tier: ASSET_TIERS },
    ContainerSummary: { tier: ASSET_TIERS },
    RegisteredVerdict: { target_kind: VERDICT_TARGET_KINDS }
};

function check(schemaName: string, value: unknown, path: string): string[] {
    const schema = SCHEMAS[schemaName];
    if (!schema) {
        return [`${path}: the document has no schema called "${schemaName}"`];
    }
    return [...against(schema, value, path), ...vocabulary(schemaName, value, path)];
}

function vocabulary(schemaName: string, value: unknown, path: string): string[] {
    const closed = VOCABULARIES[schemaName];
    if (!closed || typeof value !== 'object' || value === null || Array.isArray(value)) {
        return [];
    }
    const holder = value as Record<string, unknown>;
    return Object.entries(closed)
        .filter(([key]) => typeof holder[key] === 'string' && !closed[key].includes(holder[key]))
        .map(
            ([key, allowed]) =>
                `${path}.${key}: the server sends one of ${allowed.map((one) => JSON.stringify(one)).join(', ')},` +
                ` the fixture holds ${JSON.stringify(holder[key])}`
        );
}

function against(schema: JsonSchema, value: unknown, path: string): string[] {
    if (schema.$ref) {
        return check(schema.$ref.split('/').pop() as string, value, path);
    }
    // The server sends nulls the document cannot describe; see the note above.
    if (value === null || value === undefined) {
        return [];
    }

    switch (schema.type) {
        case 'array':
            if (!Array.isArray(value)) {
                return [`${path}: the document says array, the fixture holds ${typeOf(value)}`];
            }
            return schema.items
                ? value.flatMap((item, index) => against(schema.items as JsonSchema, item, `${path}[${index}]`))
                : [];
        case 'object':
        case undefined:
            return object(schema, value, path);
        case 'string':
        case 'integer':
        case 'number':
        case 'boolean':
            return scalar(schema, value, path);
        default:
            return [];
    }
}

function object(schema: JsonSchema, value: unknown, path: string): string[] {
    if (typeof value !== 'object' || Array.isArray(value)) {
        return [`${path}: the document says object, the fixture holds ${typeOf(value)}`];
    }
    const holder = value as Record<string, unknown>;
    const problems: string[] = [];

    // A free-form map — `backlogBySeverity` and its kind. Its keys are data, not a shape.
    if (!schema.properties && schema.additionalProperties) {
        const values = typeof schema.additionalProperties === 'object' ? schema.additionalProperties : null;
        if (values) {
            Object.entries(holder).forEach(([key, entry]) =>
                problems.push(...against(values, entry, `${path}.${key}`))
            );
        }
        return problems;
    }

    const declared = schema.properties ?? {};
    for (const key of Object.keys(holder)) {
        if (!(key in declared)) {
            problems.push(
                `${path}.${key}: the fixture carries this, the document does not declare it` +
                    (Object.keys(declared).length > 0
                        ? ` (it declares ${Object.keys(declared).sort().join(', ')})`
                        : '')
            );
        }
    }
    for (const key of schema.required ?? []) {
        if (holder[key] === undefined) {
            problems.push(`${path}.${key}: the document marks this always sent, the fixture omits it`);
        }
    }
    for (const [key, entry] of Object.entries(holder)) {
        const declaration = declared[key];
        if (declaration) {
            problems.push(...against(declaration, entry, `${path}.${key}`));
        }
    }
    return problems;
}

function scalar(schema: JsonSchema, value: unknown, path: string): string[] {
    const actual = typeOf(value);
    const expected = schema.type === 'integer' ? 'number' : schema.type;
    if (actual !== expected) {
        return [`${path}: the document says ${schema.type}, the fixture holds ${actual}`];
    }
    if (schema.enum && !schema.enum.includes(value)) {
        return [
            `${path}: the document allows ${schema.enum.map((one) => JSON.stringify(one)).join(', ')},` +
                ` the fixture holds ${JSON.stringify(value)}`
        ];
    }
    return [];
}

function typeOf(value: unknown): string {
    if (value === null) {
        return 'null';
    }
    return Array.isArray(value) ? 'array' : typeof value;
}
