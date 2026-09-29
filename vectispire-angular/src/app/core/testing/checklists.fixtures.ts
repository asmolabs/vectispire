import type {
    ChecklistAnswer,
    ChecklistEvidence,
    ChecklistItem,
    ChecklistLayout,
    ChecklistLine,
    ChecklistLineHistory,
    ChecklistOfferedVersion,
    ChecklistPreview,
    ChecklistProjectContext,
    ChecklistRevisionSummary,
    ChecklistTemplate,
    ChecklistVersion,
    ChecklistVersionSummary,
    ChecklistView
} from '../api.models';
import { asSchema } from './contract';

/**
 * The checklist templates' shapes as the control plane publishes them, checked against the
 * document on load. The controls are invented — a real organisation's template is never checked
 * in, as the backend's fixtures are generated rather than copied (decision 0032, lot L3).
 *
 * The draft is version 2 of `release`, paired with the published version 1: one line unchanged,
 * one reworded, one added and one removed — each fate the pairing can show.
 */
/**
 * A header entry's two cells. Built rather than written as `label: '…'`: the i18n check reads that
 * shape as a label typed into a screen, and a cell reference is not one.
 */
const cells = (label: string, value: string) => ({ label, value });
const HEADER = { product: cells('A1', 'B1'), date: cells('A2', 'B2') };
/** The versions' labels are the organisation's words, which no bundle translates. */
const EDITIONS = ['2025 edition', '2026 edition'] as const;

export const PUBLISHED: ChecklistVersionSummary = asSchema('ChecklistVersionSummary', {
    id: 10,
    ordinal: 1,
    label: EDITIONS[0],
    status: 'published',
    revision: 3,
    sourceSha256: 'a'.repeat(64),
    sourceSize: 18_432,
    layoutConfirmed: true,
    offersNotApplicable: true,
    itemCount: 3,
    previousOrdinal: null,
    derivedFromOrdinal: null,
    draftAuthors: ['alice'],
    importedAt: '2026-09-01T08:00:00Z',
    importedBy: 'alice',
    publishedAt: '2026-09-02T09:00:00Z',
    publishedBy: 'bob',
    retiredAt: null,
    retiredBy: null
});

export const DRAFT: ChecklistVersionSummary = asSchema('ChecklistVersionSummary', {
    id: 11,
    ordinal: 2,
    label: EDITIONS[1],
    status: 'draft',
    revision: 4,
    sourceSha256: 'b'.repeat(64),
    sourceSize: 19_200,
    layoutConfirmed: true,
    offersNotApplicable: true,
    itemCount: 3,
    previousOrdinal: 1,
    derivedFromOrdinal: null,
    draftAuthors: ['alice'],
    importedAt: '2026-09-27T08:00:00Z',
    importedBy: 'alice',
    publishedAt: null,
    publishedBy: null,
    retiredAt: null,
    retiredBy: null
});

export const TEMPLATE: ChecklistTemplate = asSchema('ChecklistTemplateView', {
    id: 1,
    slug: 'release',
    name: 'Release checklist',
    createdAt: '2026-09-01T08:00:00Z',
    createdBy: 'alice',
    versions: [PUBLISHED, DRAFT]
});

export const LAYOUT: ChecklistLayout = asSchema('ChecklistLayoutForm', {
    sheet: 'Checklist',
    columns: { domain: 'A', objective: 'B', control: 'C', kpi: 'D', answer: 'E', comment: 'F' },
    firstItemRow: 5,
    lastItemRow: 7,
    header: HEADER,
    answers: { yes: 'Oui', no: 'Non', notApplicable: 'N/A' }
});

const cell = (ref: string, text: string, formula = false) =>
    asSchema('PreviewCell', { ref, row: Number(ref.slice(1)), column: ref.slice(0, 1), text, formula });

/** The draft, read before any layout is confirmed: a proposal, no pairing yet. */
export const PREVIEW: ChecklistPreview = asSchema('ChecklistTemplatePreview', {
    templateSlug: 'release',
    version: { ...DRAFT, layoutConfirmed: false, itemCount: 0 },
    sheets: ['Checklist', 'Lists'],
    sheet: 'Checklist',
    cells: [
        cell('A1', 'Product'),
        cell('A2', 'Date'),
        cell('B2', '14/09/2026', true),
        cell('A4', 'Domain'),
        cell('B4', 'Objective'),
        cell('C4', 'Control'),
        cell('D4', 'KPI'),
        cell('E4', 'Answer'),
        cell('F4', 'Comment'),
        cell('A5', 'Access'),
        cell('B5', 'Least privilege'),
        cell('C5', 'Service accounts hold no interactive login'),
        cell('C6', 'Secrets are rotated every ninety days'),
        cell('C7', 'Dependencies carry no known critical vulnerability'),
        cell('D7', 'Zero critical')
    ],
    cellsTruncated: false,
    proposal: {
        sheet: 'Checklist',
        columnHeaderRow: 4,
        firstItemRow: 5,
        lastItemRow: 7,
        columns: { domain: 'A', objective: 'B', control: 'C', kpi: 'D', answer: 'E', comment: 'F' },
        header: HEADER,
        answerValues: ['Oui', 'Non', 'N/A']
    },
    layout: null,
    pairing: []
});

/** The same draft once its layout is confirmed: the pairing with version 1 is there. */
export const CONFIRMED_PREVIEW: ChecklistPreview = asSchema('ChecklistTemplatePreview', {
    ...PREVIEW,
    version: DRAFT,
    layout: LAYOUT,
    pairing: [
        {
            change: 'unchanged',
            pairedByHand: false,
            readKey: 'text:service accounts hold no interactive login',
            row: 5,
            control: 'Service accounts hold no interactive login',
            previousKey: 'text:service accounts hold no interactive login',
            previousRow: 5,
            previousControl: 'Service accounts hold no interactive login'
        },
        {
            change: 'added',
            pairedByHand: false,
            readKey: 'text:secrets are rotated every ninety days',
            row: 6,
            control: 'Secrets are rotated every ninety days',
            previousKey: null,
            previousRow: null,
            previousControl: null
        },
        {
            change: 'changed',
            pairedByHand: false,
            readKey: 'text:dependencies carry no known critical vulnerability',
            row: 7,
            control: 'Dependencies carry no known critical vulnerability',
            previousKey: 'text:dependencies carry no known critical vulnerability',
            previousRow: 7,
            previousControl: 'Dependencies carry no known critical vulnerability'
        },
        {
            change: 'removed',
            pairedByHand: false,
            readKey: null,
            row: null,
            control: null,
            previousKey: 'text:secrets are rotated yearly',
            previousRow: 6,
            previousControl: 'Secrets are rotated yearly'
        }
    ]
});

const item = (position: number, control: string, extra: Partial<ChecklistItem> = {}): ChecklistItem =>
    asSchema('ChecklistItemView', {
        id: 100 + position,
        versionId: 11,
        itemKey: `text:${control.toLowerCase()}`,
        position,
        domain: 'Access',
        objective: 'Least privilege',
        control,
        contact: null,
        kpi: null,
        contentDigest: String(position).repeat(64),
        sheetRow: 4 + position,
        evidenceKind: 'none',
        evidenceValidityMonths: null,
        boundRule: null,
        ...extra
    });

/**
 * A checklist 409 as `ApiExceptionHandler` writes it: the cause in the `type`
 * (`ChecklistConflict.Cause.token()`), an English `detail` no screen is to show when it knows the
 * cause, and any extension member beside them — `lines`, on a `checklist-incomplete`. The document
 * declares no problem schema, so there is nothing to check it against but the handler's tests.
 */
export function conflict(
    token: string,
    detail = 'An English sentence the screen must not show.',
    members: Record<string, unknown> = {}
): Record<string, unknown> {
    return { type: `urn:vectispire:problem:${token}`, title: REASON_409, status: 409, detail, ...members };
}
/** The status's reason phrase, not a label: named apart so that the i18n check does not read it as one. */
const REASON_409 = 'Conflict';

export const VERSION: ChecklistVersion = asSchema('ChecklistVersionView', {
    templateSlug: 'release',
    templateName: 'Release checklist',
    version: DRAFT,
    layout: LAYOUT,
    items: [
        item(1, 'Service accounts hold no interactive login'),
        item(2, 'Secrets are rotated every ninety days'),
        item(3, 'Dependencies carry no known critical vulnerability', { kpi: 'Zero critical' })
    ],
    pairs: []
});

// ---------------------------------------------------------------------- a project's checklist

/**
 * Project 7, "Gateway", answering version 1 of `release`. Revision 2 is a draft at edition 5, moved
 * from the signed-off revision 1: line 1 answered and ready, line 2's answer carried onto a line
 * that changed and awaiting confirmation — with its link proof carried beside it — and line 3, in
 * another domain, unanswered.
 */
export const PROJECT_ID = 7;

export const SIGNED_REVISION: ChecklistRevisionSummary = asSchema('ChecklistRevisionSummary', {
    projectId: PROJECT_ID,
    revision: 1,
    status: 'signed_off',
    edition: 9,
    templateSlug: 'release',
    templateName: 'Release checklist',
    versionOrdinal: 1,
    versionLabel: EDITIONS[0],
    author: 'carol',
    openedAt: '2026-09-10T08:00:00Z',
    openedBy: 'carol',
    supersedesRevision: null,
    submittedAt: '2026-09-12T08:00:00Z',
    submittedBy: 'carol',
    returnedAt: null,
    returnedBy: null,
    returnReason: null,
    signedOffAt: '2026-09-13T08:00:00Z',
    signedOffBy: 'bob',
    signOffFourEyes: true,
    supersededAt: null,
    supersededBy: null
});

export const DRAFT_REVISION: ChecklistRevisionSummary = asSchema('ChecklistRevisionSummary', {
    ...SIGNED_REVISION,
    revision: 2,
    status: 'draft',
    edition: 5,
    openedAt: '2026-09-20T08:00:00Z',
    supersedesRevision: 1,
    submittedAt: null,
    submittedBy: null,
    signedOffAt: null,
    signedOffBy: null,
    signOffFourEyes: null
});

/** Gateway's context, its newest revision the draft at edition 5. */
export const CONTEXT: ChecklistProjectContext = asSchema('ChecklistProjectContext', {
    projectId: PROJECT_ID,
    projectName: 'Gateway',
    latestRevision: 2,
    latestEdition: 5
});

/** The context of a project with no checklist yet: its name, and nothing for an opening to name. */
export const EMPTY_CONTEXT: ChecklistProjectContext = asSchema('ChecklistProjectContext', {
    ...CONTEXT,
    latestRevision: null,
    latestEdition: null
});

const answer = (itemId: number, extra: Partial<ChecklistAnswer> = {}): ChecklistAnswer =>
    asSchema('ChecklistAnswerView', {
        id: 500 + itemId,
        itemId,
        value: 'yes',
        comment: null,
        answeredBy: 'carol',
        answeredAt: '2026-09-11T08:00:00Z',
        measurementId: null,
        carriedFromId: null,
        carriedBy: null,
        carriedAt: null,
        needsConfirmation: false,
        edition: 2,
        ...extra
    });

export const LINK_PROOF: ChecklistEvidence = asSchema('ChecklistEvidenceView', {
    id: 900,
    itemId: 102,
    kind: 'link',
    link: 'https://wiki.example.invalid/rotation',
    fileName: null,
    mediaType: null,
    fileSize: null,
    fileSha256: null,
    performedOn: '2026-09-01',
    validUntil: '2027-09-01',
    addedBy: 'carol',
    addedAt: '2026-09-11T08:00:00Z',
    carriedFromId: 800,
    edition: 1,
    withdrawnBy: null,
    withdrawnAt: null,
    inDate: true
});

export const FILE_PROOF: ChecklistEvidence = asSchema('ChecklistEvidenceView', {
    ...LINK_PROOF,
    id: 901,
    itemId: 101,
    kind: 'file',
    link: null,
    fileName: 'pentest-report.pdf',
    mediaType: 'application/pdf',
    fileSize: 2048,
    fileSha256: 'c'.repeat(64),
    validUntil: null,
    carriedFromId: null,
    edition: 3
});

const line = (position: number, control: string, extra: Partial<ChecklistLine> = {}): ChecklistLine =>
    asSchema('ChecklistLineView', {
        itemId: 100 + position,
        itemKey: `text:${control.toLowerCase()}`,
        position,
        domain: 'Access',
        objective: 'Least privilege',
        control,
        contact: null,
        kpi: null,
        evidenceKind: 'none',
        evidenceValidityMonths: null,
        answer: null,
        evidence: [],
        edition: 0,
        problems: [],
        ...extra
    });

export const READY_LINE = line(1, 'Service accounts hold no interactive login', {
    contact: 'Platform team',
    answer: answer(101),
    evidence: [FILE_PROOF],
    edition: 3
});

export const CARRIED_LINE = line(2, 'Secrets are rotated every ninety days', {
    evidenceKind: 'link_or_file',
    evidenceValidityMonths: 12,
    answer: answer(102, {
        carriedFromId: 402,
        carriedBy: 'dave',
        carriedAt: '2026-09-20T08:00:00Z',
        needsConfirmation: true,
        edition: 1
    }),
    evidence: [LINK_PROOF],
    edition: 1,
    problems: ['awaiting_confirmation']
});

export const OPEN_LINE = line(3, 'Dependencies carry no known critical vulnerability', {
    domain: 'Supply chain',
    objective: 'Known vulnerabilities',
    kpi: 'Zero critical',
    problems: ['unanswered']
});

export const CHECKLIST: ChecklistView = asSchema('ChecklistView', {
    checklist: DRAFT_REVISION,
    projectName: 'Gateway',
    offersNotApplicable: true,
    answerWords: { yes: 'Oui', no: 'Non', notApplicable: 'N/A' },
    authors: ['carol', 'dave'],
    fourEyesRequired: true,
    readyToSubmit: false,
    lines: [READY_LINE, CARRIED_LINE, OPEN_LINE]
});

/** The same revision with every line ready: what a submission can be made from. */
export const READY_CHECKLIST: ChecklistView = asSchema('ChecklistView', {
    ...CHECKLIST,
    readyToSubmit: true,
    lines: [
        READY_LINE,
        { ...CARRIED_LINE, answer: { ...CARRIED_LINE.answer!, needsConfirmation: false }, problems: [] },
        { ...OPEN_LINE, answer: answer(103, { value: 'no', comment: 'Two criticals, fix planned.' }), problems: [] }
    ]
});

/** The ready revision, submitted by carol — who, under four-eyes, may not sign it off. */
export const SUBMITTED_CHECKLIST: ChecklistView = asSchema('ChecklistView', {
    ...READY_CHECKLIST,
    readyToSubmit: false,
    checklist: {
        ...DRAFT_REVISION,
        status: 'submitted',
        edition: 8,
        submittedAt: '2026-09-25T08:00:00Z',
        submittedBy: 'carol'
    }
});

export const SIGNED_CHECKLIST: ChecklistView = asSchema('ChecklistView', {
    ...SUBMITTED_CHECKLIST,
    checklist: {
        ...SUBMITTED_CHECKLIST.checklist,
        status: 'signed_off',
        edition: 9,
        signedOffAt: '2026-09-26T08:00:00Z',
        signedOffBy: 'bob',
        signOffFourEyes: true
    }
});

export const OFFERED: ChecklistOfferedVersion[] = [
    asSchema('ChecklistOfferedVersion', {
        templateSlug: 'release',
        templateName: 'Release checklist',
        ordinal: 1,
        label: EDITIONS[0],
        itemCount: 3,
        offersNotApplicable: true,
        publishedAt: '2026-09-02T09:00:00Z'
    }),
    asSchema('ChecklistOfferedVersion', {
        templateSlug: 'release',
        templateName: 'Release checklist',
        ordinal: 2,
        label: EDITIONS[1],
        itemCount: 3,
        offersNotApplicable: true,
        publishedAt: '2026-09-27T09:00:00Z'
    })
];

export const LINE_HISTORY: ChecklistLineHistory = asSchema('ChecklistLineHistory', {
    projectId: PROJECT_ID,
    revision: 2,
    itemId: 102,
    answers: [
        answer(102, {
            id: 610,
            value: 'no',
            comment: 'Not yet automated.',
            answeredBy: 'erin',
            answeredAt: '2026-09-21T08:00:00Z',
            edition: 2
        }),
        answer(102, { id: 611, answeredBy: 'dave', answeredAt: '2026-09-22T08:00:00Z', edition: 3 })
    ],
    evidence: [{ ...LINK_PROOF, withdrawnBy: 'dave', withdrawnAt: '2026-09-22T09:00:00Z', inDate: false }]
});
