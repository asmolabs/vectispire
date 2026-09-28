import type {
    ChecklistItem,
    ChecklistLayout,
    ChecklistPreview,
    ChecklistTemplate,
    ChecklistVersion,
    ChecklistVersionSummary
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
