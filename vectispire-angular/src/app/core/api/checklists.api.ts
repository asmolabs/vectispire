import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import type {
    ChecklistItemPair,
    ChecklistLayout,
    ChecklistPreview,
    ChecklistTemplate,
    ChecklistVersion
} from '../api.models';

/** The type the import route consumes; the server also takes `application/octet-stream`. */
export const XLSX_TYPE = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

/**
 * The ceiling `RequestBodyLimitFilter` holds the import to (`vectispire.http.max-body.checklist-template-import`,
 * `10MB`, which Spring reads as 10 × 1024 × 1024). The screen refuses a larger file before sending
 * it — ten megabytes uploaded to be told no is the one refusal that costs the reader something.
 */
export const MAX_WORKBOOK_BYTES = 10 * 1024 * 1024;

/**
 * The organisation's checklist templates (decision 0032 §3, §4, §8): a workbook imported as a
 * draft, its layout and answer words confirmed, its items paired with the previous version, then
 * published by somebody who may — and, under four-eyes, somebody who did not write it.
 *
 * One stateless client per domain; no absolute URL, for the CSP's `connect-src 'self'`. Reading is
 * governance (`@RequiresGovernanceRead`, the auditor included); every write is `@RequiresSecurityLead`.
 */
@Injectable({ providedIn: 'root' })
export class ChecklistsApi {
    private readonly http = inject(HttpClient);

    /** Every template with its versions, without their items. */
    checklistTemplates(): Observable<ChecklistTemplate[]> {
        return this.http.get<ChecklistTemplate[]>('/api/v1/checklist-templates');
    }

    checklistTemplate(slug: string): Observable<ChecklistTemplate> {
        return this.http.get<ChecklistTemplate>(`/api/v1/checklist-templates/${encodeURIComponent(slug)}`);
    }

    /**
     * The workbook as the raw body — there is no multipart route: the body filter bounds a raw body
     * where it could not bound a part. A new slug creates the template, named by `name`; an existing
     * one gets its next version, a draft, and `name` is ignored. Blank parameters are left out rather
     * than sent empty.
     */
    importChecklistWorkbook(
        slug: string,
        workbook: Blob,
        options: { name?: string | null; label?: string | null } = {}
    ): Observable<ChecklistVersion> {
        let params = new HttpParams();
        const name = options.name?.trim();
        const label = options.label?.trim();
        if (name) params = params.set('name', name);
        if (label) params = params.set('label', label);
        return this.http.post<ChecklistVersion>(
            `/api/v1/checklist-templates/${encodeURIComponent(slug)}/versions`,
            workbook,
            { params, headers: new HttpHeaders({ 'Content-Type': XLSX_TYPE }) }
        );
    }

    /** A version whole: its summary, confirmed layout, items in the sheet's order and pairs made by hand. */
    checklistVersion(slug: string, ordinal: number): Observable<ChecklistVersion> {
        return this.http.get<ChecklistVersion>(versionPath(slug, ordinal));
    }

    /**
     * The proposal, the confirmed layout, a sheet's cells and the pairing. `sheet` names the sheet
     * to show; absent, the server shows the confirmed layout's, else the proposal's.
     */
    checklistPreview(slug: string, ordinal: number, sheet?: string | null): Observable<ChecklistPreview> {
        const params = sheet ? new HttpParams().set('sheet', sheet) : undefined;
        return this.http.get<ChecklistPreview>(`${versionPath(slug, ordinal)}/preview`, { params });
    }

    /**
     * Reads the items by the layout; the pairs made earlier are cleared, since they named items as read before.
     * `revision` is the one on screen: a draft another lead changed since is refused (409), not overwritten.
     */
    confirmChecklistLayout(
        slug: string,
        ordinal: number,
        revision: number,
        layout: ChecklistLayout
    ): Observable<ChecklistVersion> {
        return this.http.put<ChecklistVersion>(`${versionPath(slug, ordinal)}/layout`, layout, {
            params: new HttpParams().set('revision', revision)
        });
    }

    /**
     * Replaces the draft's pairs whole: the list sent is every pair it is to have, an empty one clears them.
     * `revision` is the one on screen, for the same reason: a whole list sent over pairs made meanwhile would
     * erase them.
     */
    pairChecklistItems(
        slug: string,
        ordinal: number,
        revision: number,
        pairs: ChecklistItemPair[]
    ): Observable<ChecklistVersion> {
        return this.http.put<ChecklistVersion>(
            `${versionPath(slug, ordinal)}/pairs`,
            { pairs },
            { params: new HttpParams().set('revision', revision) }
        );
    }

    /** A new draft from a published version: same workbook, layout and items. */
    deriveChecklistVersion(slug: string, ordinal: number, label?: string | null): Observable<ChecklistVersion> {
        const trimmed = label?.trim();
        return this.http.post<ChecklistVersion>(
            `${versionPath(slug, ordinal)}/derive`,
            trimmed ? { label: trimmed } : {}
        );
    }

    /**
     * Publishes the draft **at the revision the publisher reviewed**: an edit made since refuses the
     * publication (409) rather than publishing something nobody has read.
     */
    publishChecklistVersion(slug: string, ordinal: number, revision: number): Observable<ChecklistVersion> {
        return this.http.post<ChecklistVersion>(`${versionPath(slug, ordinal)}/publish`, { revision });
    }

    /** Retires a published version — no new checklist opens on it — or sets a draft aside. */
    retireChecklistVersion(slug: string, ordinal: number): Observable<ChecklistVersion> {
        return this.http.post<ChecklistVersion>(`${versionPath(slug, ordinal)}/retire`, {});
    }
}

function versionPath(slug: string, ordinal: number): string {
    return `/api/v1/checklist-templates/${encodeURIComponent(slug)}/versions/${ordinal}`;
}
