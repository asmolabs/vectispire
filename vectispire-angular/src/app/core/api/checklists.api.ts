import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams, HttpResponse } from '@angular/common/http';
import { Observable } from 'rxjs';
import type {
    ChecklistAnswerValue,
    ChecklistItemEvidence,
    ChecklistItemPair,
    ChecklistItemRule,
    ChecklistLayout,
    ChecklistLineHistory,
    ChecklistMeasurements,
    ChecklistOfferedVersion,
    ChecklistPreview,
    ChecklistProjectContext,
    ChecklistRevisionSummary,
    ChecklistTemplate,
    ChecklistVersion,
    ChecklistView,
    Schema
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
 * The ceiling on a checklist proof's file (`vectispire.http.max-body.checklist-evidence`, `25MB`),
 * refused by the screen before a byte is sent, for the same reason as the workbook's.
 */
export const MAX_EVIDENCE_BYTES = 25 * 1024 * 1024;

/**
 * The checklists (decision 0032): the organisation's templates, and each project's checklist
 * answered against one of their published versions.
 *
 * **Templates** (§3, §4): a workbook imported as a draft, its layout and answer words confirmed, its
 * items paired with the previous version, then published by somebody who may — and, under
 * four-eyes, somebody who did not write it. Reading is governance (`@RequiresGovernanceRead`, the
 * auditor included); every write is `@RequiresSecurityLead`.
 *
 * **A project's checklist** (§5, §8): below, under its own heading.
 *
 * One stateless client per domain; no absolute URL, for the CSP's `connect-src 'self'`.
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

    /**
     * Sets what proof the lines named ask for, on a draft with a confirmed layout — **a partial
     * update**: a line not listed keeps its own, so the screen sends only the lines it changed.
     * `revision` is the one on screen, as for a layout: a draft edited meanwhile is refused (409).
     */
    setChecklistEvidence(
        slug: string,
        ordinal: number,
        revision: number,
        items: ChecklistItemEvidence[]
    ): Observable<ChecklistVersion> {
        return this.http.put<ChecklistVersion>(
            `${versionPath(slug, ordinal)}/evidence`,
            { items },
            { params: new HttpParams().set('revision', revision) }
        );
    }

    /**
     * Binds the rule each line named is measured by, or unbinds it with a null rule, on a draft with a
     * confirmed layout — **a partial update**, like the evidence route: a line not listed keeps its
     * binding, and the screen sends only the lines it changed. `revision` is the one on screen.
     */
    bindChecklistRules(
        slug: string,
        ordinal: number,
        revision: number,
        items: ChecklistItemRule[]
    ): Observable<ChecklistVersion> {
        return this.http.put<ChecklistVersion>(
            `${versionPath(slug, ordinal)}/rules`,
            { items },
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

    // ------------------------------------------------------------------ a project's checklist
    //
    // Readable by any account that sees the whole project — anything less is a 404, the words of an
    // absent project; written by `@RequiresWriteAccount`. **Every write names the edition of the
    // checklist on screen** and answers the checklist as it now is, whose edition has moved on: the
    // screen replaces its view with it, or its next write would be refused as stale.

    /** Every revision of the project's checklist, newest first. */
    projectChecklists(projectId: number): Observable<ChecklistRevisionSummary[]> {
        return this.http.get<ChecklistRevisionSummary[]>(projectPath(projectId));
    }

    /**
     * The project's name and its newest revision's number and edition — what the page shows and names
     * before a checklist exists, which neither the list nor the offered versions can say.
     */
    projectChecklistContext(projectId: number): Observable<ChecklistProjectContext> {
        return this.http.get<ChecklistProjectContext>(`${projectPath(projectId)}/context`);
    }

    /** The published versions the checklist may be opened on or moved to. */
    offeredChecklistVersions(projectId: number): Observable<ChecklistOfferedVersion[]> {
        return this.http.get<ChecklistOfferedVersion[]>(`${projectPath(projectId)}/offered`);
    }

    /**
     * Opens the project's checklist on a published version, or moves it to another. `edition` is the
     * newest revision's as read, and **left out when the screen showed no checklist**: a checklist
     * somebody opened meanwhile is then refused rather than silently moved.
     */
    openProjectChecklist(
        projectId: number,
        template: string,
        version: number,
        edition: number | null
    ): Observable<ChecklistView> {
        const body: Schema<'ChecklistOpenRequest'> = { template, version };
        if (edition !== null) body.edition = edition;
        return this.http.post<ChecklistView>(projectPath(projectId), body);
    }

    projectChecklist(projectId: number, revision: number): Observable<ChecklistView> {
        return this.http.get<ChecklistView>(revisionPath(projectId, revision));
    }

    checklistLineHistory(projectId: number, revision: number, itemId: number): Observable<ChecklistLineHistory> {
        return this.http.get<ChecklistLineHistory>(`${linePath(projectId, revision, itemId)}/history`);
    }

    /**
     * The measured lines of a revision, each beside its answer: a draft's and a submitted one's computed
     * for this read and stored nowhere, a signed-off one's as its sign-off froze them.
     */
    checklistMeasurements(projectId: number, revision: number): Observable<ChecklistMeasurements> {
        return this.http.get<ChecklistMeasurements>(`${revisionPath(projectId, revision)}/measurements`);
    }

    /**
     * A new answer on a draft's line. `no` and `not_applicable` need a comment; a blank one is left out.
     * `measurementDigest` — the `evidenceDigest` of the measurement the person read — rests the answer
     * on it: the server applies the rule again and refuses (409) evidence other than what was read.
     * Left out for an answer resting on none.
     */
    answerChecklistLine(
        projectId: number,
        revision: number,
        itemId: number,
        value: ChecklistAnswerValue,
        comment: string | null,
        edition: number,
        measurementDigest: string | null = null
    ): Observable<ChecklistView> {
        const body: Schema<'ChecklistAnswerRequest'> = { value, edition };
        const trimmed = comment?.trim();
        if (trimmed) body.comment = trimmed;
        if (measurementDigest) body.measurementDigest = measurementDigest;
        return this.http.post<ChecklistView>(`${linePath(projectId, revision, itemId)}/answers`, body);
    }

    /** The answer carried onto a line that changed still holds, under the caller's name. */
    confirmChecklistAnswer(
        projectId: number,
        revision: number,
        itemId: number,
        edition: number
    ): Observable<ChecklistView> {
        const body: Schema<'ChecklistEditionRequest'> = { edition };
        return this.http.post<ChecklistView>(`${linePath(projectId, revision, itemId)}/confirmation`, body);
    }

    /** `performedOn` is the day the work was done, `yyyy-MM-dd`. */
    attachChecklistLink(
        projectId: number,
        revision: number,
        itemId: number,
        link: string,
        performedOn: string,
        edition: number
    ): Observable<ChecklistView> {
        const body: Schema<'ChecklistLinkRequest'> = { link: link.trim(), performedOn, edition };
        return this.http.post<ChecklistView>(`${linePath(projectId, revision, itemId)}/evidence/links`, body);
    }

    /**
     * The file as the raw body — no multipart route, for the same reason as the workbook — typed as
     * the file says, the name, the day and the edition as parameters. The server stores the type and
     * never trusts it to serve the file back.
     */
    attachChecklistFile(
        projectId: number,
        revision: number,
        itemId: number,
        file: File,
        performedOn: string,
        edition: number
    ): Observable<ChecklistView> {
        const params = new HttpParams().set('name', file.name).set('performedOn', performedOn).set('edition', edition);
        return this.http.post<ChecklistView>(`${linePath(projectId, revision, itemId)}/evidence/files`, file, {
            params,
            headers: new HttpHeaders({ 'Content-Type': file.type || 'application/octet-stream' })
        });
    }

    /**
     * A proof's bytes, through `HttpClient` — the token lives in memory and a navigation would carry
     * none — to be saved as a download. Never rendered: the server sends it as an opaque attachment,
     * and an uploaded HTML file opened in the page would be a script on this origin.
     */
    checklistEvidenceFile(projectId: number, revision: number, evidenceId: number): Observable<HttpResponse<Blob>> {
        return this.http.get(`${revisionPath(projectId, revision)}/evidence/${evidenceId}/file`, {
            responseType: 'blob',
            observe: 'response'
        });
    }

    /** The proof stops counting; its row stays, dated and attributed. */
    withdrawChecklistEvidence(
        projectId: number,
        revision: number,
        evidenceId: number,
        edition: number
    ): Observable<ChecklistView> {
        const body: Schema<'ChecklistEditionRequest'> = { edition };
        return this.http.post<ChecklistView>(
            `${revisionPath(projectId, revision)}/evidence/${evidenceId}/withdrawal`,
            body
        );
    }

    submitChecklist(projectId: number, revision: number, edition: number): Observable<ChecklistView> {
        const body: Schema<'ChecklistEditionRequest'> = { edition };
        return this.http.post<ChecklistView>(`${revisionPath(projectId, revision)}/submission`, body);
    }

    /** A submitted revision back to its authors, a draft again, with the reason they will read. */
    returnChecklist(projectId: number, revision: number, reason: string, edition: number): Observable<ChecklistView> {
        const body: Schema<'ChecklistReturnRequest'> = { reason: reason.trim(), edition };
        return this.http.post<ChecklistView>(`${revisionPath(projectId, revision)}/return`, body);
    }

    signOffChecklist(projectId: number, revision: number, edition: number): Observable<ChecklistView> {
        const body: Schema<'ChecklistEditionRequest'> = { edition };
        return this.http.post<ChecklistView>(`${revisionPath(projectId, revision)}/sign-off`, body);
    }

    /** The next revision of a signed-off one, every answer carried as current; the signed one never changes. */
    reopenChecklist(projectId: number, revision: number, edition: number): Observable<ChecklistView> {
        const body: Schema<'ChecklistEditionRequest'> = { edition };
        return this.http.post<ChecklistView>(`${revisionPath(projectId, revision)}/reopen`, body);
    }
}

function versionPath(slug: string, ordinal: number): string {
    return `/api/v1/checklist-templates/${encodeURIComponent(slug)}/versions/${ordinal}`;
}

function projectPath(projectId: number): string {
    return `/api/v1/projects/${projectId}/checklists`;
}

function revisionPath(projectId: number, revision: number): string {
    return `${projectPath(projectId)}/${revision}`;
}

function linePath(projectId: number, revision: number, itemId: number): string {
    return `${revisionPath(projectId, revision)}/items/${itemId}`;
}
