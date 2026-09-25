import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
    ExceptionsRegister,
    ReviewOutcome,
    BulkTriageRequest,
    Issue,
    TriagedIssue,
    IssueFilters,
    Page,
    IssueDetail,
    TriageRequest
} from '../api.models';

/**
 * Findings and their triage, including the register of accepted risks and its reviews.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class IssuesApi {
    private readonly http = inject(HttpClient);

    issues(filters: IssueFilters = {}): Observable<Page<Issue>> {
        let params = new HttpParams();
        for (const [key, value] of Object.entries(filters)) {
            // An absent value must not become "undefined" in the URL — the server would read
            // it as a filter on the literal string "undefined".
            if (value !== undefined && value !== null && value !== '') params = params.set(key, String(value));
        }
        return this.http.get<Page<Issue>>('/api/v1/issues', { params });
    }

    triage(issueId: number, request: TriageRequest): Observable<TriagedIssue> {
        return this.http.post<TriagedIssue>(`/api/v1/issues/${issueId}/triage`, request);
    }

    /**
     * The same decision on every issue in the batch.
     *
     * All or nothing: the server checks every id before writing the first, so a refusal means
     * nothing was triaged. A caller that retried "the rest" after a failure would be inventing
     * a partial outcome the API does not produce.
     */
    triageMany(request: BulkTriageRequest): Observable<TriagedIssue[]> {
        return this.http.post<TriagedIssue[]>('/api/v1/issues/triage', request);
    }

    issue(id: number): Observable<IssueDetail> {
        return this.http.get<IssueDetail>(`/api/v1/issues/${id}`);
    }

    /**
     * Attaches an existing ticket to a finding.
     *
     * **Onto `ticketRef`, and not onto `t_issue_ticket`.** The two methods aiming at that second
     * table have been removed from here: nothing reads it — not the inbound webhook, which looks
     * the finding up by its reference, not the sweep, not a screen. Writing there would have
     * shipped an attachment that synchronisation ignores, that is a feature that looks as though it
     * works and never synchronises.
     */
    attachTicket(issueId: number, reference: string, url?: string | null): Observable<TriagedIssue> {
        return this.http.put<TriagedIssue>(`/api/v1/issues/${issueId}/ticket`, { reference, url: url ?? null });
    }

    exceptionsRegister(limit?: number, cursor?: string | null): Observable<ExceptionsRegister> {
        let params = new HttpParams();
        if (limit) params = params.set('limit', limit);
        if (cursor) params = params.set('cursor', cursor);
        return this.http.get<ExceptionsRegister>('/api/v1/exceptions', { params });
    }

    /** La revue rend le registre entier : les compteurs bougent avec la ligne. */
    reviewException(issueId: number, outcome: ReviewOutcome, comment: string | null, newExpiry: string | null) {
        return this.http.post<ExceptionsRegister>(`/api/v1/exceptions/${issueId}/reviews`, {
            outcome,
            comment,
            new_expiry: newExpiry
        });
    }
}
