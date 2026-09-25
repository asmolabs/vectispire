import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams, HttpResponse } from '@angular/common/http';
import { Observable } from 'rxjs';
import {
    ComplianceSeries,
    ControlDeclaration,
    DeclarationRequest,
    ScopeView,
    SoaStatement,
    ComplianceSummary
} from '../api.models';
import { DocumentsApi } from './documents.api';

/**
 * Compliance: the summary and its exports, its history, the statements of applicability and the
 * certified scope.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class ComplianceApi {
    private readonly http = inject(HttpClient);
    private readonly documents = inject(DocumentsApi);

    complianceSummary(targetId?: string): Observable<ComplianceSummary> {
        let params = new HttpParams();
        if (targetId) params = params.set('targetId', targetId);
        return this.http.get<ComplianceSummary>('/api/v1/compliance/summary', { params });
    }

    exportCompliancePdf(targetId?: string): Observable<HttpResponse<Blob>> {
        let url = '/api/v1/compliance/export.pdf';
        if (targetId) url += `?targetId=${encodeURIComponent(targetId)}`;
        return this.documents.downloadDocument(url);
    }

    exportEvidenceBundle(): Observable<HttpResponse<Blob>> {
        return this.documents.downloadDocument('/api/v1/compliance/evidence-bundle.zip');
    }

    complianceHistory(): Observable<ComplianceSeries[]> {
        return this.http.get<ComplianceSeries[]>('/api/v1/compliance/history');
    }

    statementsOfApplicability(): Observable<SoaStatement[]> {
        return this.http.get<SoaStatement[]>('/api/v1/compliance/soa');
    }

    /**
     * The declarations whose review has lapsed, across all frameworks.
     *
     * A route of its own rather than a filter on a document: "what have we stopped looking at" is
     * asked at the scale of the management system, and a screen that had to fetch six documents to
     * assemble it would not ask the question.
     */
    overdueReviews(): Observable<ControlDeclaration[]> {
        return this.http.get<ControlDeclaration[]>('/api/v1/compliance/soa/reviews/overdue');
    }

    declareControl(framework: string, controlId: string, body: DeclarationRequest): Observable<ControlDeclaration> {
        return this.http.put<ControlDeclaration>(`/api/v1/compliance/soa/${framework}/${controlId}`, body);
    }

    certifiedScope(): Observable<ScopeView> {
        return this.http.get<ScopeView>('/api/v1/compliance/scope');
    }

    setRepositoryInScope(id: number, inScope: boolean): Observable<ScopeView> {
        return this.http.put<ScopeView>(`/api/v1/compliance/scope/repositories/${id}`, null, {
            params: new HttpParams().set('in_scope', inScope)
        });
    }

    setContainerInScope(id: number, inScope: boolean): Observable<ScopeView> {
        return this.http.put<ScopeView>(`/api/v1/compliance/scope/containers/${id}`, null, {
            params: new HttpParams().set('in_scope', inScope)
        });
    }
}
