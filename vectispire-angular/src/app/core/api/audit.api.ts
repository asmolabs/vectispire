import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { AuditEntry, AuditFilters, AuditVerification, Page } from '../api.models';

/**
 * The audit log and the verification of its hash chain.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class AuditApi {
    private readonly http = inject(HttpClient);

    auditLog(filters: AuditFilters = {}): Observable<Page<AuditEntry>> {
        let params = new HttpParams();
        for (const [key, value] of Object.entries(filters)) {
            if (value !== undefined && value !== null && value !== '') params = params.set(key, String(value));
        }
        return this.http.get<Page<AuditEntry>>('/api/v1/audit-log', { params });
    }

    auditOperationTypes(): Observable<string[]> {
        return this.http.get<string[]>('/api/v1/audit-log/operation-types');
    }

    verifyAuditChain(): Observable<AuditVerification> {
        return this.http.get<AuditVerification>('/api/v1/audit-log/verify');
    }
}
