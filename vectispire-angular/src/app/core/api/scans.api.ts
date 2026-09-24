import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { HistoryDossier, InventoryResults, HistoryRepository, ScanDetail, ScanSummary, SbomDiffReport } from '../api.models';

/**
 * Scans — starting them, reading them, comparing their SBOMs — and the history and inventory built
 * from them.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class ScansApi {
    private readonly http = inject(HttpClient);

    scan(id: number): Observable<ScanDetail> {
        return this.http.get<ScanDetail>(`/api/v1/scans/${id}`);
    }

    searchComponents(name: string, version: string): Observable<InventoryResults> {
        const params = new URLSearchParams({ name });
        if (version) {
            params.set('version', version);
        }
        return this.http.get<InventoryResults>(`/api/v1/inventory/search?${params.toString()}`);
    }

    historyRepositories(): Observable<HistoryRepository[]> {
        return this.http.get<HistoryRepository[]>('/api/v1/history/repositories');
    }

    historyDossier(id: number): Observable<HistoryDossier> {
        return this.http.get<HistoryDossier>(`/api/v1/history/repositories/${id}`);
    }

    triggerContainerScan(id: number): Observable<{ id: number; status: string }> {
        return this.http.post<{ id: number; status: string }>(`/api/v1/containers/${id}/scan`, {});
    }

    triggerRepositoryScan(id: number): Observable<{ id: number; status: string }> {
        return this.http.post<{ id: number; status: string }>(`/api/v1/repositories/${id}/scan`, {});
    }

    getSbomDiff(fromScanId: number, toScanId: number): Observable<SbomDiffReport> {
        const params = new HttpParams()
            .set('fromScanId', fromScanId)
            .set('toScanId', toScanId);
        return this.http.get<SbomDiffReport>('/api/v1/sbom/diff', { params });
    }

    /**
     * A target's scan history, newest first.
     *
     * <p><b>The server has answered this since before the client asked.</b> `GET /api/v1/scans`
     * takes `repo_id` or `container_id` and returns the summaries — id, date, branch, status,
     * findings — and no screen called it. The SBOM comparison therefore asked its reader for two
     * scan numbers that nothing displays prominently, which is a way of saying it asked them to
     * read the database.
     *
     * <p>The limit is a plain bound rather than a paging cursor: this feeds a picker, and a picker
     * that needs a second page is a picker nobody can use. Fifty is what a target scanned nightly
     * accumulates in under two months, and the server caps it regardless.
     */
    scansOf(repoId?: number, containerId?: number, limit = 50): Observable<ScanSummary[]> {
        let params = new HttpParams().set('limit', limit);
        if (repoId) params = params.set('repo_id', repoId);
        if (containerId) params = params.set('container_id', containerId);
        return this.http.get<ScanSummary[]>('/api/v1/scans', { params });
    }
}
