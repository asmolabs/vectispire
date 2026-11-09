import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { CoverageImport, TestReportImport } from '../api.models';

/**
 * Coverage and test reports from declared internal sources (decision 0032 §7): what each repository
 * received. Figures a checklist reads — never findings, never a backlog.
 *
 * **There is no upload here, deliberately**, for the reason {@link SarifApi} has none: an import is
 * accepted from a declared source's integration key only (scope `report_import`), and a session is
 * not a source. The interface reads the history; the pipeline writes it.
 */
@Injectable({ providedIn: 'root' })
export class ReportImportsApi {
    private readonly http = inject(HttpClient);

    /** The latest fifty, newest first. 404 for a repository the reader cannot see. */
    coverageImports(repositoryId: number): Observable<CoverageImport[]> {
        return this.http.get<CoverageImport[]>(`/api/v1/repositories/${repositoryId}/coverage-imports`);
    }

    /** The latest fifty, newest first, without their suites. 404 for a repository the reader cannot see. */
    testReportImports(repositoryId: number): Observable<TestReportImport[]> {
        return this.http.get<TestReportImport[]>(`/api/v1/repositories/${repositoryId}/test-report-imports`);
    }
}
