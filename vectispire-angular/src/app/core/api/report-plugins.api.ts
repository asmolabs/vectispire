import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpResponse } from '@angular/common/http';
import { Observable } from 'rxjs';
import type { ReportPlugin, ReportPluginActivation, ReportPluginManifest, ReportRun } from '../api.models';

/**
 * Report plugins (decision 0035): the registry, where each is switched on, the runs of a project, the
 * documents they produced and the project export they render.
 *
 * **Four audiences, and the server tells them apart.** Reading the registry is governance reading;
 * registering, updating, enabling and withdrawing are the platform governor's; approving a digest and
 * switching a plugin on for a project are the security leads'; requesting a report and taking the export
 * are for write accounts and auditors who see the whole project. The screens only avoid offering what a
 * role would be refused.
 *
 * **Every download goes through `HttpClient`** with `observe: 'response'`: the token lives in memory and
 * a navigation would carry none, and the server's file name is in `Content-Disposition`, not the body.
 * Ids and digests are path segments, encoded as such.
 */
@Injectable({ providedIn: 'root' })
export class ReportPluginsApi {
    private readonly http = inject(HttpClient);

    /** Every registered report plugin, each with its manifest history. Governance reading. */
    reportPlugins(): Observable<ReportPlugin[]> {
        return this.http.get<ReportPlugin[]>('/api/v1/report-plugins');
    }

    /** 201; with four-eyes on the manifest waits for a second person. 409 `report-plugin-id-taken`. */
    registerReportPlugin(manifest: ReportPluginManifest): Observable<ReportPlugin> {
        return this.http.post<ReportPlugin>('/api/v1/report-plugins', manifest);
    }

    /** A new manifest under the same id; the approved one keeps serving while it waits. 409 for a withdrawn one. */
    updateReportPlugin(id: string, manifest: ReportPluginManifest): Observable<ReportPlugin> {
        return this.http.put<ReportPlugin>(`/api/v1/report-plugins/${encodeURIComponent(id)}`, manifest);
    }

    /** Disabling stops every activation from rendering without forgetting them. */
    setReportPluginEnabled(id: string, enabled: boolean): Observable<ReportPlugin> {
        return this.http.put<ReportPlugin>(`/api/v1/report-plugins/${encodeURIComponent(id)}/enabled`, { enabled });
    }

    /** 409 `report-plugin-four-eyes` for the account that registered it, `-not-pending` for a digest not waiting. */
    approveReportManifest(id: string, digest: string): Observable<ReportPlugin> {
        return this.http.post<ReportPlugin>(
            `/api/v1/report-plugins/${encodeURIComponent(id)}/manifests/${encodeURIComponent(digest)}/approval`,
            null
        );
    }

    /** Final. 400 without a justification of 20 to 500 characters; 409 `report-plugin-withdrawn` when it already was. */
    withdrawReportManifest(id: string, digest: string, justification: string): Observable<ReportPlugin> {
        return this.http.post<ReportPlugin>(
            `/api/v1/report-plugins/${encodeURIComponent(id)}/manifests/${encodeURIComponent(digest)}/withdrawal`,
            { justification }
        );
    }

    /** The report plugins switched on for a project — to whoever sees it whole; 404 otherwise. */
    projectReportPlugins(projectId: number): Observable<ReportPluginActivation[]> {
        return this.http.get<ReportPluginActivation[]>(`/api/v1/projects/${projectId}/report-plugins`);
    }

    /** Idempotent. 409 `report-plugin-not-approved` for a plugin with no approved manifest. */
    activateReportPlugin(projectId: number, pluginId: string): Observable<ReportPluginActivation> {
        return this.http.put<ReportPluginActivation>(
            `/api/v1/projects/${projectId}/report-plugins/${encodeURIComponent(pluginId)}`,
            null
        );
    }

    /** 404 when it was not on. */
    deactivateReportPlugin(projectId: number, pluginId: string): Observable<void> {
        return this.http.delete<void>(`/api/v1/projects/${projectId}/report-plugins/${encodeURIComponent(pluginId)}`);
    }

    /** The project's runs, newest first, the latest 200. */
    projectReports(projectId: number): Observable<ReportRun[]> {
        return this.http.get<ReportRun[]>(`/api/v1/projects/${projectId}/reports`);
    }

    /**
     * 202 with the run, pending. 404 for a plugin not switched on; 409 `report-plugin-disabled`,
     * `-not-approved`, `report-executor-unavailable`, `report-run-in-progress`.
     */
    requestReport(projectId: number, pluginId: string): Observable<ReportRun> {
        return this.http.post<ReportRun>(`/api/v1/projects/${projectId}/reports`, { pluginId });
    }

    /** A produced run's package: the file, `<file>.sig` and `provenance.json`, as `application/zip`. */
    downloadReportPackage(projectId: number, runId: number): Observable<HttpResponse<Blob>> {
        return this.http.get(`/api/v1/projects/${projectId}/reports/${runId}/document`, {
            responseType: 'blob',
            observe: 'response'
        });
    }

    /** `export.json` and its signature, zipped. Audited, and signalled to the SIEM as an export leaving. */
    downloadProjectExport(projectId: number): Observable<HttpResponse<Blob>> {
        return this.http.get(`/api/v1/projects/${projectId}/export`, { responseType: 'blob', observe: 'response' });
    }

    /** The JSON Schema of one export major — what a plugin's author writes against. 404 for a major not produced. */
    downloadExportSchema(major: number): Observable<HttpResponse<Blob>> {
        return this.http.get(`/api/v1/schemas/project-export/${major}`, { responseType: 'blob', observe: 'response' });
    }
}
