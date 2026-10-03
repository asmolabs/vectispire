import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { asSchema, asSchemaList } from '../testing/contract';
import {
    PENDING_DIGEST,
    PENDING_RUN,
    REPORT_ACTIVATION,
    REPORT_MANIFEST,
    REPORT_PLUGIN
} from '../testing/report-plugins.fixtures';
import { ReportPluginsApi } from './report-plugins.api';

/**
 * The report plugins client, route by route: the verb and the path are what a type cannot see — an
 * approval is a POST on the digest, a withdrawal a POST carrying the justification, switching off a
 * DELETE on the activation — and every download asks for a blob with the whole response, or the
 * server's file name is lost.
 */
describe('the report plugins client', () => {
    let api: ReportPluginsApi;
    let http: HttpTestingController;

    beforeEach(() => {
        TestBed.configureTestingModule({ providers: [provideHttpClient(withXhr()), provideHttpClientTesting()] });
        api = TestBed.inject(ReportPluginsApi);
        http = TestBed.inject(HttpTestingController);
    });

    afterEach(() => http.verify());

    it('reads the registry, registers with a POST and gives a new manifest with a PUT on the id', () => {
        let listed: unknown;
        api.reportPlugins().subscribe((plugins) => (listed = plugins));
        http.expectOne({ method: 'GET', url: '/api/v1/report-plugins' }).flush(
            asSchemaList('ReportPluginView', [REPORT_PLUGIN])
        );
        expect(listed).toEqual([REPORT_PLUGIN]);

        api.registerReportPlugin(REPORT_MANIFEST).subscribe();
        const registered = http.expectOne({ method: 'POST', url: '/api/v1/report-plugins' });
        expect(registered.request.body).toEqual(asSchema('ReportPluginManifest', REPORT_MANIFEST));
        registered.flush(REPORT_PLUGIN, { status: 201, statusText: 'Created' });

        api.updateReportPlugin('quarterly-summary', REPORT_MANIFEST).subscribe();
        expect(http.expectOne({ method: 'PUT', url: '/api/v1/report-plugins/quarterly-summary' }).request.body).toEqual(
            REPORT_MANIFEST
        );
    });

    it('enables with a PUT on /enabled, approves and withdraws with POSTs on the digest', () => {
        api.setReportPluginEnabled('quarterly-summary', false).subscribe();
        const enabled = http.expectOne({ method: 'PUT', url: '/api/v1/report-plugins/quarterly-summary/enabled' });
        expect(enabled.request.body).toEqual(asSchema('ReportPluginEnabled', { enabled: false }));
        enabled.flush(REPORT_PLUGIN);

        api.approveReportManifest('quarterly-summary', PENDING_DIGEST).subscribe();
        http.expectOne({
            method: 'POST',
            url: `/api/v1/report-plugins/quarterly-summary/manifests/${PENDING_DIGEST}/approval`
        }).flush(REPORT_PLUGIN);

        api.withdrawReportManifest('quarterly-summary', PENDING_DIGEST, 'The renderer dropped rows.').subscribe();
        const withdrawn = http.expectOne({
            method: 'POST',
            url: `/api/v1/report-plugins/quarterly-summary/manifests/${PENDING_DIGEST}/withdrawal`
        });
        expect(withdrawn.request.body).toEqual(
            asSchema('WithdrawalRequest', { justification: 'The renderer dropped rows.' })
        );
        withdrawn.flush(REPORT_PLUGIN);
    });

    it('lists, switches on with a PUT and off with a DELETE a project’s report plugins', () => {
        api.projectReportPlugins(12).subscribe();
        http.expectOne({ method: 'GET', url: '/api/v1/projects/12/report-plugins' }).flush(
            asSchemaList('ReportPluginActivationView', [REPORT_ACTIVATION])
        );
        api.activateReportPlugin(12, 'quarterly-summary').subscribe();
        http.expectOne({ method: 'PUT', url: '/api/v1/projects/12/report-plugins/quarterly-summary' }).flush(
            REPORT_ACTIVATION
        );
        api.deactivateReportPlugin(12, 'quarterly-summary').subscribe();
        http.expectOne({ method: 'DELETE', url: '/api/v1/projects/12/report-plugins/quarterly-summary' }).flush(null, {
            status: 204,
            statusText: 'No Content'
        });
    });

    it('lists runs and requests one with a POST naming the plugin', () => {
        api.projectReports(12).subscribe();
        http.expectOne({ method: 'GET', url: '/api/v1/projects/12/reports' }).flush(
            asSchemaList('ReportRunView', [PENDING_RUN])
        );
        api.requestReport(12, 'quarterly-summary').subscribe();
        const requested = http.expectOne({ method: 'POST', url: '/api/v1/projects/12/reports' });
        expect(requested.request.body).toEqual(asSchema('ReportRequest', { pluginId: 'quarterly-summary' }));
        requested.flush(PENDING_RUN, { status: 202, statusText: 'Accepted' });
    });

    it('downloads the package, the export and the schema as blobs with their whole response', () => {
        const blobs: [string, () => void][] = [
            ['/api/v1/projects/12/reports/34/document', () => api.downloadReportPackage(12, 34).subscribe()],
            ['/api/v1/projects/12/export', () => api.downloadProjectExport(12).subscribe()],
            ['/api/v1/schemas/project-export/1', () => api.downloadExportSchema(1).subscribe()]
        ];
        for (const [url, call] of blobs) {
            call();
            const request = http.expectOne({ method: 'GET', url });
            expect(request.request.responseType).toBe('blob');
            request.flush(new Blob(['x']));
        }
    });

    it('encodes an id or a digest that would otherwise change the route', () => {
        api.approveReportManifest('a/b', 'sha256:x').subscribe();
        http.expectOne('/api/v1/report-plugins/a%2Fb/manifests/sha256%3Ax/approval').flush(REPORT_PLUGIN);
    });
});
