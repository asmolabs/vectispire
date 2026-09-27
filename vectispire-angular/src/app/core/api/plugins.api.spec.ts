import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { asSchema, asSchemaList } from '../testing/contract';
import { ACTIVATION, MANIFEST, PLUGIN } from '../testing/plugins.fixtures';
import { PluginsApi } from './plugins.api';

/**
 * The plugins client, pinned route by route.
 *
 * **What a type cannot see is the verb and the path.** `PUT /plugins/{id}` and `POST /plugins` take
 * the same body; confusing them turns an update into a 409 or a registration into a 404. Switching
 * off is a `DELETE` on the activation, not a `PUT` with `false`. Each case pins one of those, and
 * the bodies are read against the document the server publishes.
 */
describe('the plugins client', () => {
    let api: PluginsApi;
    let http: HttpTestingController;

    beforeEach(() => {
        TestBed.configureTestingModule({ providers: [provideHttpClient(withXhr()), provideHttpClientTesting()] });
        api = TestBed.inject(PluginsApi);
        http = TestBed.inject(HttpTestingController);
    });

    afterEach(() => http.verify());

    it('reads the registry and one plugin', () => {
        let listed: unknown;
        api.plugins().subscribe((plugins) => (listed = plugins));
        http.expectOne({ method: 'GET', url: '/api/v1/plugins' }).flush(asSchemaList('PluginView', [PLUGIN]));
        expect(listed).toEqual([PLUGIN]);

        api.plugin('acme-lint').subscribe();
        http.expectOne({ method: 'GET', url: '/api/v1/plugins/acme-lint' }).flush(PLUGIN);
    });

    it('registers with a POST and updates with a PUT on the id, the manifest as the body', () => {
        api.registerPlugin(MANIFEST).subscribe();
        const registered = http.expectOne({ method: 'POST', url: '/api/v1/plugins' });
        expect(registered.request.body).toEqual(MANIFEST);
        registered.flush(PLUGIN, { status: 201, statusText: 'Created' });

        api.updatePlugin('acme-lint', MANIFEST).subscribe();
        const updated = http.expectOne({ method: 'PUT', url: '/api/v1/plugins/acme-lint' });
        expect(updated.request.body).toEqual(MANIFEST);
        updated.flush(PLUGIN);
    });

    it('enables and disables through its own route, with a body the document declares', () => {
        api.setPluginEnabled('acme-lint', false).subscribe();
        const request = http.expectOne({ method: 'PUT', url: '/api/v1/plugins/acme-lint/enabled' });
        expect(asSchema('PluginEnabled', request.request.body)).toEqual({ enabled: false });
        request.flush({ ...PLUGIN, enabled: false });
    });

    it('lists activations from either side', () => {
        api.pluginProjects('acme-lint').subscribe();
        http.expectOne({ method: 'GET', url: '/api/v1/plugins/acme-lint/projects' }).flush([ACTIVATION]);

        api.projectPlugins(12).subscribe();
        http.expectOne({ method: 'GET', url: '/api/v1/projects/12/plugins' }).flush([ACTIVATION]);
    });

    it('switches on with a PUT and off with a DELETE on the activation', () => {
        api.activatePlugin(12, 'acme-lint').subscribe();
        http.expectOne({ method: 'PUT', url: '/api/v1/projects/12/plugins/acme-lint' }).flush(ACTIVATION);

        api.deactivatePlugin(12, 'acme-lint').subscribe();
        http.expectOne({ method: 'DELETE', url: '/api/v1/projects/12/plugins/acme-lint' }).flush(null);
    });

    it('encodes the id, so a hand-typed one cannot become another route', () => {
        api.plugin('../users').subscribe({ error: () => undefined });
        http.expectOne('/api/v1/plugins/..%2Fusers').flush(null, { status: 404, statusText: 'Not Found' });
    });
});
