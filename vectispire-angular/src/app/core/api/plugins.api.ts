import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Plugin, PluginActivation, PluginManifest } from '../api.models';

/**
 * The plugin registry and where each plugin is switched on (decision 0017).
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 *
 * **Three audiences, and the server tells them apart.** Reading the registry is any signed-in
 * account's; registering, updating and enabling are the platform governor's; switching a plugin on
 * for a project is a security lead's, and which projects a plugin reads is answered to the
 * governance roles. The screens only avoid offering what a role would be refused.
 *
 * The plugin id is part of a path here and is encoded as such. The server already refuses any id
 * outside `[a-z0-9-]`, so this changes nothing for a valid one — it keeps a hand-edited URL from
 * turning an id into a different route.
 */
@Injectable({ providedIn: 'root' })
export class PluginsApi {
    private readonly http = inject(HttpClient);

    plugins(): Observable<Plugin[]> {
        return this.http.get<Plugin[]>('/api/v1/plugins');
    }

    plugin(id: string): Observable<Plugin> {
        return this.http.get<Plugin>(`/api/v1/plugins/${encodeURIComponent(id)}`);
    }

    /** 201 on success; **409 when the id is taken** — ids are never reused, even by their owner. */
    registerPlugin(manifest: PluginManifest): Observable<Plugin> {
        return this.http.post<Plugin>('/api/v1/plugins', manifest);
    }

    /**
     * A new manifest under the same id. **400 if the manifest names another id**: the id is in every
     * issue fingerprint the plugin opened, so a rename would be a new plugin inheriting none of them.
     */
    updatePlugin(id: string, manifest: PluginManifest): Observable<Plugin> {
        return this.http.put<Plugin>(`/api/v1/plugins/${encodeURIComponent(id)}`, manifest);
    }

    /** Off everywhere from the next scan, without forgetting the projects it was switched on for. */
    setPluginEnabled(id: string, enabled: boolean): Observable<Plugin> {
        return this.http.put<Plugin>(`/api/v1/plugins/${encodeURIComponent(id)}/enabled`, { enabled });
    }

    /** The projects a plugin reads — governance, since it names parts of the estate. */
    pluginProjects(id: string): Observable<PluginActivation[]> {
        return this.http.get<PluginActivation[]>(`/api/v1/plugins/${encodeURIComponent(id)}/projects`);
    }

    /** 404 for a project that does not exist. */
    projectPlugins(projectId: number): Observable<PluginActivation[]> {
        return this.http.get<PluginActivation[]>(`/api/v1/projects/${projectId}/plugins`);
    }

    /** Idempotent: switching on what is already on changes nothing. */
    activatePlugin(projectId: number, pluginId: string): Observable<PluginActivation> {
        return this.http.put<PluginActivation>(
            `/api/v1/projects/${projectId}/plugins/${encodeURIComponent(pluginId)}`,
            null
        );
    }

    /** Its open issues stay as they are. 404 when it was not on. */
    deactivatePlugin(projectId: number, pluginId: string): Observable<void> {
        return this.http.delete<void>(`/api/v1/projects/${projectId}/plugins/${encodeURIComponent(pluginId)}`);
    }
}
