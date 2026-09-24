import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { MonitoredContainer, MonitoredRepository, NewContainer, NewRepository, NewSshKey, SshKeySummary } from '../api.models';

/**
 * The monitored repositories and container images, and the SSH keys repositories are cloned with.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class TargetsApi {
    private readonly http = inject(HttpClient);

    repositories(): Observable<MonitoredRepository[]> {
        return this.http.get<MonitoredRepository[]>('/api/v1/repositories');
    }

    createRepository(repository: NewRepository): Observable<MonitoredRepository> {
        return this.http.post<MonitoredRepository>('/api/v1/repositories', repository);
    }

    /**
     * Changes a repository. **Send only what changed.**
     *
     * Absent means unchanged and empty means cleared — sending the whole form back would erase
     * every field the form does not show, which is how an SSH key or a schedule disappears
     * without anybody touching it.
     */
    updateRepository(id: number, changes: Partial<NewRepository>): Observable<MonitoredRepository> {
        return this.http.patch<MonitoredRepository>(`/api/v1/repositories/${id}`, changes);
    }

    deleteRepository(id: number): Observable<void> {
        return this.http.delete<void>(`/api/v1/repositories/${id}`);
    }

    containers(): Observable<MonitoredContainer[]> {
        return this.http.get<MonitoredContainer[]>('/api/v1/containers');
    }

    createContainer(container: NewContainer): Observable<MonitoredContainer> {
        return this.http.post<MonitoredContainer>('/api/v1/containers', container);
    }

    /**
     * Changes a monitored image, the row and its scan history staying put.
     *
     * `Partial`, because the server reads an absent field as "leave alone": a screen that edits
     * two fields sends two fields. The one exception is the interval, where `null` is already
     * "leave alone" and switching a rescan off is spelled `0` — see `ContainersController.update`.
     */
    updateContainer(id: number, changes: Partial<NewContainer>): Observable<MonitoredContainer> {
        return this.http.patch<MonitoredContainer>(`/api/v1/containers/${id}`, changes);
    }

    deleteContainer(id: number): Observable<void> {
        return this.http.delete<void>(`/api/v1/containers/${id}`);
    }

    sshKeys(): Observable<SshKeySummary[]> {
        return this.http.get<SshKeySummary[]>('/api/v1/ssh-keys');
    }

    createSshKey(key: NewSshKey): Observable<{ id: string }> {
        return this.http.post<{ id: string }>('/api/v1/ssh-keys', key);
    }

    deleteSshKey(id: string): Observable<void> {
        return this.http.delete<void>(`/api/v1/ssh-keys/${id}`);
    }
}
