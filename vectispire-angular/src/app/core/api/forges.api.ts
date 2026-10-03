import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import type {
    ForgeCandidatePage,
    ForgeConnection,
    ForgeDiscovery,
    ForgeImportPreview,
    ForgeImportRequest,
    ForgeImportResult,
    ForgeRepositoryPage,
    ForgeSelection,
    ForgeSelectionFilters,
    Schema
} from '../api.models';

/** Which part of a discovery's comparison to read: `gone` is answered for a completed run only. */
export type ForgeChange = 'all' | 'new' | 'changed' | 'gone';

/** The selection's operations (decision 0037 §4): over what the filters match, or by id. */
export type ForgeSelectionOperation = 'proposed' | 'all' | 'none' | 'invert' | 'add' | 'remove';

/**
 * Forge connections, their discoveries, the selection and the import (decision 0037). Administrators
 * only, as every route behind it.
 *
 * **The token goes one way.** It is sent in the body of a creation or a replacement and never comes back:
 * no route returns it, and no method here has a reason to keep it.
 *
 * **The selection is the screen's**, a set of forge ids sent with each gesture; the server stores nothing
 * of it, so every operation carries the ids ticked so far and answers the new set.
 */
@Injectable({ providedIn: 'root' })
export class ForgesApi {
    private readonly http = inject(HttpClient);

    forgeConnections(): Observable<ForgeConnection[]> {
        return this.http.get<ForgeConnection[]>('/api/v1/forge-connections');
    }

    forgeConnection(id: string): Observable<ForgeConnection> {
        return this.http.get<ForgeConnection>(`/api/v1/forge-connections/${encodeURIComponent(id)}`);
    }

    /** Probed against the forge before anything is kept: a refusal is a 400 whose `detail` says why. */
    createForgeConnection(request: Schema<'ForgeConnectionRequest'>): Observable<ForgeConnection> {
        return this.http.post<ForgeConnection>('/api/v1/forge-connections', request);
    }

    /** A blank `caPem` unpins the CA; an absent one keeps it. The address never changes. */
    updateForgeConnection(id: string, change: Schema<'ForgeConnectionChange'>): Observable<ForgeConnection> {
        return this.http.patch<ForgeConnection>(`/api/v1/forge-connections/${encodeURIComponent(id)}`, change);
    }

    /** Rotation in place, probed as at creation: the connection keeps its id and its discoveries. */
    replaceForgeConnectionToken(id: string, token: string): Observable<ForgeConnection> {
        return this.http.put<ForgeConnection>(`/api/v1/forge-connections/${encodeURIComponent(id)}/token`, {
            token
        } satisfies Schema<'ForgeTokenReplacement'>);
    }

    /** No target goes with it: an imported repository is a target like any other. */
    deleteForgeConnection(id: string): Observable<void> {
        return this.http.delete<void>(`/api/v1/forge-connections/${encodeURIComponent(id)}`);
    }

    /** The connection's last fifty discoveries, newest first. */
    forgeDiscoveries(connectionId: string): Observable<ForgeDiscovery[]> {
        return this.http.get<ForgeDiscovery[]>(this.discoveriesOf(connectionId));
    }

    /** 202 with the run, pending; 409 `forge-discovery-in-progress` names the running one in `discoveryId`. */
    requestForgeDiscovery(connectionId: string): Observable<ForgeDiscovery> {
        return this.http.post<ForgeDiscovery>(this.discoveriesOf(connectionId), null);
    }

    forgeDiscovery(connectionId: string, discoveryId: number): Observable<ForgeDiscovery> {
        return this.http.get<ForgeDiscovery>(`${this.discoveriesOf(connectionId)}/${discoveryId}`);
    }

    /** One page of a discovery's comparison; `offset` is a multiple of `limit`. */
    discoveredRepositories(
        connectionId: string,
        discoveryId: number,
        change: ForgeChange,
        limit: number,
        offset: number
    ): Observable<ForgeRepositoryPage> {
        const params = new HttpParams().set('change', change).set('limit', limit).set('offset', offset);
        return this.http.get<ForgeRepositoryPage>(`${this.discoveriesOf(connectionId)}/${discoveryId}/repositories`, {
            params
        });
    }

    /** The selection table: the filters in the query, one page of candidates and what each filter could not judge. */
    importCandidates(
        connectionId: string,
        discoveryId: number,
        filters: ForgeSelectionFilters,
        limit: number,
        offset: number
    ): Observable<ForgeCandidatePage> {
        let params = new HttpParams().set('limit', limit).set('offset', offset);
        for (const [key, value] of Object.entries(filters)) {
            if (value !== undefined && value !== null && value !== '') params = params.set(key, String(value));
        }
        return this.http.get<ForgeCandidatePage>(`${this.discoveriesOf(connectionId)}/${discoveryId}/selection`, {
            params
        });
    }

    /** Nothing is written: the answer is the new selection, and the ids that could not be ticked. */
    changeImportSelection(
        connectionId: string,
        discoveryId: number,
        operation: ForgeSelectionOperation,
        selected: readonly string[],
        filters: ForgeSelectionFilters,
        forgeIds: readonly string[] = []
    ): Observable<ForgeSelection> {
        const body: Schema<'ForgeSelectionChange'> = {
            operation,
            selected: [...selected],
            filters,
            forgeIds: [...forgeIds]
        };
        return this.http.post<ForgeSelection>(`${this.discoveriesOf(connectionId)}/${discoveryId}/selection`, body);
    }

    /** What the import would do, nothing written. */
    previewForgeImport(connectionId: string, request: ForgeImportRequest): Observable<ForgeImportPreview> {
        return this.http.post<ForgeImportPreview>(
            `/api/v1/forge-connections/${encodeURIComponent(connectionId)}/imports/preview`,
            request
        );
    }

    /** One transaction: everything the preview listed, or nothing. Replaying it creates nothing. */
    importForgeRepositories(connectionId: string, request: ForgeImportRequest): Observable<ForgeImportResult> {
        return this.http.post<ForgeImportResult>(
            `/api/v1/forge-connections/${encodeURIComponent(connectionId)}/imports`,
            request
        );
    }

    private discoveriesOf(connectionId: string): string {
        return `/api/v1/forge-connections/${encodeURIComponent(connectionId)}/discoveries`;
    }
}
