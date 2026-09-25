import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpResponse } from '@angular/common/http';
import { Observable } from 'rxjs';
import { OpenVexDocument, CosignCliHelper, VexIngestResult } from '../api.models';

/**
 * Documents served as files or issued for others to verify: exports, VEX, CSAF, CycloneDX, and the
 * signatures over them.
 *
 * One stateless client per domain, named `*.api.ts` / `*Api` so that it is never mistaken for a
 * `*.service.ts` or a store holding state, and so that `scripts/check-dead-api-methods.mjs` knows
 * which files declare the API surface. No absolute URL: the development server proxies `/api`
 * (`proxy.conf.json`) and production serves both from one origin, which is what lets the CSP stay
 * on `connect-src 'self'`.
 */
@Injectable({ providedIn: 'root' })
export class DocumentsApi {
    private readonly http = inject(HttpClient);

    /**
     * An export, as bytes plus the response that carries its filename.
     *
     * **Not a plain `<a href>`**, which was the first attempt and answered 401 every time: the
     * session token lives in memory and is put on requests by the interceptor, so a browser
     * navigation carries no credential at all. Going through `HttpClient` is what authenticates
     * the download — and `observe: 'response'` is what keeps the server's filename, which the
     * body alone does not carry.
     */
    exportDocument(kind: string, id: number, document: string): Observable<HttpResponse<Blob>> {
        return this.http.get(`/api/v1/targets/${kind}/${id}/${document}`, {
            responseType: 'blob',
            observe: 'response'
        });
    }

    /**
     * Any document the server serves as a file.
     *
     * **Through `HttpClient`, never a navigation.** The token is in memory and travels only on
     * requests the interceptor sees; a browser navigation carries none, the server answers 401
     * and the browser saves the empty body as a zero-byte file.
     */
    downloadDocument(path: string): Observable<HttpResponse<Blob>> {
        return this.http.get(path, { responseType: 'blob', observe: 'response' });
    }

    getScanVex(scanId: number): Observable<OpenVexDocument> {
        return this.http.get<OpenVexDocument>(`/api/v1/vex/scans/${scanId}/openvex.json`);
    }

    getAggregateVex(): Observable<OpenVexDocument> {
        return this.http.get<OpenVexDocument>('/api/v1/vex/aggregate.json');
    }

    getAggregateCsaf(): Observable<unknown> {
        return this.http.get<unknown>('/api/v1/csaf/aggregate.json');
    }

    getAggregateCycloneDx(): Observable<unknown> {
        return this.http.get<unknown>('/api/v1/cyclonedx/aggregate.json');
    }

    ingestVex(doc: unknown): Observable<VexIngestResult> {
        return this.http.post<VexIngestResult>('/api/v1/vex/ingest', doc);
    }

    getPublicKeyPem(): Observable<string> {
        return this.http.get('/api/v1/crypto/public-key.pub', { responseType: 'text' });
    }

    /** `vectispireKey` says whether the key checked is Vectispire's: valid under any other key vouches for nothing. */
    verifyCryptoSignature(payload: string, signature: string, publicKey?: string): Observable<{ valid: boolean; keyId: string; vectispireKey: boolean; algorithm: string; message: string }> {
        return this.http.post<{ valid: boolean; keyId: string; vectispireKey: boolean; algorithm: string; message: string }>('/api/v1/crypto/verify', { payload, signature, publicKey });
    }

    getCosignCliHelper(): Observable<CosignCliHelper> {
        return this.http.get<CosignCliHelper>('/api/v1/crypto/cosign-cli-helper');
    }
}
