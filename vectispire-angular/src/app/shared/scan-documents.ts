import { Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';
import { DocumentsApi } from '../core/api/documents.api';
import { saveDocument } from '../core/download';

/** The documents a scan is served as, each by its own route. */
export type ScanDocument = 'sbom' | 'attestation' | 'csaf' | 'cyclonedx';

/**
 * Where each scan document is served and the name it is saved under when the server names none.
 * One table for the scan's page and the repositories' shortcut, so the same scan saves as the same
 * file from either — `vectispire-scan-<id>.sbom.json` is also what the CLI's `sbom` writes.
 */
export function scanDocument(kind: ScanDocument, id: number): { path: string; filename: string } {
    switch (kind) {
        case 'sbom':
            return { path: `/api/v1/scans/${id}/sbom`, filename: `vectispire-scan-${id}.sbom.json` };
        case 'attestation':
            return { path: `/api/v1/attestations/scans/${id}`, filename: `vectispire-scan-${id}.attestation.json` };
        case 'csaf':
            return { path: `/api/v1/csaf/scans/${id}/csaf.json`, filename: `vectispire-scan-${id}.csaf.json` };
        case 'cyclonedx':
            return {
                path: `/api/v1/cyclonedx/scans/${id}/cyclonedx-vex.json`,
                filename: `vectispire-scan-${id}.cyclonedx-vex.json`
            };
    }
}

/**
 * Saves a scan document. Through `HttpClient`, never a navigation: the token is in memory and a
 * navigation carries none, so the browser would save the 401's empty body as a zero-byte file
 * (`core/download.ts`). The observable completes once the file is handed to the browser and fails
 * with the response when the server refuses, for the caller to say so.
 */
@Injectable({ providedIn: 'root' })
export class ScanDocuments {
    private readonly documentsApi = inject(DocumentsApi);

    save(kind: ScanDocument, id: number): Observable<void> {
        const { path, filename } = scanDocument(kind, id);
        return this.documentsApi.downloadDocument(path).pipe(map((response) => saveDocument(response, filename)));
    }
}
