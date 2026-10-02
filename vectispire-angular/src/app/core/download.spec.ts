import { HttpHeaders, HttpResponse } from '@angular/common/http';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { filenameOf, saveBlob, saveDocument, saveJson } from './download';

/**
 * The one place a file is saved. Five screens used to build their own object URL and anchor; the
 * copies agreed only by luck, and a copy that forgot to revoke kept every export in memory.
 */
describe('saving a document', () => {
    const saved: { name: string; href: string }[] = [];
    let made: Blob[];
    let revoked: string[];

    beforeEach(() => {
        saved.length = 0;
        made = [];
        revoked = [];
        // happy-dom's anchor click navigates the window; what was saved, and under what name, is the point.
        vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
            saved.push({ name: this.download, href: this.href });
        });
        vi.spyOn(URL, 'createObjectURL').mockImplementation((blob: Blob | MediaSource) => {
            made.push(blob as Blob);
            return `blob:test/${made.length}`;
        });
        vi.spyOn(URL, 'revokeObjectURL').mockImplementation((url: string) => {
            revoked.push(url);
        });
    });

    afterEach(() => vi.restoreAllMocks());

    it('saves a JSON document indented, as JSON, under the name given, and frees it', async () => {
        saveJson({ '@context': 'https://openvex.dev/ns/v0.2.0', statements: [] }, 'scan-34-openvex.json');

        expect(saved).toEqual([{ name: 'scan-34-openvex.json', href: 'blob:test/1' }]);
        expect(made[0].type).toBe('application/json');
        expect(await made[0].text()).toBe('{\n  "@context": "https://openvex.dev/ns/v0.2.0",\n  "statements": []\n}');
        expect(revoked).toEqual(['blob:test/1']);
    });

    it('saves a blob as it is', () => {
        const pem = new Blob(['-----BEGIN PUBLIC KEY-----'], { type: 'application/x-pem-file' });

        saveBlob(pem, 'vectispire-signing-key.pub');

        expect(saved.map((file) => file.name)).toEqual(['vectispire-signing-key.pub']);
        expect(made).toEqual([pem]);
        expect(revoked).toEqual(['blob:test/1']);
    });

    it("prefers the server's filename over the fallback, and saves nothing for an empty body", () => {
        const headers = new HttpHeaders({ 'Content-Disposition': 'attachment; filename="history-5.csv"' });

        saveDocument(new HttpResponse({ body: new Blob(['a,b']), headers }), 'fallback.csv');
        saveDocument(new HttpResponse({ body: new Blob(['a,b']) }), 'fallback.csv');
        saveDocument(new HttpResponse<Blob>({ body: null }), 'nothing.csv');

        expect(saved.map((file) => file.name)).toEqual(['history-5.csv', 'fallback.csv']);
        expect(revoked).toHaveLength(2);
    });

    it('reads the filename out of a Content-Disposition header', () => {
        expect(filenameOf('attachment; filename="a.pdf"')).toBe('a.pdf');
        expect(filenameOf('attachment')).toBeNull();
        expect(filenameOf(null)).toBeNull();
    });
});
