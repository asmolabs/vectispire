import { HttpResponse } from '@angular/common/http';

/**
 * Saving a document the server sent.
 *
 * **Never a plain navigation, and this is the mistake that keeps being made.** The session token
 * lives in memory and is put on requests by the interceptor; `window.location.href` and
 * `<a href>` are not requests the interceptor sees, so they carry no credential at all. The
 * server answers 401 and the browser writes the empty error body to disk — a download that
 * "worked" and produced a file of zero bytes. It happened to the first export written here, and
 * again to three added later, which is why the mechanism now lives in one place with the reason
 * attached.
 *
 * The blob must therefore come through `HttpClient`, with `observe: 'response'` so the server's
 * filename survives: the body alone does not carry it.
 */
export function saveDocument(response: HttpResponse<Blob>, fallbackName: string): void {
    const blob = response.body;
    if (!blob) {
        return;
    }

    const url = URL.createObjectURL(blob);
    const link = window.document.createElement('a');
    link.href = url;
    link.download = filenameOf(response.headers.get('Content-Disposition')) ?? fallbackName;
    link.click();
    // Revoked immediately: the blob holds the whole export in memory, and a tab left open on a
    // screen with an export button would accumulate one per click.
    URL.revokeObjectURL(url);
}

/** The name the server chose, or nothing when it did not say. */
export function filenameOf(disposition: string | null): string | null {
    const match = disposition?.match(/filename="([^"]+)"/);
    return match ? match[1] : null;
}
