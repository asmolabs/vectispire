import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Owasp } from './owasp';

/**
 * The OWASP screen.
 *
 * <p>Written after three defects that the compiler could not see and no test existed to catch:
 * a report rendered as raw Markdown, a failed run shown as an empty page, and a download that
 * bypassed the interceptor and saved zero bytes. All three are template and wiring behaviour —
 * the kind that only a mounted component reveals.
 */
/**
 * jsdom refuses a real navigation and prints a stack for it. `saveDocument` clicks an anchor to
 * hand the blob to the browser, which is the behaviour under test — the noise is the environment
 * saying it is not a browser, and left in it would hide a genuine error in the same output.
 */
function silenceAnchorNavigation(): void {
    HTMLAnchorElement.prototype.click = function click() {};
}

describe('the OWASP report screen', () => {
    let fixture: ComponentFixture<Owasp>;
    let http: HttpTestingController;

    beforeEach(async () => {
        silenceAnchorNavigation();
        await TestBed.configureTestingModule({
            imports: [Owasp],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(Owasp);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        // The constructor asks for the repositories it offers in the picker.
        http.expectOne('/api/v1/repositories').flush([
            { id: 5, displayName: 'Arm Libs Spring', url: 'ssh://git@example.com/art/arm.git', branch: 'master' }
        ]);
        fixture.detectChanges();
    });

    function runProducing(report: Record<string, unknown>): void {
        fixture.componentInstance.selected = 5;
        fixture.componentInstance.run();
        http.expectOne({ method: 'POST', url: '/api/v1/repositories/5/owasp-review' }).flush(report);
        fixture.detectChanges();
    }

    it('renders the report from blocks, never as raw Markdown', () => {
        runProducing({
            id: 1,
            status: 'completed',
            model: 'gemma4:e4b',
            content: '## A03 — Injection\n\nA finding.',
            blocks: [
                { kind: 'CATEGORY', level: 2, marker: null, text: 'A03 — Injection' },
                { kind: 'PARAGRAPH', level: 0, marker: null, text: 'A finding.' }
            ],
            error: null,
            scanId: 34,
            createdAt: '2026-08-21T07:57:53Z'
        });

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('A03 — Injection');
        expect(text).toContain('A finding.');
        // The hashes are typography, not content. Printing them is what the block rendering
        // replaced, and it is invisible to the compiler.
        expect(text).not.toContain('## ');
    });

    it('shows a failed run with its reason instead of an empty page', () => {
        runProducing({
            id: 2,
            status: 'failed',
            model: 'ornith-1.5:9b',
            content: null,
            blocks: [],
            error: 'Ollama: request timed out',
            scanId: 34,
            createdAt: '2026-08-21T07:40:01Z'
        });

        // A run that vanished would leave this page identical to one nobody ever asked for.
        expect(fixture.nativeElement.textContent).toContain('Ollama: request timed out');
    });

    it('offers the PDF only for a report that exists', () => {
        runProducing({
            id: 3, status: 'failed', model: 'm', content: null, blocks: [],
            error: 'boom', scanId: 34, createdAt: '2026-08-21T07:40:01Z'
        });
        // A PDF of "the model could not be reached", under an OWASP cover, would look like a
        // report and say nothing — and a file travels away from the screen that explained it.
        expect(fixture.nativeElement.textContent).not.toContain('Export PDF');

        runProducing({
            id: 4, status: 'completed', model: 'm', content: 'x',
            blocks: [{ kind: 'PARAGRAPH', level: 0, marker: null, text: 'x' }],
            error: null, scanId: 34, createdAt: '2026-08-21T07:57:53Z'
        });
        expect(fixture.nativeElement.textContent).toContain('Export PDF');
    });

    it('downloads through HttpClient, because a navigation carries no token', () => {
        runProducing({
            id: 5, status: 'completed', model: 'm', content: 'x',
            blocks: [{ kind: 'PARAGRAPH', level: 0, marker: null, text: 'x' }],
            error: null, scanId: 34, createdAt: '2026-08-21T07:57:53Z'
        });

        fixture.componentInstance.downloadPdf();

        // The defect this pins: `window.location.href` is not a request the interceptor sees, so
        // the session token never travels, the server answers 401 and the browser writes the
        // empty error body to disk as a zero-byte file.
        const request = http.expectOne('/api/v1/repositories/5/owasp-review/export.pdf');
        expect(request.request.responseType).toBe('blob');
        request.flush(new Blob(['%PDF-1.4'], { type: 'application/pdf' }));
    });

    it('reports a refusal rather than staying silent', () => {
        fixture.componentInstance.selected = 5;
        fixture.componentInstance.run();
        http.expectOne({ method: 'POST', url: '/api/v1/repositories/5/owasp-review' })
            .flush({ detail: 'Model review is switched off.' }, { status: 409, statusText: 'Conflict' });
        fixture.detectChanges();

        expect(fixture.componentInstance.running()).toBe(false);
        expect(fixture.componentInstance.error()).not.toBeNull();
    });
});
