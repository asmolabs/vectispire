import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { Containers } from './containers';

/**
 * The container list, as cards rather than rows.
 *
 * <p>Same conversion as the repositories, and the same thing to prove: that the card still
 * carries what the row did. A smoke test only says the screen renders.
 */
describe('the container list', () => {
    let fixture: ComponentFixture<Containers>;
    let http: HttpTestingController;

    const CONTAINER = {
        id: 3,
        imageName: 'nginx',
        reference: 'nginx@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        tag: 'sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        openIssues: 12,
        lastScan: { id: 18, status: 'completed', createdAt: '2026-08-21T05:03:00Z', error: null }
    };

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [Containers],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(Containers);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
    });

    function load(container: Record<string, unknown> = CONTAINER): void {
        for (const request of http.match(() => true)) {
            request.flush(request.request.url.endsWith('/containers') ? [container] : []);
        }
        fixture.detectChanges();
    }

    it('keeps every field the row carried', () => {
        load();

        const text = fixture.nativeElement.textContent as string;
        expect(text).toContain('nginx');
        expect(text).toContain('12 outstanding');
    });

    it('truncates the reference on screen and keeps it whole on hover', () => {
        load();

        // Sixty characters of hexadecimal would push everything else off a phone, and a digest is
        // read to be compared rather than to be read.
        const shortened = fixture.nativeElement.querySelector('[title*="sha256:"]');
        expect(shortened).not.toBeNull();
        expect(shortened.getAttribute('title')).toContain('1234567890abcdef');
        expect(shortened.textContent.length).toBeLessThan(CONTAINER.reference.length);
    });

    it("links the outstanding count to that image's backlog", () => {
        load();

        const link = fixture.nativeElement.querySelector('a[href*="/issues"]');
        expect(link.getAttribute('href')).toContain('container_id=3');
    });

    it('says "nothing outstanding" rather than showing a bare zero', () => {
        load({ ...CONTAINER, openIssues: 0 });
        expect(fixture.nativeElement.textContent).toContain('nothing outstanding');
    });

    it('says a never-scanned image was never scanned', () => {
        load({ ...CONTAINER, lastScan: null });
        expect(fixture.nativeElement.textContent).toContain('Never scanned');
    });
});
