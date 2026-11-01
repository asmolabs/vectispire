import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { useEnglish, useFrench } from '@/app/core/testing/english';
import type { LastScan } from '@/app/core/api.models';
import { LastScanTag } from './last-scan';

/**
 * The last-scan tag works out its words and its colour from its input, not from a method called on
 * every pass — so what it shows has to follow the input and the language, which is what these pin.
 */
describe('the last-scan tag', () => {
    let fixture: ComponentFixture<LastScanTag>;

    const scan = (status: string): LastScan => ({ id: 1, status, createdAt: '2026-10-01T10:00:00Z', error: null });
    const tag = () => (fixture.nativeElement as HTMLElement).querySelector('.p-tag')!;

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [LastScanTag],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting()]
        }).compileComponents();
        useEnglish();
        fixture = TestBed.createComponent(LastScanTag);
    });

    it('words the status and colours it, and follows a new scan', () => {
        fixture.componentRef.setInput('scan', scan('failed'));
        fixture.detectChanges();
        expect(tag().textContent.trim()).toBe('Failed');
        expect(tag().className).toContain('p-tag-danger');

        fixture.componentRef.setInput('scan', scan('completed'));
        fixture.detectChanges();
        expect(tag().textContent.trim()).toBe('Completed');
        expect(tag().className).toContain('p-tag-success');
    });

    it('shows a status it does not know as sent, in the neutral colour', () => {
        fixture.componentRef.setInput('scan', scan('archived'));
        fixture.detectChanges();
        expect(tag().textContent.trim()).toBe('archived');
        expect(tag().className).toContain('p-tag-info');
    });

    it('words the status in the reader language, after a switch too', () => {
        fixture.componentRef.setInput('scan', scan('failed'));
        fixture.detectChanges();
        const english = tag().textContent.trim();
        useFrench();
        fixture.detectChanges();
        expect(tag().textContent.trim()).not.toBe(english);
        expect(tag().textContent.trim()).toBe('Échoué');
    });
});
