import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { Type } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import document from '../../../openapi.json';
import { useEnglish } from '@/app/core/testing/english';
import { AuditLog } from '@/app/pages/audit-log/audit-log';
import { BlastRadius } from '@/app/pages/blast-radius/blast-radius';
import { Inventory } from '@/app/pages/inventory/inventory';
import { Issues } from '@/app/pages/issues/issues';
import { SEARCH_MAX_LENGTH } from './search-bound';

interface Operation {
    parameters?: { name: string; schema?: { maxLength?: number } }[];
}

/** The `maxLength` the contract publishes for one query parameter of one route. */
function publishedBound(path: string, parameter: string): number | undefined {
    const paths = document.paths as unknown as Record<string, { get?: Operation }>;
    return paths[path]?.get?.parameters?.find((declared) => declared.name === parameter)?.schema?.maxLength;
}

/**
 * The search boxes stop where the server stops answering.
 *
 * <p>The list routes refuse a free-text search past one figure with a 400. A box without a `maxlength` let
 * a reader type or paste past it and get an error where their results should be; the figure here and the
 * server's are tied through the contract, read back below, and each box is read in the DOM, where the
 * browser enforces it.
 */
describe('the search boxes, bounded as the server bounds them', () => {
    it.each([
        ['/api/v1/issues', 'search'],
        ['/api/v1/audit-log', 'search'],
        ['/api/v1/blast-radius/explore', 'q'],
        ['/api/v1/inventory/search', 'name'],
        ['/api/v1/inventory/versions', 'name']
    ])('%s?%s= is bounded in the contract by the figure the boxes carry', (path, parameter) => {
        expect(publishedBound(path, parameter)).toBe(SEARCH_MAX_LENGTH);
    });

    describe('each box', () => {
        beforeEach(async () => {
            TestBed.resetTestingModule();
            await TestBed.configureTestingModule({
                providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
            }).compileComponents();
            useEnglish();
        }, 20_000);

        function box(component: Type<unknown>, selector: string): HTMLInputElement {
            const fixture = TestBed.createComponent(component);
            fixture.detectChanges();
            const input = (fixture.nativeElement as HTMLElement).querySelector<HTMLInputElement>(selector);
            expect(input, selector).not.toBeNull();
            return input!;
        }

        it.each<[string, Type<unknown>, string]>([
            ['the backlog', Issues, 'input[aria-label="Search the issues"]'],
            ['the audit log', AuditLog, 'input#q'],
            ['the component search', Inventory, 'input#name'],
            ['the blast radius', BlastRadius, 'input[type="text"]']
        ])("%s's search box takes no more than the server answers", (_, component, selector) => {
            expect(box(component, selector).maxLength).toBe(SEARCH_MAX_LENGTH);
        });
    });
});
