import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { AuditLog } from './audit-log';
import { I18nService, TranslationTree } from '@/app/core/i18n/i18n.service';
import { asSchema } from '@/app/core/testing/contract';
import english from '../../../../public/i18n/en.json';
import french from '../../../../public/i18n/fr.json';

/**
 * The operation filter, in words.
 *
 * <p>The label map is an open table — an unknown type is shown raw — so a type the server starts
 * recording reads as `PROJECT_REPOSITORIES_CHANGED` until somebody adds it, and nothing fails. The
 * keys it names are not literal calls either, so the i18n check cannot see a missing translation.
 * This pins the solution and project operations (decision 0023) in both languages.
 */
describe('the audit log operation labels', () => {
    let http: HttpTestingController;

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [AuditLog],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        http = TestBed.inject(HttpTestingController);
    }, 20_000);

    function labels(bundle: TranslationTree): string[] {
        TestBed.inject(I18nService).translations.set(bundle);
        const page = TestBed.createComponent(AuditLog).componentInstance;
        http.expectOne((call) => call.url === '/api/v1/audit-log/operation-types').flush([
            'SOLUTION_UPDATED',
            'PROJECT_UPDATED',
            'PROJECT_REPOSITORIES_CHANGED',
            'PROJECT_CONTAINERS_CHANGED'
        ]);
        return page.operationOptions().map((option) => option.label);
    }

    it('names the solution and project operations in English', () => {
        expect(labels(english)).toEqual([
            'Solution changed',
            'Project changed',
            'Project repositories changed',
            'Project images changed'
        ]);
    });

    it('names them in French', () => {
        expect(labels(french)).toEqual([
            'Solution modifiée',
            'Projet modifié',
            'Dépôts du projet modifiés',
            'Images du projet modifiées'
        ]);
    });
});

/**
 * The chain's verdict, counted. It read "1 entrée(s) vérifiée(s), 1 antérieure(s) au chaînage": two
 * counts in one sentence had kept it out of the plural pairs. The second count is a phrase of its own,
 * so each agrees with its own number — in French, where "antérieure" agrees too.
 */
describe('the audit chain verdict', () => {
    let http: HttpTestingController;

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [AuditLog],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        http = TestBed.inject(HttpTestingController);
    }, 20_000);

    function verdict(bundle: TranslationTree, verified: number, unverifiable: number): string {
        TestBed.inject(I18nService).translations.set(bundle);
        const fixture = TestBed.createComponent(AuditLog);
        fixture.detectChanges();
        http.expectOne('/api/v1/audit-log/verify').flush(
            asSchema('Verification', {
                intact: true,
                broken: null,
                mirrored: false,
                missingFromMirror: 0,
                missingFromTable: 0,
                total: verified + unverifiable,
                unverifiable,
                verified
            })
        );
        fixture.detectChanges();
        return ((fixture.nativeElement as HTMLElement).querySelector('p-message')?.textContent ?? '').trim();
    }

    it('agrees each count with its own noun, in French', () => {
        expect(verdict(french, 1, 1)).toBe('Chaîne intègre — 1 entrée vérifiée, 1 antérieure au chaînage.');
    });

    it('takes the plural for each count that needs it, independently', () => {
        expect(verdict(french, 1, 3)).toBe('Chaîne intègre — 1 entrée vérifiée, 3 antérieures au chaînage.');
    });

    it('says one entry in English, and no partial clause when every entry was verifiable', () => {
        expect(verdict(english, 1, 0)).toBe('Chain intact — 1 entry verified.');
    });

    it('says entries for any other number in English', () => {
        expect(verdict(english, 4, 2)).toBe('Chain intact — 4 entries verified, 2 predating the chaining.');
    });
});
