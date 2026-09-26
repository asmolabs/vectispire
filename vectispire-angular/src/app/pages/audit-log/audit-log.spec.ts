import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { AuditLog } from './audit-log';
import { I18nService, TranslationTree } from '@/app/core/i18n/i18n.service';
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
            'PROJECT_REPOSITORIES_CHANGED'
        ]);
        return page.operationOptions().map((option) => option.label);
    }

    it('names the solution and project operations in English', () => {
        expect(labels(english)).toEqual(['Solution changed', 'Project changed', 'Project repositories changed']);
    });

    it('names them in French', () => {
        expect(labels(french)).toEqual(['Solution modifiée', 'Projet modifié', 'Dépôts du projet modifiés']);
    });
});
