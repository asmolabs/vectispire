import { describe, it, expect, beforeEach, vi } from 'vitest';
import { TestBed } from '@angular/core/testing';
import { HttpClient } from '@angular/common/http';
import { of } from 'rxjs';
import { I18nService } from './i18n.service';
import { TranslatePipe } from './translate.pipe';

describe('I18nService & TranslatePipe', () => {
    let service: I18nService;
    let mockHttpClient: { get: ReturnType<typeof vi.fn> };

    const mockEn = {
        common: {
            save: 'Save',
            welcome: 'Hello {{ name }}!'
        },
        menu: {
            dashboard: 'Dashboard'
        }
    };

    const mockFr = {
        common: {
            save: 'Enregistrer',
            welcome: 'Bonjour {{ name }} !'
        },
        menu: {
            dashboard: 'Tableau de bord'
        }
    };

    beforeEach(() => {
        mockHttpClient = {
            get: vi.fn((url: string) => {
                if (url.includes('fr.json')) return of(mockFr);
                return of(mockEn);
            })
        };

        TestBed.configureTestingModule({
            providers: [
                I18nService,
                TranslatePipe,
                { provide: HttpClient, useValue: mockHttpClient }
            ]
        });

        service = TestBed.inject(I18nService);
    });

    it('loads language and translates simple keys', async () => {
        await service.setLanguage('en');
        expect(service.currentLang()).toBe('en');
        expect(service.t('common.save')).toBe('Save');
        expect(service.t('menu.dashboard')).toBe('Dashboard');
    });

    it('interpolates parameters in translation strings', async () => {
        await service.setLanguage('en');
        expect(service.t('common.welcome', { name: 'Alice' })).toBe('Hello Alice!');
    });

    it('switches language and translates in French', async () => {
        await service.setLanguage('fr');
        expect(service.currentLang()).toBe('fr');
        expect(service.t('common.save')).toBe('Enregistrer');
        expect(service.t('menu.dashboard')).toBe('Tableau de bord');
        expect(service.t('common.welcome', { name: 'Bob' })).toBe('Bonjour Bob !');
    });

    it('falls back to the key name if not found', async () => {
        await service.setLanguage('en');
        expect(service.t('unknown.key')).toBe('unknown.key');
    });

    it('works with TranslatePipe', async () => {
        await service.setLanguage('fr');
        const pipe = TestBed.inject(TranslatePipe);
        expect(pipe.transform('common.save')).toBe('Enregistrer');
        expect(pipe.transform('common.welcome', { name: 'Charlie' })).toBe('Bonjour Charlie !');
    });
});
