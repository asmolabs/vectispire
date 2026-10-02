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
        },
        scans: {
            queued_one: 'Scan queued for {{count}} repository.',
            queued_other: 'Scan queued for {{count}} repositories.',
            mean_one: '{{count}} day',
            mean_other: '{{count}} days',
            seen_once: 'seen once',
            refused: 'refusals',
            refused_one: 'refused'
        }
    };

    const mockFr = {
        common: {
            save: 'Enregistrer',
            welcome: 'Bonjour {{ name }} !'
        },
        menu: {
            dashboard: 'Tableau de bord'
        },
        scans: {
            queued_one: 'Analyse planifiée pour {{count}} dépôt.',
            queued_other: 'Analyse planifiée pour {{count}} dépôts.',
            lose_one: '{{count}} membre perd {{targets}}.',
            lose_other: '{{count}} membres perdent {{targets}}.',
            targets_one: '{{count}} cible',
            targets_other: '{{count}} cibles'
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
            providers: [I18nService, TranslatePipe, { provide: HttpClient, useValue: mockHttpClient }]
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

    /**
     * "1 repositories" was on screen wherever a count was: the strings were written for the plural
     * and the singular never came. The language's rule picks the form, not `count === 1`.
     */
    describe('plurals', () => {
        it('takes the singular for one and the plural otherwise, in English', async () => {
            await service.setLanguage('en');
            expect(service.t('scans.queued', { count: 1 })).toBe('Scan queued for 1 repository.');
            expect(service.t('scans.queued', { count: 0 })).toBe('Scan queued for 0 repositories.');
            expect(service.t('scans.queued', { count: 12 })).toBe('Scan queued for 12 repositories.');
        });

        it('takes the singular for zero as well in French', async () => {
            await service.setLanguage('fr');
            expect(service.t('scans.queued', { count: 0 })).toBe('Analyse planifiée pour 0 dépôt.');
            expect(service.t('scans.queued', { count: 1 })).toBe('Analyse planifiée pour 1 dépôt.');
            expect(service.t('scans.queued', { count: 2 })).toBe('Analyse planifiée pour 2 dépôts.');
            // CLDR's `many` for French large round numbers falls back to the general form.
            expect(service.t('scans.queued', { count: 1_000_000 })).toBe('Analyse planifiée pour 1000000 dépôts.');
        });

        it('reads a count given as text with its decimals, as the reader sees it', async () => {
            await service.setLanguage('en');
            expect(service.t('scans.mean', { count: '1' })).toBe('1 day');
            expect(service.t('scans.mean', { count: '1.0' })).toBe('1.0 days');
            expect(service.t('scans.mean', { count: '2.5' })).toBe('2.5 days');
        });

        it('gives the general form to a plural key asked without a count, never the raw key', async () => {
            await service.setLanguage('en');
            expect(service.t('scans.queued')).toBe('Scan queued for {{count}} repositories.');
        });

        it('leaves a key that merely ends like a plural form alone', async () => {
            await service.setLanguage('en');
            expect(service.t('scans.seen_once', { count: 1 })).toBe('seen once');
            // `gate_verdicts.refused_one` sits beside `refused` in the real bundle: a word, not a form.
            expect(service.t('scans.refused', { count: 1 })).toBe('refusals');
        });

        it('agrees a second count through a phrase of its own, never through the first', async () => {
            // "ses 3 membre(s) perdent les 1 cible(s)": a sentence with two counts. `count` chooses the
            // sentence; the other count is a phrase translated with its own, and passed in as text.
            await service.setLanguage('fr');
            const lose = (members: number, targets: number) =>
                service.t('scans.lose', { count: members, targets: service.t('scans.targets', { count: targets }) });
            expect(lose(3, 1)).toBe('3 membres perdent 1 cible.');
            expect(lose(1, 2)).toBe('1 membre perd 2 cibles.');
        });

        it('chooses through the pipe too', async () => {
            await service.setLanguage('en');
            const pipe = TestBed.inject(TranslatePipe);
            expect(pipe.transform('scans.queued', { count: 1 })).toBe('Scan queued for 1 repository.');
        });
    });
});
