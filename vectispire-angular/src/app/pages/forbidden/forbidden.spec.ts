import { provideHttpClient } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, convertToParamMap, provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { SessionStore } from '@/app/core/session.store';
import { missingFromBundles } from '@/app/core/testing/bundles';
import { useEnglish } from '@/app/core/testing/english';
import english from '../../../../public/i18n/en.json';
import { Forbidden, NEED_KEYS } from './forbidden';

/**
 * The refusal page, read as the person refused reads it: a heading saying what the page needs, and
 * what their account is.
 *
 * Both used to be keys built from a value — `forbidden.need_${need}` from the query string,
 * `roles.${role}` from the session — so a need or a role the bundle did not name put a key path in
 * the page's only heading (decision 0019).
 */
describe('the refusal page', () => {
    beforeEach(() => {
        TestBed.resetTestingModule();
    });

    function render(query: Record<string, string>, role: string): HTMLElement {
        TestBed.configureTestingModule({
            imports: [Forbidden],
            providers: [
                provideHttpClient(),
                provideRouter([]),
                { provide: ActivatedRoute, useValue: { snapshot: { queryParamMap: convertToParamMap(query) } } }
            ]
        });
        useEnglish();
        TestBed.inject(SessionStore).user.set({ id: 1, username: 'x', role, mustChangePassword: false } as never);
        const fixture = TestBed.createComponent(Forbidden);
        fixture.detectChanges();
        return fixture.nativeElement as HTMLElement;
    }

    it('says what the page needs and names the role as the accounts screen does', () => {
        const page = render({ need: 'security-lead', page: 'gate-policies' }, 'SECURITY_CHAMPION');

        expect(page.querySelector('h1')?.textContent.trim()).toBe(english.forbidden.need_security_lead);
        expect(page.querySelector('strong')?.textContent.trim()).toBe(english.roles.security_champion);
        expect(page.textContent).toContain('/gate-policies');
    });

    it('still says the door is closed for a need nobody spelt, and a role it does not know as sent', () => {
        const page = render({ need: 'root' }, 'RISK_OWNER');

        expect(page.querySelector('h1')?.textContent.trim()).toBe(english.titles.forbidden);
        expect(page.querySelector('strong')?.textContent.trim()).toBe('RISK_OWNER');
        expect(page.textContent).not.toMatch(/forbidden\.need_|roles\./);
    });

    it('spells every need with a key both bundles hold', () => {
        expect(missingFromBundles(Object.values(NEED_KEYS))).toEqual([]);
    });
});
