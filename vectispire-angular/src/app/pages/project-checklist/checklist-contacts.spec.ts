import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { CONTACT_CANDIDATES, CONTACTS, PROJECT_ID } from '@/app/core/testing/checklists.fixtures';
import { asSchema } from '@/app/core/testing/contract';
import { useEnglish } from '@/app/core/testing/english';
import english from '../../../../public/i18n/en.json';
import french from '../../../../public/i18n/fr.json';
import { ChecklistContactsPanel, WARNING_KEYS } from './checklist-contacts';

/**
 * Who each checklist profile is linked to (decision 0044), through the DOM: every profile with its lines
 * to fill in, why one would remind nobody, a writer's choice sent as the profile's key and the account's
 * id — and a reader shown the same list with nothing to change.
 */
describe('the checklist contacts panel', () => {
    let fixture: ComponentFixture<ChecklistContactsPanel>;
    let http: HttpTestingController;

    const BASE = `/api/v1/projects/${PROJECT_ID}/checklists/contacts`;

    afterEach(() => {
        try {
            http?.verify();
        } finally {
            TestBed.resetTestingModule();
        }
    });

    async function start(writes: boolean, edition = 5): Promise<void> {
        await TestBed.configureTestingModule({
            imports: [ChecklistContactsPanel],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting()]
        }).compileComponents();
        useEnglish();
        fixture = TestBed.createComponent(ChecklistContactsPanel);
        fixture.componentRef.setInput('projectId', PROJECT_ID);
        fixture.componentRef.setInput('writes', writes);
        fixture.componentRef.setInput('edition', edition);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne({ method: 'GET', url: BASE }).flush(CONTACTS);
        if (writes) http.expectOne({ method: 'GET', url: `${BASE}/candidates` }).flush(CONTACT_CANDIDATES);
        fixture.detectChanges();
    }

    const dom = () => fixture.nativeElement as HTMLElement;
    const rows = () => Array.from(dom().querySelectorAll('[data-testid="contact-row"]'));
    const cell = (row: Element, id: string) =>
        row.querySelector(`[data-testid="${id}"]`)?.textContent?.replace(/\s+/g, ' ').trim() ?? '';

    it('names every warning in both languages — the i18n check cannot see them', () => {
        const lookup = (bundle: unknown, key: string) =>
            key
                .split('.')
                .reduce<unknown>((node, part) => (node as Record<string, unknown> | undefined)?.[part], bundle);
        for (const key of Object.values(WARNING_KEYS)) {
            expect(typeof lookup(english, key), `${key} in en.json`).toBe('string');
            expect(typeof lookup(french, key), `${key} in fr.json`).toBe('string');
        }
    });

    it('shows a reader each profile, its lines to fill in, who it is linked to and why one reminds nobody', async () => {
        await start(false);

        expect(rows().map((row) => cell(row, 'contact-profile'))).toEqual(['PO', 'Arch', 'BA']);
        expect(rows().map((row) => cell(row, 'contact-open-lines'))).toEqual(['2', '1', '0']);
        expect(rows().map((row) => cell(row, 'contact-account'))).toEqual(['Product owner', 'Account 42', 'Nobody']);
        expect(cell(rows()[0], 'contact-warning')).toBe('');
        expect(cell(rows()[1], 'contact-warning')).toBe('No e-mail address');
        // Linked to nobody, or to an account that would not be reminded: the CISOs are.
        expect(rows().map((row) => cell(row, 'contact-ciso'))).toEqual([
            '',
            'Reminded to the CISOs',
            'Reminded to the CISOs'
        ]);
        expect(dom().querySelector('[data-testid="contact-select"]')).toBeNull();
    });

    it('says when the contact column names no profile', async () => {
        await TestBed.configureTestingModule({
            imports: [ChecklistContactsPanel],
            providers: [provideHttpClient(withXhr()), provideHttpClientTesting()]
        }).compileComponents();
        useEnglish();
        fixture = TestBed.createComponent(ChecklistContactsPanel);
        fixture.componentRef.setInput('projectId', PROJECT_ID);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne({ method: 'GET', url: BASE }).flush(
            asSchema('ChecklistContactsView', { ...CONTACTS, profiles: [] })
        );
        fixture.detectChanges();

        expect(dom().querySelector('[data-testid="contacts-none"]')?.textContent?.trim()).toBe(
            "The checklist's contact column names no profile."
        );
    });

    it('offers a writer the candidates, each by name or by id, and keeps a linked account no longer among them', async () => {
        await start(true);
        const panel = fixture.componentInstance;

        expect(panel.options()['PO'].map((option) => option.label)).toEqual(['Product owner', 'Account 42', 'Analyst']);
        expect(rows()).toHaveLength(3);
        expect(dom().querySelectorAll('[data-testid="contact-select"]')).toHaveLength(3);

        panel.contacts.set(
            asSchema('ChecklistContactsView', {
                ...CONTACTS,
                profiles: [{ ...CONTACTS.profiles[0], accountId: 99, accountName: null, warning: 'account_inactive' }]
            })
        );
        expect(panel.options()['PO'].map((option) => option.value)).toEqual([41, 42, 43, 99]);
        expect(panel.options()['PO'].at(-1)?.label).toBe('Account 99');
    });

    it("links a profile by its key to the account chosen, and shows the server's list back", async () => {
        await start(true);
        const linked = asSchema('ChecklistContactsView', {
            ...CONTACTS,
            profiles: [{ ...CONTACTS.profiles[2], accountId: 43, accountName: 'Analyst' }]
        });

        fixture.componentInstance.choose(CONTACTS.profiles[2], 43);
        const request = http.expectOne({ method: 'PUT', url: `${BASE}/BA` });
        expect(asSchema('ChecklistContactRequest', request.request.body)).toEqual({ accountId: 43 });
        request.flush(linked);
        fixture.detectChanges();

        expect(fixture.componentInstance.contacts()).toEqual(linked);
    });

    it('unlinks a profile whose choice is cleared, and sends nothing when the choice did not change', async () => {
        await start(true);

        fixture.componentInstance.choose(CONTACTS.profiles[0], 41);
        fixture.componentInstance.choose(CONTACTS.profiles[0], null);
        http.expectOne({ method: 'DELETE', url: `${BASE}/PO` }).flush(CONTACTS);
    });

    it('says a refused link in the server words, and reads again what the server holds', async () => {
        await start(true);

        fixture.componentInstance.choose(CONTACTS.profiles[2], 42);
        http.expectOne({ method: 'PUT', url: `${BASE}/BA` }).flush(
            { title: 'Bad Request', status: 400, detail: 'Account 42 cannot be linked.' },
            { status: 400, statusText: 'Bad Request' }
        );
        http.expectOne({ method: 'GET', url: BASE }).flush(CONTACTS);
        fixture.detectChanges();

        expect(dom().querySelector('[data-testid="contacts-error"]')?.textContent?.trim()).toBe(
            'Account 42 cannot be linked.'
        );
    });

    it('reads the list again when the edition on screen moves, the lines to fill in having changed', async () => {
        await start(false, 5);

        fixture.componentRef.setInput('edition', 6);
        fixture.detectChanges();

        http.expectOne({ method: 'GET', url: BASE }).flush(CONTACTS);
    });
});
