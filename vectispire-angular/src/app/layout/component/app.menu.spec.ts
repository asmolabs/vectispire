import { TestBed, ComponentFixture } from '@angular/core/testing';
import { describe, it, expect } from 'vitest';
import { provideRouter } from '@angular/router';
import { AppMenu } from './app.menu';
import { SessionStore } from '@/app/core/session.store';
import { useEnglish } from '@/app/core/testing/english';

/**
 * Where the sidebar files an entry, and for whom.
 *
 * <p>Read through the rendered links grouped under their section title, not through the component's
 * model: what a reader meets is a link under a heading, and a model that is right while the
 * template drops a level would pass a test of the model.
 */
describe('the sidebar', () => {
    async function render(role: string): Promise<ComponentFixture<AppMenu>> {
        await TestBed.configureTestingModule({
            imports: [AppMenu],
            providers: [provideRouter([])]
        }).compileComponents();
        useEnglish();
        TestBed.inject(SessionStore).open('a-token', { username: 'someone', role } as never);
        const fixture = TestBed.createComponent(AppMenu);
        fixture.detectChanges();
        return fixture;
    }

    /** Section title → the paths its links lead to. */
    function sections(fixture: ComponentFixture<AppMenu>): Map<string, string[]> {
        const out = new Map<string, string[]>();
        const roots = (fixture.nativeElement as HTMLElement).querySelectorAll('li.layout-root-menuitem');
        for (const root of Array.from(roots)) {
            const title = root.querySelector('.layout-menuitem-root-text')?.textContent?.trim() ?? '';
            const links = Array.from(root.querySelectorAll('ul a[href]')).map((a) => a.getAttribute('href') ?? '');
            out.set(title, links);
        }
        return out;
    }

    /** Every section holding a link to the path, so that a duplicate shows up as two. */
    function holding(fixture: ComponentFixture<AppMenu>, path: string): string[] {
        return [...sections(fixture)].filter(([, links]) => links.includes(path)).map(([title]) => title);
    }

    // The product owner's decision: both entries are administration entries. Every role that sees the
    // Administration section finds them there and nowhere else.
    for (const role of ['SUPERUSER', 'ADMIN', 'CISO', 'AUDITOR']) {
        it(`files the plugins and the audit log under Administration only, for ${role}`, async () => {
            const fixture = await render(role);

            expect(holding(fixture, '/plugins')).toEqual(['Administration']);
            expect(holding(fixture, '/audit-log')).toEqual(['Administration']);
            // Governance reading, as `GET /api/v1/report-plugins` is (decision 0035 §4).
            expect(holding(fixture, '/report-plugins')).toEqual(['Administration']);
        });
    }

    // Discovering and importing repositories creates targets: an administrator's, like the routes behind it.
    for (const role of ['SUPERUSER', 'ADMIN']) {
        it(`files the forge connections under Administration for ${role}`, async () => {
            const fixture = await render(role);
            expect(holding(fixture, '/forge-connections')).toEqual(['Administration']);
        });
    }

    for (const role of ['CISO', 'AUDITOR', 'SECURITY_CHAMPION', 'USER']) {
        it(`offers ${role} no link to the forge connections`, async () => {
            const fixture = await render(role);
            expect(holding(fixture, '/forge-connections')).toEqual([]);
        });
    }

    // **The accepted cost.** These accounts lose the menu link — not the page, whose route stays open
    // to them — and are offered no Administration section to find it in.
    for (const role of ['SECURITY_CHAMPION', 'USER']) {
        it(`offers ${role} neither entry, and no Administration section`, async () => {
            const fixture = await render(role);

            expect(holding(fixture, '/plugins')).toEqual([]);
            expect(holding(fixture, '/audit-log')).toEqual([]);
            expect(holding(fixture, '/report-plugins')).toEqual([]);
            expect(sections(fixture).has('Administration')).toBe(false);
            // The positive control: the sidebar did render for this account.
            expect(holding(fixture, '/issues')).toEqual(['Security']);
        });
    }
});
