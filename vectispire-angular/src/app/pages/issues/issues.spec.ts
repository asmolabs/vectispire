import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ActivatedRoute, convertToParamMap, provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { I18nService } from '../../core/i18n/i18n.service';
import { SessionStore } from '@/app/core/session.store';
import { Issues } from './issues';
import { asSchema } from '@/app/core/testing/contract';

/**
 * The backlog.
 *
 * <p>The one screen with real volume, and therefore the one where paging is not decoration: it
 * asks the server for a window and says which window it is showing. A page that silently
 * displayed the first fifty of two hundred would read as a backlog of fifty.
 */
describe('the issue backlog', () => {
    let fixture: ComponentFixture<Issues>;
    let http: HttpTestingController;

    function issue(id: number, identifier: string): Record<string, unknown> {
        return asSchema('BacklogEntry', {
            id,
            repoId: 5,
            containerId: null,
            targetKind: 'repository',
            targetName: 'Arm Libs Spring',
            type: 'vulnerability',
            identifier,
            severity: 'high',
            packageName: 'openssl',
            packageVersion: '3.0.1',
            state: 'open',
            firstSeenAt: '2026-03-03T08:00:00Z',
            lastSeenAt: '2026-08-21T05:03:00Z',
            timesSeen: 1,
            triageStatus: 'under_review',
            isKev: false
        });
    }

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [Issues],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(Issues);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();

        // The filters offer target names, so the page fetches both target kinds.
        http.expectOne((call) => call.url === '/api/v1/repositories').flush([]);
        http.expectOne((call) => call.url === '/api/v1/containers').flush([]);

        // Et la disponibilité du modèle, qui décide si le bouton d'explication existe. Un modèle
        // configuré par défaut dans ces essais : l'absence a son propre cas.
        http.expectOne((call) => call.url === '/api/v1/ai-advisor/status')
            .flush({ enabled: true, selectedModel: 'llama3', availableModels: ['llama3'] });
    }, 20_000);

    function firstPage(total: number): void {
        http.expectOne((call) => call.url === '/api/v1/issues')
            .flush({ items: [issue(1, 'CVE-2026-1234')], total, limit: 50, offset: 0 });
        fixture.detectChanges();
    }

    it('says which window of the backlog it is showing', () => {
        firstPage(228);

        // Without this, fifty rows out of two hundred read as a backlog of fifty.
        expect(fixture.componentInstance.pageLabel()).toBe('1–50 of 228');
        expect(fixture.nativeElement.textContent).toContain('1–50 of 228');
    });

    it('asks the server for the next window rather than slicing what it holds', () => {
        firstPage(228);

        fixture.componentInstance.reload(50);
        const next = http.expectOne((call) => call.url === '/api/v1/issues');
        expect(next.request.urlWithParams).toContain('offset=50');
        next.flush({ items: [issue(2, 'CVE-2026-9999')], total: 228, limit: 50, offset: 50 });
        fixture.detectChanges();

        expect(fixture.componentInstance.pageLabel()).toBe('51–100 of 228');
    });

    it('links each row to its detail', () => {
        firstPage(1);

        const link = fixture.nativeElement.querySelector('a[href="/issues/1"]');
        expect(link).not.toBeNull();
        expect(link.textContent).toContain('CVE-2026-1234');
    });

    it('says "no result" rather than showing an empty frame', () => {
        http.expectOne((call) => call.url === '/api/v1/issues')
            .flush({ items: [], total: 0, limit: 50, offset: 0 });
        fixture.detectChanges();

        expect(fixture.componentInstance.pageLabel()).toBe('No result');
    });

    it('stops loading when the request is refused', () => {
        http.expectOne((call) => call.url === '/api/v1/issues')
            .flush(null, { status: 500, statusText: 'Server Error' });
        fixture.detectChanges();

        // A spinner that never stops is how a failed page passes for a slow one.
        expect(fixture.componentInstance.loading()).toBe(false);
    });

    /**
     * The four filters the API has always accepted and this screen offered no way to set.
     *
     * What is asserted is the parameter, not the field: a control bound to a property nobody
     * puts in the request is a switch that moves and does nothing, which is the defect these
     * four were already an instance of.
     */
    it('sends each switch to the server as the parameter the API reads', () => {
        firstPage(1);

        const component = fixture.componentInstance;
        component.onlyKev = true;
        component.overdue = true;
        component.onlyDirect = true;
        component.triageFilter = 'affected';
        component.reload(0);

        const url = http.expectOne((call) => call.url === '/api/v1/issues').request.urlWithParams;
        expect(url).toContain('is_kev=true');
        expect(url).toContain('overdue=true');
        expect(url).toContain('only_direct=true');
        expect(url).toContain('triage_status=affected');
    });

    it('reloads with is_kev when the switch on screen is thrown', async () => {
        firstPage(1);

        // Through the DOM and not through the field: a control wired to nothing looks identical
        // from the component's side, and that is precisely the state this screen was in.
        fixture.nativeElement.querySelector('#filter-kev').click();
        await fixture.whenStable();
        fixture.detectChanges();

        expect(fixture.componentInstance.onlyKev).toBe(true);
        expect(http.expectOne((call) => call.url === '/api/v1/issues').request.urlWithParams).toContain('is_kev=true');
    });

    it('leaves the three switches out of the request while they are off', () => {
        // `only_direct=false` says nothing the server does not already assume, and a URL full of
        // false filters is a URL nobody can read back to see what was actually asked for.
        const url = http.expectOne((call) => call.url === '/api/v1/issues').request.urlWithParams;
        expect(url).not.toContain('is_kev');
        expect(url).not.toContain('overdue');
        expect(url).not.toContain('only_direct');
        expect(url).not.toContain('triage_status');
    });

    it("n'offre pas le conseiller quand aucun modèle n'est configuré", async () => {
        // **Une option absente doit être absente, pas présente et refusante.** Le bouton était
        // offert à tout le monde ; sans modèle il ouvrait une fenêtre sur un service injoignable.
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Issues],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        const offline = TestBed.createComponent(Issues);
        const calls = TestBed.inject(HttpTestingController);
        offline.detectChanges();
        calls.expectOne((call) => call.url === '/api/v1/repositories').flush([]);
        calls.expectOne((call) => call.url === '/api/v1/containers').flush([]);
        calls.expectOne((call) => call.url === '/api/v1/ai-advisor/status')
            .flush({ enabled: false, selectedModel: null, availableModels: [] });
        calls.expectOne((call) => call.url === '/api/v1/issues')
            .flush({ items: [issue(1, 'CVE-2026-1234')], total: 1, limit: 50, offset: 0 });
        offline.detectChanges();

        expect(offline.componentInstance.aiEnabled()).toBe(false);
    });

    it("cache le conseiller aussi quand la disponibilité elle-même ne répond pas", async () => {
        // Un défaut de lecture n'est pas un accès : promettre un bouton dont on ne sait pas s'il
        // marchera est exactement ce que ce garde-fou empêche.
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Issues],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        const broken = TestBed.createComponent(Issues);
        const calls = TestBed.inject(HttpTestingController);
        broken.detectChanges();
        calls.expectOne((call) => call.url === '/api/v1/repositories').flush([]);
        calls.expectOne((call) => call.url === '/api/v1/containers').flush([]);
        calls.expectOne((call) => call.url === '/api/v1/ai-advisor/status')
            .error(new ProgressEvent('failed'));
        calls.expectOne((call) => call.url === '/api/v1/issues')
            .flush({ items: [], total: 0, limit: 50, offset: 0 });
        broken.detectChanges();

        expect(broken.componentInstance.aiEnabled()).toBe(false);
    });

    it("dit que le modèle n'a pas répondu, au lieu d'ouvrir une fenêtre vide", () => {
        firstPage(1);

        const page = fixture.componentInstance;
        page.openAiAdvisor({ id: 1 } as never);
        http.expectOne((call) => call.url === '/api/v1/ai-advisor/explain/issue/1')
            .error(new ProgressEvent('failed'));
        fixture.detectChanges();

        // **L'erreur était posée dans un signal que le gabarit n'utilisait pas** : la fenêtre
        // s'ouvrait, le tourniquet s'arrêtait, et il ne restait rien. Le message promettait par
        // ailleurs une « génération locale de secours » que ce code n'a jamais écrite.
        expect(page.aiAdviceError()).toBeTruthy();
        expect(page.aiAdviceError()).not.toContain('secours');
        expect(page.aiAdviceLoading()).toBe(false);
    });
});

/**
 * The same decision on many issues.
 *
 * One CVE appears in forty repositories, and "not reachable in our configuration" is one judgement
 * about one context, not forty. What is asserted here is the two things that make the feature safe
 * rather than convenient: that the ids the user ticked are the ids the request carries, and that a
 * refusal is reported as a refusal of the whole batch — the server writes nothing when one id is
 * invisible, and a message that leaves a partial write plausible makes the reader stop instead of
 * retrying.
 */
describe('triaging a selection', () => {
    let fixture: ComponentFixture<Issues>;
    let http: HttpTestingController;

    function row(id: number): Record<string, unknown> {
        return asSchema('BacklogEntry', {
            id,
            targetKind: 'repository',
            type: 'vulnerability',
            identifier: `CVE-2026-${id}`,
            severity: 'high',
            state: 'open',
            firstSeenAt: '2026-03-03T08:00:00Z',
            lastSeenAt: '2026-08-21T05:03:00Z',
            timesSeen: 1,
            triageStatus: 'under_review',
            isKev: false
        });
    }

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [Issues],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(Issues);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        for (const request of http.match(() => true)) {
            request.flush(
                request.request.url.endsWith('/issues')
                    ? { items: [row(11), row(22), row(33)], total: 3, limit: 50, offset: 0 }
                    : []
            );
        }
        fixture.detectChanges();
    }, 20_000);

    it('sends the ticked issues as `ids`, once', () => {
        const component = fixture.componentInstance;
        component.selected.set([component.issues()[0], component.issues()[2]]);
        component.openBulkTriage();
        component.triageStatus = 'not_affected';
        component.triageJustification = 'vulnerable_code_not_in_execute_path';
        component.submitTriage();

        const call = http.expectOne('/api/v1/issues/triage');
        expect(call.request.method).toBe('POST');
        // The ids, and not a request per row: forty requests would be forty audit entries and
        // thirty-nine chances of a half-applied decision.
        expect(call.request.body.ids).toEqual([11, 33]);
        expect(call.request.body.status).toBe('not_affected');
        expect(call.request.body.justification).toBe('vulnerable_code_not_in_execute_path');
    });

    it('reloads and drops the selection once the batch is written', () => {
        const component = fixture.componentInstance;
        component.selected.set([component.issues()[0]]);
        component.openBulkTriage();
        component.submitTriage();
        http.expectOne('/api/v1/issues/triage').flush([row(11)]);

        // A selection outliving its rows is a decision about issues nobody is looking at any more.
        expect(component.selected()).toEqual([]);
        http.expectOne((call) => call.url === '/api/v1/issues').flush({ items: [], total: 0, limit: 50, offset: 0 });
    });

    it('drops the selection when the filters change under it', () => {
        const component = fixture.componentInstance;
        component.selected.set([component.issues()[0], component.issues()[1]]);
        component.severity = 'critical';
        component.reload(0);

        expect(component.selected()).toEqual([]);
        http.expectOne((call) => call.url === '/api/v1/issues').flush({ items: [], total: 0, limit: 50, offset: 0 });
    });

    it('says the whole batch was refused when one issue is not visible', () => {
        const component = fixture.componentInstance;
        component.selected.set([component.issues()[0], component.issues()[1]]);
        component.openBulkTriage();
        component.submitTriage();
        // The server's own sentence for this case, which says nothing about the other rows.
        http.expectOne('/api/v1/issues/triage').flush({ detail: 'Issue not found.' }, { status: 404, statusText: 'Not Found' });
        fixture.detectChanges();

        const message = component.triageError();
        expect(message).toContain('None of the 2 selected issues were triaged');
        expect(message).toContain('refused as a whole');
        // And nothing was reloaded, so the ticks are still there to select again from.
        http.expectNone((call) => call.url === '/api/v1/issues');
    });

    it('still shows the server\'s explanation when the refusal is not a visibility one', () => {
        const component = fixture.componentInstance;
        component.selected.set([component.issues()[0]]);
        component.openBulkTriage();
        component.submitTriage();
        http.expectOne('/api/v1/issues/triage')
            .flush({ detail: 'Too many issues at once: 900, the limit is 500.' }, { status: 400, statusText: 'Bad Request' });

        // The sentence the server took care to write, kept — with the batch's fate stated first.
        expect(component.triageError()).toContain('Too many issues at once');
        expect(component.triageError()).toContain('None of the 1 selected issues were triaged');
    });

    /**
     * Through the DOM, because a checkbox column bound to nothing looks identical from the
     * component's side — and "select all, decide once" is the whole flow this feature exists for.
     */
    it('ticks the page from the header checkbox and sends what it ticked', async () => {
        const header = fixture.nativeElement.querySelector('p-tableheadercheckbox input[type="checkbox"]');
        expect(header).not.toBeNull();
        header.click();
        await fixture.whenStable();
        fixture.detectChanges();

        expect(fixture.componentInstance.selected().map((issue) => issue.id)).toEqual([11, 22, 33]);

        fixture.componentInstance.openBulkTriage();
        fixture.componentInstance.submitTriage();
        expect(http.expectOne('/api/v1/issues/triage').request.body.ids).toEqual([11, 22, 33]);
    });

    it('offers the action only once something is ticked, and says what it will do', () => {
        const component = fixture.componentInstance;
        const session = TestBed.inject(SessionStore);
        const as = (role: string) =>
            session.user.set({ id: 1, username: 'x', role, mustChangePassword: false } as never);

        // **Un dictionnaire de test, parce que le libellé passe maintenant par l'i18n.** Il
        // était écrit en dur, en français, dans une application bilingue — trois fois. Ce que ce
        // cas éprouve reste le même : que la promesse du bouton change avec le rôle. Que la
        // traduction existe pour de vrai est le travail de `check-i18n-keys.mjs`.
        TestBed.inject(I18nService).translations.set({
            issues: { triage_action: 'Trier', triage_request: 'Envoyer pour approbation' }
        });

        as('CISO');
        expect(fixture.nativeElement.textContent).not.toContain('(2)');

        component.selected.set([component.issues()[0], component.issues()[1]]);
        fixture.detectChanges();

        // The count is on the button because "Save" looks the same for one row and for forty.
        expect(fixture.nativeElement.textContent).toContain('Trier (2)');

        // **Le libellé est la promesse.** Un compte sans droit d'approbation peut trier, mais sa
        // décision part en file : l'écran l'annonçait « Triage » comme aux autres, et il le
        // découvrait après coup en voyant le tag passer en « En attente d'approbation ».
        as('USER');
        fixture.detectChanges();
        expect(fixture.nativeElement.textContent).toContain('Envoyer pour approbation (2)');
        expect(fixture.nativeElement.textContent).not.toContain('Trier (2)');

        // Un auditeur constate et ne décide pas : le contrôle est absent, pas grisé.
        //
        // **Asserté sur la clé et non sur la phrase.** Le libellé était en dur en français dans un
        // gabarit par ailleurs anglais ; il passe maintenant par les bundles, et une assertion sur
        // le texte traduit dirait quelle langue la suite a chargée plutôt que ce que l'écran
        // montre.
        as('AUDITOR');
        fixture.detectChanges();
        expect(fixture.nativeElement.textContent).not.toContain('(2)');
        expect(fixture.nativeElement.textContent).toContain('issues.reads_only');
    });
});

/**
 * The dashboard's links, and the controls they have to light up.
 *
 * The filter applied while every control on screen read "all" — that was the state this screen
 * shipped in, and the reason it was wrong is not that the list was unfiltered but that the screen
 * contradicted the URL that opened it: a short backlog with no filter showing reads as a backlog
 * that lost most of its rows.
 */
describe('the backlog opened from a dashboard link', () => {
    async function open(queryParams: Record<string, string>): Promise<ComponentFixture<Issues>> {
        TestBed.resetTestingModule();
        TestBed.configureTestingModule({
            imports: [Issues],
            providers: [
                provideHttpClient(),
                provideHttpClientTesting(),
                provideRouter([]),
                { provide: ActivatedRoute, useValue: { snapshot: { queryParamMap: convertToParamMap(queryParams) } } }
            ]
        });

        const fixture = TestBed.createComponent(Issues);
        const http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        for (const request of http.match(() => true)) {
            request.flush(request.request.url.endsWith('/issues') ? { items: [], total: 0, limit: 50, offset: 0 } : []);
        }
        fixture.detectChanges();
        // `ngModel` writes the initial value into the control on a microtask, so a switch asserted
        // synchronously reads as off however right the field is — and that would pass a screen
        // whose controls never light up.
        await fixture.whenStable();
        fixture.detectChanges();
        return fixture;
    }

    it('applies is_kev and shows the control as active', async () => {
        const fixture = await open({ is_kev: 'true' });

        expect(fixture.componentInstance.onlyKev).toBe(true);
        const control = fixture.nativeElement.querySelector('#filter-kev');
        expect(control).not.toBeNull();
        expect(control.checked).toBe(true);

        // And it is still the filter the server was asked for, not only the box that is ticked.
        const http = TestBed.inject(HttpTestingController);
        fixture.componentInstance.reload(0);
        expect(http.expectOne((call) => call.url === '/api/v1/issues').request.urlWithParams).toContain('is_kev=true');
    });

    it('does the same for the deadline figure', async () => {
        const fixture = await open({ overdue: 'true' });

        expect(fixture.componentInstance.overdue).toBe(true);
        expect(fixture.nativeElement.querySelector('#filter-overdue').checked).toBe(true);
    });

    it('shows nothing as active when the link carries no filter', async () => {
        // The other half of the same contract: a control lit up without a filter behind it would
        // be the same contradiction the other way round.
        const fixture = await open({});

        expect(fixture.componentInstance.onlyKev).toBe(false);
        expect(fixture.nativeElement.querySelector('#filter-kev').checked).toBe(false);
    });
});
