import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { beforeEach, describe, expect, it } from 'vitest';
import { OwaspGridComponent } from './owasp-grid';
import { asSchema } from '@/app/core/testing/contract';

/**
 * La grille des dix, et la distinction qui la justifie.
 *
 * <p><b>« Rien trouvé » et « rien ne regarde » produisent le même vert.</b> Deux états ne peuvent
 * pas les séparer, d'où quatre — et les assertions ici portent sur les trois qui ne sont pas
 * « rien trouvé », parce que ce sont ceux qu'une grille à deux états se trompe en ayant l'air
 * juste.
 */
describe('la grille OWASP', () => {
    let fixture: ComponentFixture<OwaspGridComponent>;
    let http: HttpTestingController;

    function line(id: string, state: string, findings = 0) {
        return { id, title: id, state, findings, because: 'parce que.' };
    }

    const GRID = asSchema('Grid', {
            lines: [
                line('A01', 'NOT_COVERED'),
                line('A05', 'FINDINGS', 3),
                line('A06', 'NO_FINDING'),
                line('A07', 'NOT_MEASURED')
            ],
            covered: 3,
            withFindings: 1,
            unmeasured: 1
    });

    beforeEach(async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [OwaspGridComponent],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();

        fixture = TestBed.createComponent(OwaspGridComponent);
        http = TestBed.inject(HttpTestingController);
        fixture.detectChanges();
        http.expectOne((call) => call.url === '/api/v1/owasp/coverage').flush(GRID);
        fixture.detectChanges();
    }, 20_000);

    it('ne peint pas « aucun scanner ici » de la couleur de « rien trouvé »', () => {
        const component = fixture.componentInstance;

        expect(component.colourOf('NOT_COVERED')).not.toBe(component.colourOf('NO_FINDING'));
        expect(component.colourOf('NOT_MEASURED')).not.toBe(component.colourOf('NO_FINDING'));
    });

    it("n'affiche un compte que là où quelque chose a été compté", () => {
        // Un « 0 » en face d'une catégorie que rien ne regarde est le chiffre que toute cette
        // grille existe pour ne pas écrire.
        const cells = fixture.nativeElement.querySelectorAll('tbody tr td:nth-child(3)');
        expect([...cells].map((cell: HTMLElement) => cell.textContent!.trim()))
            .toEqual(['—', '3', '—', '—']);
    });

    it("garde l'ordre du serveur, qui est celui du standard", () => {
        expect(fixture.componentInstance.lines().map((l) => l.id)).toEqual(['A01', 'A05', 'A06', 'A07']);
    });

    it('se tait quand la grille ne peut pas être lue', async () => {
        TestBed.resetTestingModule();
        await TestBed.configureTestingModule({
            imports: [OwaspGridComponent],
            providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])]
        }).compileComponents();
        const failed = TestBed.createComponent(OwaspGridComponent);
        const client = TestBed.inject(HttpTestingController);
        failed.detectChanges();
        client.expectOne((call) => call.url === '/api/v1/owasp/coverage').error(new ProgressEvent('failed'));
        failed.detectChanges();

        // Le rapport en dessous porte ses propres erreurs ; une grille vide vaut mieux qu'un
        // bandeau rouge au-dessus de données valides.
        expect(failed.nativeElement.textContent.trim()).toBe('');
    });
});
