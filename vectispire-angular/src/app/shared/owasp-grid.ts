import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { SelectModule } from '@openng/optimus-ui/select';
import { ApiService } from '@/app/core/api.service';
import { messageOf } from '@/app/core/api-error';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import { SessionStore } from '@/app/core/session.store';
import type {
    Applicability,
    EvidenceSource,
    Implementation,
    OwaspGrid,
    OwaspCoverageLine,
    OwaspState
} from '@/app/core/api.models';

/**
 * Les dix catégories, répondues par règle plutôt que par un modèle.
 *
 * <p><b>Quatre états et non deux, parce que deux mentiraient.</b> Une catégorie sans constat et
 * une catégorie que rien ne regarde produisent le même vert. Sept des dix ne sont couvertes par
 * aucun scanner ici, et le dire est la chose la plus utile que cette grille fasse.
 *
 * <p>Posée au-dessus du rapport écrit par le modèle, pas à sa place : le rapport produit la prose
 * qu'aucun moteur de règles n'écrit, et il ne sert pas de preuve. Les lire dans cet ordre est
 * l'ordre dans lequel ils valent quelque chose.
 */
@Component({
    selector: 'zs-owasp-grid',
    standalone: true,
    imports: [
        CommonModule,
        FormsModule,
        ButtonModule,
        DialogModule,
        InputTextModule,
        MessageModule,
        SelectModule,
        TranslatePipe
    ],
    templateUrl: './owasp-grid.html'
})
export class OwaspGridComponent {
    private readonly api = inject(ApiService);
    private readonly session = inject(SessionStore);
    readonly i18n = inject(I18nService);

    readonly grid = signal<OwaspGrid | null>(null);

    /**
     * La déclaration en cours d'écriture, et les champs qu'elle porte.
     *
     * <p><b>Le même formulaire que la SoA, parce que c'est la même chose.</b> Une catégorie
     * qu'aucun scanner d'ici ne mesure n'a que la déclaration pour porter une revue : qui
     * l'affirme, avec quelle preuve, et quand cela se revoit. Écrire un second modèle de saisie
     * pour la même table donnerait deux formulaires qui divergeraient sur la première règle ajoutée.
     */
    readonly editing = signal<OwaspCoverageLine | null>(null);
    readonly busy = signal(false);
    readonly error = signal<string | null>(null);

    applicability: Applicability = 'APPLICABLE';
    implementation: Implementation = 'IMPLEMENTED';
    evidenceSource: EvidenceSource = 'EXTERNAL';
    justification = '';
    externalEvidence = '';
    owner = '';
    reviewDue = '';

    readonly canDeclare = computed(() => this.session.isSecurityLead());

    /**
     * Déclarable là où la mesure s'arrête, et nulle part ailleurs.
     *
     * <p>Une catégorie qu'un scanner d'ici sait lire n'a pas besoin d'être affirmée : elle est
     * mesurée, et une déclaration posée à côté d'une mesure est une seconde source qui finira par
     * la contredire. Le bouton n'apparaît donc que sur les cases que rien ne mesure.
     */
    declarable(line: OwaspCoverageLine): boolean {
        return this.canDeclare() && line.state === 'NOT_COVERED';
    }

    openDeclare(line: OwaspCoverageLine): void {
        const existing = line.declaration;
        this.applicability = existing?.applicability ?? 'APPLICABLE';
        this.implementation = existing?.implementation ?? 'IMPLEMENTED';
        // `EXTERNAL` par défaut, et non `VECTISPIRE` : la catégorie est précisément celle que ce
        // produit ne mesure pas, donc sa preuve vit ailleurs par construction.
        this.evidenceSource = existing?.evidenceSource ?? 'EXTERNAL';
        this.justification = existing?.justification ?? '';
        this.externalEvidence = existing?.externalEvidence ?? '';
        this.owner = existing?.owner ?? '';
        this.reviewDue = existing?.reviewDueAt ? existing.reviewDueAt.slice(0, 10) : '';
        this.error.set(null);
        this.editing.set(line);
    }

    /**
     * Les deux refus du serveur, dits ici par un bouton éteint plutôt qu'après la frappe.
     *
     * <p>Ce sont les mêmes que sous ISO 27001, et ils ne parlent d'aucun référentiel : une
     * exclusion sans motif est une ligne qui sort du périmètre sans dire pourquoi, et une preuve
     * déclarée ailleurs sans dire où est la même omission à un autre endroit.
     */
    incomplete(): boolean {
        if (this.applicability === 'EXCLUDED') {
            return !this.justification.trim();
        }
        return this.evidenceSource !== 'VECTISPIRE' && !this.externalEvidence.trim();
    }

    submit(): void {
        const line = this.editing();
        if (!line || this.incomplete()) {
            return;
        }
        this.busy.set(true);
        this.error.set(null);

        this.api
            .declareOwaspCategory(line.id, {
                applicability: this.applicability,
                justification: this.justification.trim() || null,
                implementation: this.applicability === 'EXCLUDED' ? null : this.implementation,
                evidence_source: this.evidenceSource,
                external_evidence: this.externalEvidence.trim() || null,
                owner: this.owner.trim() || null,
                review_due_at: this.reviewDue ? new Date(this.reviewDue).toISOString() : null
            })
            .subscribe({
                next: () => {
                    this.editing.set(null);
                    this.busy.set(false);
                    // Rechargée plutôt que fusionnée sur place : la grille porte aussi des
                    // compteurs, et les recalculer ici en ferait une seconde implémentation.
                    this.reload();
                },
                error: (failure) => {
                    this.busy.set(false);
                    this.error.set(messageOf(failure, this.i18n.t('owasp_grid.declare_failed')));
                }
            });
    }

    private reload(): void {
        this.api.owaspCoverage().subscribe({
            next: (data) => this.grid.set(data),
            error: () => this.grid.set(null)
        });
    }

    /**
     * L'ordre du standard, toujours.
     *
     * <p>Trier par gravité mettrait les catégories actionnables en haut, ce qui est le bon réflexe
     * d'un tableau de bord et le mauvais ici : un questionnaire d'audit pose A01 puis A02, et une
     * grille réordonnée oblige à chercher chaque ligne.
     */
    readonly lines = computed<OwaspCoverageLine[]>(() => this.grid()?.lines ?? []);

    constructor() {
        this.reload();
    }

    /**
     * Un zéro qui va bien se peint en vert, pas en alarme.
     *
     * <p>« 0 couverte mais non mesurée » en orange était une bonne nouvelle affichée comme un
     * problème. Un tableau où les bonnes nouvelles sont oranges apprend à ignorer l'orange.
     */
    alarming(count: number, tone: 'danger' | 'warn'): string {
        if (count === 0) {
            return 'text-emerald-700';
        }
        return tone === 'danger' ? 'text-red-700' : 'text-orange-700';
    }

    /** Le gris de « non couvert » n'est pas le vert de « rien trouvé », et c'est tout le sujet. */
    colourOf(state: OwaspState): string {
        switch (state) {
            case 'FINDINGS':
                return 'text-red-700';
            case 'NOT_MEASURED':
                return 'text-orange-700';
            case 'NOT_COVERED':
                return 'text-muted-color';
            default:
                return 'text-emerald-700';
        }
    }
}
