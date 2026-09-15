import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ButtonModule } from '@openng/optimus-ui/button';
import { DialogModule } from '@openng/optimus-ui/dialog';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '@/app/core/api-error';
import { ApiService } from '@/app/core/api.service';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { SessionStore } from '@/app/core/session.store';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import type { Applicability, Divergence, EvidenceSource, Implementation, SoaLine, SoaStatement } from '@/app/core/api.models';

/**
 * La déclaration d'applicabilité : ce qu'on affirme, confronté à ce qui est mesuré.
 *
 * **L'artefact utile n'est ni la déclaration ni la mesure, c'est leur désaccord.** Un contrôle
 * déclaré en place que le parc mesure non conforme est exactement ce qu'un évaluateur relève,
 * et aucune des deux moitiés du produit ne pouvait le voir seule. L'écran trie donc par
 * gravité d'écart et non par identifiant de contrôle.
 *
 * **Une instance neuve affiche vingt-quatre constats et c'est correct.** La clause 6.1.3 d
 * demande *chaque* contrôle traité ; le silence est le manque. Trier les non déclarés en bas
 * aurait fait passer le document vide pour un document propre.
 *
 * **`evidence_source` est le champ qui empêche l'écran de mentir.** Vectispire mesure une
 * tranche de chaque contrôle ; une ligne dont la preuve vit ailleurs est affichée comme non
 * mesurée ici, ce qui est un renvoi vers l'autre document et pas un constat.
 */
@Component({
    selector: 'zs-soa',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, DialogModule, InputTextModule, MessageModule, TagModule, TranslatePipe],
    templateUrl: './soa.html'
})
export class Soa {
    private readonly api = inject(ApiService);
    private readonly i18n = inject(I18nService);
    private readonly session = inject(SessionStore);

    readonly statements = signal<SoaStatement[]>([]);
    readonly framework = signal<string | null>(null);
    readonly error = signal<string | null>(null);
    readonly busy = signal(false);

    readonly editing = signal<SoaLine | null>(null);
    applicability: Applicability = 'APPLICABLE';
    implementation: Implementation = 'IMPLEMENTED';
    evidenceSource: EvidenceSource = 'VECTISPIRE';
    justification = '';
    externalEvidence = '';
    owner = '';
    reviewDue = '';

    readonly canDeclare = computed(() => this.session.isSecurityLead());

    /**
     * L'écran ouvre sur ISO 27001, pas sur le premier cadre de l'énumération.
     *
     * <p>Il ouvrait sur NIS 2 parce que c'est la première valeur déclarée — sur un écran dont le
     * sous-titre parle de la clause 6.1.3 d d'ISO 27001. Le défaut de l'énumération n'est pas un
     * choix d'écran.
     */
    private static readonly OPENS_ON = 'ISO_27001';

    readonly current = computed<SoaStatement | null>(() => {
        const all = this.statements();
        const chosen = this.framework();
        return all.find((statement) => statement.framework === chosen)
            ?? all.find((statement) => statement.framework === Soa.OPENS_ON)
            ?? all[0]
            ?? null;
    });

    /**
     * Les écarts d'abord, du plus grave au moins grave, puis les lignes qui vont bien.
     *
     * Le serveur rend les lignes dans l'ordre du cadre, qui est celui du standard. C'est le bon
     * ordre pour imprimer le document et le mauvais pour l'ouvrir : la question posée ici est
     * « qu'est-ce qui ne va pas », et elle se répond en haut de l'écran.
     */
    private static readonly ORDER: Divergence[] = [
        'CONTRADICTED',
        'EXCLUDED_WITHOUT_JUSTIFICATION',
        'UNDECLARED',
        'OVERSTATED',
        'UNDERSTATED',
        'NOT_MEASURED_HERE',
        'NOT_APPLICABLE',
        'CONSISTENT'
    ];

    readonly lines = computed<SoaLine[]>(() => {
        const statement = this.current();
        if (!statement) {
            return [];
        }
        return [...statement.lines].sort((a, b) => Soa.ORDER.indexOf(a.divergence) - Soa.ORDER.indexOf(b.divergence));
    });

    constructor() {
        this.load();
    }

    load(): void {
        this.api.statementsOfApplicability().subscribe({
            next: (data) => this.statements.set(data),
            error: (failure) => this.error.set(messageOf(failure, this.i18n.t('soa.load_failed')))
        });
    }

    isFinding(line: SoaLine): boolean {
        return line.divergence === 'CONTRADICTED'
            || line.divergence === 'EXCLUDED_WITHOUT_JUSTIFICATION'
            || line.divergence === 'UNDECLARED';
    }

    severityOf(line: SoaLine): 'danger' | 'warn' | 'info' | 'secondary' {
        if (this.isFinding(line)) {
            return 'danger';
        }
        if (line.divergence === 'OVERSTATED' || line.divergence === 'UNDERSTATED') {
            return 'warn';
        }
        return line.divergence === 'CONSISTENT' ? 'secondary' : 'info';
    }

    openDeclare(line: SoaLine): void {
        const existing = line.declaration;
        this.applicability = existing?.applicability ?? 'APPLICABLE';
        this.implementation = existing?.implementation ?? 'IMPLEMENTED';
        this.evidenceSource = existing?.evidenceSource ?? 'VECTISPIRE';
        this.justification = existing?.justification ?? '';
        this.externalEvidence = existing?.externalEvidence ?? '';
        this.owner = existing?.owner ?? '';
        this.reviewDue = existing?.reviewDueAt ? existing.reviewDueAt.slice(0, 10) : '';
        this.error.set(null);
        this.editing.set(line);
    }

    /**
     * Les deux refus du serveur, dits ici par un bouton éteint.
     *
     * Laisser partir la requête pour afficher son message marcherait. Un bouton désactivé dit
     * la même chose avant la frappe plutôt qu'après.
     */
    incomplete(): boolean {
        if (this.applicability === 'EXCLUDED') {
            return !this.justification.trim();
        }
        return this.evidenceSource !== 'VECTISPIRE' && !this.externalEvidence.trim();
    }

    submit(): void {
        const line = this.editing();
        const statement = this.current();
        if (!line || !statement || this.incomplete()) {
            return;
        }
        this.busy.set(true);
        this.error.set(null);

        this.api
            .declareControl(statement.framework, line.control.id, {
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
                    // Rechargé plutôt que fusionné localement : la ligne change de divergence,
                    // et recalculer cette règle dans le navigateur en ferait une seconde
                    // implémentation qui finirait par ne plus dire la même chose.
                    this.load();
                },
                error: (failure) => {
                    this.error.set(messageOf(failure, this.i18n.t('soa.declare_failed')));
                    this.busy.set(false);
                }
            });
    }
}
