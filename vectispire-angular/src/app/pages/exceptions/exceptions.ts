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
import type { ExceptionEntry, ExceptionsRegister, ReviewOutcome } from '@/app/core/api.models';

/**
 * Ce que quelqu'un a décidé de ne pas corriger, et sous quelles conditions.
 *
 * **C'est la question qu'un évaluateur pose en premier et qu'aucun tableau de bord ne
 * répond.** Tous les autres écrans décrivent ce que le parc contient ; celui-ci décrit ce
 * qu'on a écarté — et un backlog vert veut dire deux choses opposées selon celle des deux
 * qui l'a produit.
 *
 * **Deux chiffres portent l'écran, et ce ne sont pas les acceptations en vigueur.** Les
 * périmées — accordées pour une période, la période est passée, personne n'a rouvert — et
 * les jamais revues. La seconde est celle qui n'existait pas : une acceptation confirmée
 * chaque trimestre et une acceptation que personne n'a ouverte depuis janvier se lisaient à
 * l'identique.
 *
 * La revue est réservée au responsable sécurité, comme l'octroi. Confirmer est l'action qui
 * compte et ne change rien : c'est elle qui transforme « personne n'a regardé » en fait
 * daté.
 */
@Component({
    selector: 'zs-exceptions',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, DialogModule, InputTextModule, MessageModule, TagModule, TranslatePipe],
    templateUrl: './exceptions.html'
})
export class Exceptions {
    private readonly api = inject(ApiService);
    private readonly session = inject(SessionStore);
    private readonly i18n = inject(I18nService);

    readonly register = signal<ExceptionsRegister | null>(null);
    readonly error = signal<string | null>(null);
    readonly busy = signal(false);

    /**
     * Les lignes déjà chargées, accumulées page après page.
     *
     * <p><b>Les compteurs en sont dérivés plutôt que repris du serveur.</b> Le serveur compte ce
     * qu'il a rendu sur *cette* page ; afficher « 23 acceptations en vigueur » au-dessus d'une
     * page de deux serait un chiffre qui ne décrit ni la page ni le registre. Ceux-ci décrivent
     * ce que le lecteur a sous les yeux, et le bouton « charger la suite » dit qu'il en reste.
     */
    readonly loaded = signal<ExceptionEntry[]>([]);

    readonly granted = computed(() =>
        this.loaded().filter((entry) => entry.decision === 'not_affected').length);
    readonly awaiting = computed(() =>
        this.loaded().filter((entry) => entry.decision === 'pending_approval').length);
    readonly lapsed = computed(() => this.loaded().filter((entry) => entry.lapsed).length);
    readonly neverReviewed = computed(() =>
        this.loaded().filter((entry) => entry.last_reviewed_at === null).length);

    /**
     * Il reste des lignes à demander.
     *
     * <p><b>Un curseur peut arriver avec une page vide, et c'est voulu.</b> La visibilité est
     * appliquée après la lecture : une fenêtre entière peut n'appartenir qu'à d'autres. Masquer
     * le bouton parce que la page est vide ferait s'arrêter le lecteur restreint juste avant ses
     * propres lignes.
     */
    readonly hasMore = computed(() => this.register()?.next_cursor != null);

    /** La ligne en cours de revue, et ce que le formulaire porte. */
    readonly reviewing = signal<ExceptionEntry | null>(null);
    outcome: ReviewOutcome = 'CONFIRMED';
    comment = '';
    newExpiry = '';

    readonly canReview = computed(() => this.session.isSecurityLead());

    constructor() {
        this.load();
    }

    load(): void {
        this.fetch(null);
    }

    more(): void {
        const cursor = this.register()?.next_cursor;
        if (cursor) {
            this.fetch(cursor);
        }
    }

    private fetch(cursor: string | null): void {
        this.api.exceptionsRegister(200, cursor).subscribe({
            next: (data) => {
                this.register.set(data);
                this.loaded.update((rows) => (cursor ? [...rows, ...data.entries] : data.entries));
            },
            error: (failure) => this.error.set(messageOf(failure, this.i18n.t('exceptions.load_failed')))
        });
    }

    openReview(entry: ExceptionEntry): void {
        this.outcome = 'CONFIRMED';
        this.comment = '';
        this.newExpiry = '';
        this.error.set(null);
        this.reviewing.set(entry);
    }

    /**
     * Prolonger sans date est refusé par le serveur ; le bouton l'est ici aussi.
     *
     * Laisser partir la requête pour afficher son erreur marcherait, et ferait porter à un
     * message d'erreur ce qu'une désactivation dit sans bruit.
     */
    readonly submittable = computed(() => !this.busy());

    incomplete(): boolean {
        return this.outcome === 'EXTENDED' && !this.newExpiry;
    }

    submitReview(): void {
        const entry = this.reviewing();
        if (!entry || this.incomplete()) {
            return;
        }
        this.busy.set(true);
        this.error.set(null);

        this.api
            .reviewException(
                entry.issue_id,
                this.outcome,
                this.comment.trim() || null,
                this.outcome === 'EXTENDED' ? new Date(this.newExpiry).toISOString() : null
            )
            .subscribe({
                next: (data) => {
                    // **Relu depuis le début plutôt que fusionné.** Une révocation retire la ligne
                    // du registre : la fusionner dans ce qui est déjà chargé laisserait sur place
                    // une exception qui n'en est plus une, ce que ce registre ne doit jamais faire.
                    this.register.set(data);
                    this.loaded.set(data.entries);
                    this.reviewing.set(null);
                    this.busy.set(false);
                },
                error: (failure) => {
                    this.error.set(messageOf(failure, this.i18n.t('exceptions.review_failed')));
                    this.busy.set(false);
                }
            });
    }

    severityOf(entry: ExceptionEntry): 'danger' | 'warn' | 'info' | 'secondary' {
        switch ((entry.severity ?? '').toLowerCase()) {
            case 'critical':
                return 'danger';
            case 'high':
                return 'warn';
            case 'medium':
                return 'info';
            default:
                return 'secondary';
        }
    }
}
