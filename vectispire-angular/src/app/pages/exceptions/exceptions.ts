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
        this.api.exceptionsRegister(200).subscribe({
            next: (data) => this.register.set(data),
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
                    this.register.set(data);
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
