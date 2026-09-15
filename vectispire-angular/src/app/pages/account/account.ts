import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '@/app/core/api-error';
import { ApiService } from '@/app/core/api.service';
import { SessionStore } from '@/app/core/session.store';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';

/**
 * Son propre compte, et le second facteur qu'on ne pouvait pas activer.
 *
 * <h2>Pourquoi cet écran existe</h2>
 *
 * <p><b>Le second facteur était complet et inactivable.</b> {@code TotpService}, la table des
 * défis, les quatre routes {@code /auth/mfa/*}, et jusqu'à la page de connexion qui sait déjà
 * répondre à un défi : tout était livré. Les trois méthodes clientes existaient aussi. Aucun
 * écran ne les appelait — personne ne pouvait donc activer le second facteur d'un produit de
 * sécurité depuis son interface, et il n'y avait pas de moyen de le savoir en regardant l'écran.
 *
 * <h2>Ce que l'enrôlement doit dire, et quand</h2>
 *
 * <p>L'enrôlement se fait en deux temps parce que le serveur le fait en deux temps, et c'est la
 * bonne forme : le secret est proposé, puis <b>confirmé par un premier code</b>. Sans cette
 * confirmation, une horloge décalée ou un secret mal recopié n'apparaîtrait qu'à la déconnexion
 * suivante, c'est-à-dire au pire moment.
 *
 * <p><b>Les codes de secours ne sont montrés qu'une fois</b>, et l'écran le dit avant de les
 * afficher : le serveur les chiffre et ne les rend plus. Un écran qui les afficherait sans
 * avertissement laisserait quelqu'un fermer l'onglet en pensant les retrouver plus tard.
 *
 * <p><b>Pas d'image QR, et c'est dit plutôt que caché.</b> Le serveur rend bien l'URI
 * {@code otpauth://}, mais la dessiner demande une dépendance de plus, ce qui est une décision
 * qui ne se prend pas en passant. Le secret est donc affiché en groupes de quatre — la saisie
 * manuelle que toute application d'authentification accepte — et l'URI reste copiable.
 */
@Component({
    selector: 'app-account',
    standalone: true,
    imports: [CommonModule, FormsModule, RouterLink, ButtonModule, CardModule, InputTextModule, MessageModule, TagModule, TranslatePipe],
    templateUrl: './account.html'
})
export class Account {
    private readonly api = inject(ApiService);
    private readonly session = inject(SessionStore);
    private readonly i18n = inject(I18nService);

    readonly user = this.session.user;
    readonly mfaEnabled = computed(() => this.session.user()?.mfaEnabled === true);

    readonly busy = signal(false);
    readonly error = signal<string | null>(null);

    /** Le secret proposé, tant qu'il n'est pas confirmé. Jamais conservé après l'activation. */
    readonly enrolment = signal<{ secret: string; qrCodeUri: string; issuer: string } | null>(null);

    /** Montrés une fois, parce que le serveur les chiffre et ne les rendra plus. */
    readonly backupCodes = signal<string[]>([]);

    /** Ouvert seulement quand on retire le second facteur : le code est exigé pour cela aussi. */
    readonly removing = signal(false);

    code = '';

    /** Le secret en groupes de quatre : recopié à la main, il l'est caractère par caractère. */
    readonly readableSecret = computed(() => {
        const secret = this.enrolment()?.secret ?? '';
        return (secret.match(/.{1,4}/g) ?? []).join(' ');
    });

    /** Commence l'enrôlement : le serveur propose un secret, rien n'est encore activé. */
    begin(): void {
        this.busy.set(true);
        this.error.set(null);
        this.code = '';
        this.backupCodes.set([]);

        this.api.setupMfa().subscribe({
            next: (setup) => {
                this.enrolment.set(setup);
                this.busy.set(false);
            },
            error: (response) => {
                this.busy.set(false);
                this.error.set(messageOf(response, this.i18n.t('account.mfa_setup_failed')));
            }
        });
    }

    /**
     * Confirme le secret par un premier code.
     *
     * <p>Un refus garde l'enrôlement ouvert : le code a six chiffres et trente secondes de vie,
     * se tromper est ordinaire, et renvoyer l'utilisateur au début lui donnerait un secret neuf
     * à recopier pour une faute de frappe.
     */
    confirm(): void {
        const enrolment = this.enrolment();
        if (!enrolment || !this.code.trim()) return;

        this.busy.set(true);
        this.error.set(null);
        this.api.enableMfa(enrolment.secret, this.code.trim()).subscribe({
            next: (result) => {
                this.busy.set(false);
                this.enrolment.set(null);
                this.code = '';
                this.backupCodes.set(result?.backupCodes ?? []);
                this.session.setMfaEnabled(true);
            },
            error: (response) => {
                this.busy.set(false);
                this.error.set(messageOf(response, this.i18n.t('account.mfa_enable_failed')));
            }
        });
    }

    /** Abandonne l'enrôlement. Rien n'a été activé, donc il n'y a rien à annuler côté serveur. */
    cancel(): void {
        this.enrolment.set(null);
        this.code = '';
        this.error.set(null);
    }

    askRemoval(): void {
        this.removing.set(true);
        this.code = '';
        this.error.set(null);
    }

    /**
     * Retire le second facteur.
     *
     * <p>Un code est exigé — courant ou de secours — et c'est le serveur qui l'exige : sans lui,
     * un poste laissé déverrouillé une minute suffirait à désarmer le facteur qui protège le
     * compte, ce qui viderait la protection de son sens.
     */
    remove(): void {
        if (!this.code.trim()) return;

        this.busy.set(true);
        this.error.set(null);
        this.api.disableMfa(this.code.trim()).subscribe({
            next: () => {
                this.busy.set(false);
                this.removing.set(false);
                this.code = '';
                this.backupCodes.set([]);
                this.session.setMfaEnabled(false);
            },
            error: (response) => {
                this.busy.set(false);
                this.error.set(messageOf(response, this.i18n.t('account.mfa_disable_failed')));
            }
        });
    }
}
