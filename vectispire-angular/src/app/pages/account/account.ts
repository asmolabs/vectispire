import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { CardModule } from '@openng/optimus-ui/card';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { TagModule } from '@openng/optimus-ui/tag';
import { messageOf } from '@/app/core/api-error';
import { AuthApi } from '@/app/core/api/auth.api';
import { SessionStore } from '@/app/core/session.store';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';

/**
 * One's own account, and the second factor nobody could switch on.
 *
 * <h2>Why this screen exists</h2>
 *
 * <p><b>The second factor was complete and could not be enabled.</b> {@code TotpService}, the
 * challenge table, the four {@code /auth/mfa/*} routes, right down to a sign-in page that already
 * knows how to answer a challenge: all of it shipped. The three client methods existed too. No
 * screen called them — so nobody could switch on the second factor of a security product from its
 * own interface, and there was no way of knowing that by looking at the screen.
 *
 * <h2>What enrolment must say, and when</h2>
 *
 * <p>Enrolment happens in two steps because the server does it in two steps, and that is the right
 * shape: the secret is offered, then <b>confirmed by a first code</b>. Without that confirmation, a
 * clock that is out or a secret copied wrong would only show at the next sign-out, that is at the
 * worst possible moment.
 *
 * <p><b>The recovery codes are shown once</b>, and the screen says so before showing them: the
 * server hashes them and will not return them again. A screen showing them without that warning
 * would let somebody close the tab thinking they could find them later.
 *
 * <p><b>No QR image, and that is said rather than hidden.</b> The server does return the
 * {@code otpauth://} URI, but drawing it takes one more dependency, which is a decision one does
 * not make in passing. The secret is therefore shown in groups of four — the manual entry every
 * authenticator application accepts — and the URI stays copyable.
 */
@Component({
    selector: 'app-account',
    standalone: true,
    imports: [CommonModule, FormsModule, RouterLink, ButtonModule, CardModule, InputTextModule, MessageModule, TagModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './account.html'
})
export class Account {
    private readonly authApi = inject(AuthApi);
    private readonly session = inject(SessionStore);
    private readonly i18n = inject(I18nService);

    readonly user = this.session.user;
    readonly mfaEnabled = computed(() => this.session.user()?.mfaEnabled === true);

    readonly busy = signal(false);
    readonly error = signal<string | null>(null);

    /** The secret offered, until it is confirmed. Never kept after activation. */
    readonly enrolment = signal<{ secret: string; qrCodeUri: string; issuer: string } | null>(null);

    /** Shown once, because the server hashes them and will not return them again. */
    readonly backupCodes = signal<string[]>([]);

    /** Opened only when removing the second factor: a code is required for that too. */
    readonly removing = signal(false);

    code = '';

    /** The secret in groups of four: copied by hand, it is copied character by character. */
    readonly readableSecret = computed(() => {
        const secret = this.enrolment()?.secret ?? '';
        return (secret.match(/.{1,4}/g) ?? []).join(' ');
    });

    /** Begins enrolment: the server offers a secret, nothing is switched on yet. */
    begin(): void {
        this.busy.set(true);
        this.error.set(null);
        this.code = '';
        this.backupCodes.set([]);

        this.authApi.setupMfa().subscribe({
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
     * Confirms the secret with a first code.
     *
     * <p>A refusal keeps enrolment open: the code has six digits and thirty seconds of life,
     * getting it wrong is ordinary, and sending the user back to the start would give them a fresh
     * secret to copy over a typo.
     */
    confirm(): void {
        const enrolment = this.enrolment();
        if (!enrolment || !this.code.trim()) return;

        this.busy.set(true);
        this.error.set(null);
        this.authApi.enableMfa(enrolment.secret, this.code.trim()).subscribe({
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

    /** Abandons enrolment. Nothing was switched on, so there is nothing to undo on the server. */
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
     * Removes the second factor.
     *
     * <p>A code is required — current or recovery — and it is the server that requires it: without
     * one, a workstation left unlocked for a minute would be enough to disarm the factor protecting
     * the account, which would empty the protection of its meaning.
     */
    remove(): void {
        if (!this.code.trim()) return;

        this.busy.set(true);
        this.error.set(null);
        this.authApi.disableMfa(this.code.trim()).subscribe({
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
