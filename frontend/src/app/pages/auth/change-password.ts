import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { PasswordModule } from '@openng/optimus-ui/password';
import { ApiService } from '../../core/api.service';
import { SessionStore } from '../../core/session.store';

const MINIMUM_LENGTH = 12;

/**
 * Le changement de son propre mot de passe.
 *
 * Hors de `AppLayout`, comme la connexion : un compte qui doit changer son mot de passe
 * n'a rien à faire dans le reste de l'application, et lui montrer une barre latérale
 * cliquable inviterait à contourner l'écran.
 */
@Component({
    selector: 'app-change-password',
    standalone: true,
    imports: [CommonModule, FormsModule, ButtonModule, MessageModule, PasswordModule],
    template: `
        <div class="flex items-center justify-center min-h-screen overflow-hidden">
            <div class="flex flex-col items-center justify-center w-full max-w-md">
                <div style="border-radius: 56px; padding: 0.3rem; background: linear-gradient(180deg, var(--primary-color) 10%, rgba(33, 150, 243, 0) 30%)">
                    <div class="w-full bg-surface-0 dark:bg-surface-900 py-12 px-8 sm:px-12" style="border-radius: 53px">
                        <div class="text-center mb-8">
                            <div class="text-surface-900 dark:text-surface-0 text-2xl font-medium mb-2">Changer votre mot de passe</div>
                            @if (imposed()) {
                                <span class="text-muted-color">Ce compte a été créé avec un mot de passe provisoire.</span>
                            } @else {
                                <span class="text-muted-color">Vos autres sessions seront fermées.</span>
                            }
                        </div>

                        <form (ngSubmit)="submit()">
                            <label for="current" class="block text-surface-900 dark:text-surface-0 font-medium text-xl mb-2">Mot de passe actuel</label>
                            <p-password id="current" name="current" [(ngModel)]="currentPassword" [toggleMask]="true" [feedback]="false"
                                        styleClass="mb-6" [fluid]="true" autocomplete="current-password" />

                            <label for="next" class="block text-surface-900 dark:text-surface-0 font-medium text-xl mb-2">Nouveau mot de passe</label>
                            <p-password id="next" name="next" [(ngModel)]="newPassword" [toggleMask]="true" [feedback]="false"
                                        styleClass="mb-2" [fluid]="true" autocomplete="new-password" />

                            <label for="confirm" class="block text-surface-900 dark:text-surface-0 font-medium text-xl mb-2 mt-4">Confirmation</label>
                            <p-password id="confirm" name="confirm" [(ngModel)]="confirmation" [toggleMask]="true" [feedback]="false"
                                        styleClass="mb-2" [fluid]="true" autocomplete="new-password" (keyup.enter)="submit()" />

                            <!-- La longueur seule, parce que c'est la seule contrainte dont
                                 l'effet sur l'entropie soit réel. Les classes de caractères
                                 produisent « Motdepasse1! ». -->
                            <p class="text-muted-color text-sm mt-2 mb-4">Au moins {{ minimumLength }} caractères.</p>

                            @if (error(); as message) {
                                <p-message severity="error" [text]="message" styleClass="w-full mb-4" />
                            }

                            <p-button type="submit" label="Changer le mot de passe" styleClass="w-full" [loading]="loading()" />
                        </form>
                    </div>
                </div>
            </div>
        </div>
    `
})
export class ChangePassword {
    private readonly api = inject(ApiService);
    private readonly session = inject(SessionStore);
    private readonly router = inject(Router);

    readonly minimumLength = MINIMUM_LENGTH;
    readonly loading = signal(false);
    readonly error = signal<string | null>(null);
    readonly imposed = computed(() => this.session.mustChangePassword());

    currentPassword = '';
    newPassword = '';
    confirmation = '';

    submit(): void {
        // Vérifiée ici et pas côté serveur : la confirmation est une protection contre la
        // faute de frappe, pas une règle. L'envoyer ne lui donnerait rien à vérifier.
        if (this.newPassword !== this.confirmation) {
            this.error.set('Le nouveau mot de passe et sa confirmation diffèrent.');
            return;
        }

        this.loading.set(true);
        this.error.set(null);
        this.api.changePassword(this.currentPassword, this.newPassword).subscribe({
            next: () => {
                this.loading.set(false);
                this.session.clearMustChangePassword();
                void this.router.navigate(['/dashboard']);
            },
            error: (response: { status: number; error?: { message?: string } }) => {
                this.loading.set(false);
                if (response.status === 0) {
                    this.error.set('Serveur injoignable. Vérifiez que Zanshin est démarré.');
                } else {
                    // Le serveur distingue « mot de passe actuel incorrect » (401) de
                    // « nouveau mot de passe refusé » (400) ; son message porte laquelle.
                    this.error.set(response.error?.message ?? 'Le changement a échoué.');
                }
            }
        });
    }
}
