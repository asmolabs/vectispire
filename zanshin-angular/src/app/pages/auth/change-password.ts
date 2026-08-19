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
 * Changing your own password.
 *
 * Outside `AppLayout`, like the sign-in screen: an account that has to change its password has
 * no business in the rest of the application, and showing it a clickable sidebar would be an
 * invitation to go around this screen.
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
                            <div class="text-surface-900 dark:text-surface-0 text-2xl font-medium mb-2">Change your password</div>
                            @if (imposed()) {
                                <span class="text-muted-color">This account was created with a temporary password.</span>
                            } @else {
                                <span class="text-muted-color">Your other sessions will be closed.</span>
                            }
                        </div>

                        <form (ngSubmit)="submit()">
                            <label for="current" class="block text-surface-900 dark:text-surface-0 font-medium text-xl mb-2">Current password</label>
                            <p-password id="current" name="current" [(ngModel)]="currentPassword" [toggleMask]="true" [feedback]="false"
                                        styleClass="mb-6" [fluid]="true" autocomplete="current-password" />

                            <label for="next" class="block text-surface-900 dark:text-surface-0 font-medium text-xl mb-2">New password</label>
                            <p-password id="next" name="next" [(ngModel)]="newPassword" [toggleMask]="true" [feedback]="false"
                                        styleClass="mb-2" [fluid]="true" autocomplete="new-password" />

                            <label for="confirm" class="block text-surface-900 dark:text-surface-0 font-medium text-xl mb-2 mt-4">Confirmation</label>
                            <p-password id="confirm" name="confirm" [(ngModel)]="confirmation" [toggleMask]="true" [feedback]="false"
                                        styleClass="mb-2" [fluid]="true" autocomplete="new-password" (keyup.enter)="submit()" />

                            <!-- Length alone, because it is the only constraint whose effect on
                                 entropy is real. Character classes produce "Password1!". -->
                            <p class="text-muted-color text-sm mt-2 mb-4">At least {{ minimumLength }} characters.</p>

                            @if (error(); as message) {
                                <p-message severity="error" [text]="message" styleClass="w-full mb-4" />
                            }

                            <p-button type="submit" label="Change the password" styleClass="w-full" [loading]="loading()" />
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
        // Checked here and not on the server: the confirmation guards against a typo, it is
        // not a rule. Sending it would give the server nothing to check.
        if (this.newPassword !== this.confirmation) {
            this.error.set('The new password and its confirmation differ.');
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
                    this.error.set('Server unreachable. Check that Zanshin is running.');
                } else {
                    // The server distinguishes "current password wrong" (401) from "new
                    // password refused" (400); its message says which one.
                    this.error.set(response.error?.message ?? 'The change failed.');
                }
            }
        });
    }
}
