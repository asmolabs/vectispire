import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { PasswordModule } from '@openng/optimus-ui/password';
import { messageOf } from '../../core/api-error';
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
    templateUrl: './change-password.html'
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
                    this.error.set(messageOf(response, 'The change failed.'));
                }
            }
        });
    }
}
