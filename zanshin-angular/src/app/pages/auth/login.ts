import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { InputTextModule } from '@openng/optimus-ui/inputtext';
import { MessageModule } from '@openng/optimus-ui/message';
import { PasswordModule } from '@openng/optimus-ui/password';
import { ApiService } from '@/app/core/api.service';
import { SessionStore } from '@/app/core/session.store';

/**
 * The sign-in screen.
 *
 * **No default credential is displayed**, unlike the Reflex version. The bootstrap account
 * carries `mustChangePassword`, which is the correct way to say "change your password" without
 * writing down what it currently is.
 *
 * The error message does not distinguish "unknown account" from "wrong password" — the API does
 * not distinguish them either, and separating them would hand the list of existing accounts to
 * whoever probes it. A rate-limiter block, on the other hand, is announced: that is something
 * the person needs to know, so that they know waiting is enough.
 */
@Component({
    selector: 'zs-login',
    standalone: true,
    imports: [FormsModule, ButtonModule, InputTextModule, PasswordModule, MessageModule],
    templateUrl: './login.html'
})
export class Login {
    private readonly api = inject(ApiService);
    private readonly session = inject(SessionStore);
    private readonly router = inject(Router);

    username = '';
    password = '';
    readonly loading = signal(false);
    readonly error = signal<string | null>(null);

    submit(): void {
        if (this.loading()) return;
        this.loading.set(true);
        this.error.set(null);

        this.api.login(this.username, this.password, clientId()).subscribe({
            next: (response) => {
                this.session.open(response.token, response.user);
                // Un compte de provisionnement va d'abord changer son mot de passe : le
                // laisser atteindre le reste viderait le drapeau de son sens.
                void this.router.navigate([response.user.mustChangePassword ? '/change-password' : '/dashboard']);
            },
            error: (response: { status: number; error?: { message?: string; retryAfterSeconds?: number } }) => {
                this.loading.set(false);
                const retryAfter = response.error?.retryAfterSeconds;
                if (retryAfter) {
                    this.error.set(`Too many attempts. Try again in ${Math.ceil(retryAfter / 60)} minute(s).`);
                } else if (response.status === 401) {
                    this.error.set('Invalid credentials.');
                } else {
                    // An unreachable or failing server used to display "Invalid credentials",
                    // which sends somebody hunting for the right password while the real fault
                    // is elsewhere. Seen by trying it, not by reading it.
                    this.error.set(
                        response.status === 0
                            ? 'Server unreachable. Check that Zanshin is running.'
                            : `The server answered ${response.status}. Try again, or check its logs.`
                    );
                }
            }
        });
    }
}

/**
 * Identifies this browser for the rate limiter's second counter.
 *
 * Persisted, because an identifier drawn afresh on every load would make that counter useless —
 * and it is precisely the one that stops an attacker sweeping the account list from a single
 * machine. It is not a secret: losing it gives nobody anything, it only makes the limiter more
 * forgiving.
 */
function clientId(): string {
    const key = 'zanshin.client';
    let value = localStorage.getItem(key);
    if (!value) {
        value = crypto.randomUUID();
        localStorage.setItem(key, value);
    }
    return value;
}
