import { Component, computed, inject, ChangeDetectionStrategy } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { SessionStore } from '@/app/core/session.store';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import { keyFor } from '@/app/core/i18n/literal-keys';
import type { Need } from '@/app/core/role.guard';
import { roleLabel } from '@/app/shared/role-labels';

/**
 * What the refused page needs, through literal keys (decision 0019). The page built
 * `forbidden.need_${need}` from the query string, so a need the guard learnt and the bundle did not
 * — or a hand-typed URL — put a key path in the page's only heading.
 */
export const NEED_KEYS = {
    administrator: 'forbidden.need_administrator',
    'security-lead': 'forbidden.need_security_lead',
    'governance-read': 'forbidden.need_governance_read'
} as const satisfies Record<Need, string>;

/**
 * The page a refused route lands on.
 *
 * <p>It names three things, because a refusal that names none of them reads as a fault: which page
 * was asked for, what that page needs, and what this account is. The previous behaviour named
 * none — the component loaded and showed "Could not load…", which says the product is broken
 * rather than that the door is not this one's.
 */
@Component({
    selector: 'app-forbidden',
    imports: [RouterLink, ButtonModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './forbidden.html'
})
export class Forbidden {
    private readonly route = inject(ActivatedRoute);
    private readonly i18n = inject(I18nService);
    private readonly session = inject(SessionStore);

    readonly page = computed(() => this.route.snapshot.queryParamMap.get('page') ?? '');

    /** The role, in the words the accounts screen uses — never the enum constant. */
    readonly role = computed(() => {
        this.i18n.translations();
        return roleLabel(this.i18n, this.session.role());
    });

    /** A need nobody spelt — a hand-typed URL — still says the door is closed, in the widest words. */
    readonly reason = computed(() => {
        this.i18n.translations();
        const need = this.route.snapshot.queryParamMap.get('need') ?? '';
        return this.i18n.t(keyFor(NEED_KEYS, need) ?? 'titles.forbidden');
    });

    /** An auditor is sent to the thing it came for, everybody else to the backlog. */
    readonly elsewhere = computed(() => (this.session.canReadGovernance() ? '/audit-log' : '/issues'));
}
