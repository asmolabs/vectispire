import { CommonModule } from '@angular/common';
import { Component, computed, inject } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { SessionStore } from '@/app/core/session.store';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';

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
    standalone: true,
    imports: [CommonModule, RouterLink, ButtonModule, TranslatePipe],
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
        const key = this.session.role().toLowerCase();
        const label = this.i18n.t(`roles.${key}`);
        return label === `roles.${key}` ? this.session.role() : label;
    });

    readonly reason = computed(() => {
        this.i18n.translations();
        const need = this.route.snapshot.queryParamMap.get('need') ?? '';
        return this.i18n.t(`forbidden.need_${need.replace('-', '_')}`);
    });

    /** An auditor is sent to the thing it came for, everybody else to the backlog. */
    readonly elsewhere = computed(() => (this.session.canReadGovernance() ? '/audit-log' : '/issues'));
}
