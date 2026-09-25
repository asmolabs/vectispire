import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal, ChangeDetectionStrategy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MessageModule } from '@openng/optimus-ui/message';
import { messageOf } from '@/app/core/api-error';
import { ComplianceApi } from '@/app/core/api/compliance.api';
import { TargetsApi } from '@/app/core/api/targets.api';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { SessionStore } from '@/app/core/session.store';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';
import type { MonitoredContainer, MonitoredRepository, ScopeView } from '@/app/core/api.models';

/**
 * What the certified scope covers, and how much of it carries current evidence.
 *
 * **A tool measuring its own coverage always announces one hundred per cent.** Every other screen
 * answers a question about the targets somebody registered; a management system has a scope
 * declared in a document, and the two are not the same set. An estate scanned in full but made of
 * half the certified assets reads as a clean result, and no query can notice it.
 *
 * **Hence the number at the top of the screen, which is about what is missing.** "Your scope names
 * forty assets, this instance holds thirty-one" is the sentence an audit begins with, and it is
 * not derived: the declared number is copied from the scope document.
 *
 * **Nothing is in scope by default.** A scope nobody has drawn is an undrawn scope, not the whole
 * estate — and the screen says "not declared" rather than producing a percentage against an
 * unknown denominator.
 */
@Component({
    selector: 'zs-certified-scope',
    standalone: true,
    imports: [CommonModule, FormsModule, MessageModule, TranslatePipe],
    changeDetection: ChangeDetectionStrategy.Eager,
    templateUrl: './certified-scope.html'
})
export class CertifiedScope {
    private readonly complianceApi = inject(ComplianceApi);
    private readonly targetsApi = inject(TargetsApi);
    private readonly i18n = inject(I18nService);
    private readonly session = inject(SessionStore);

    readonly scope = signal<ScopeView | null>(null);
    readonly repositories = signal<MonitoredRepository[]>([]);
    readonly containers = signal<MonitoredContainer[]>([]);
    readonly error = signal<string | null>(null);

    readonly canEdit = computed(() => this.session.isSecurityLead());

    readonly declared = computed(() => (this.scope()?.coverage.declaredAssets ?? 0) > 0);

    /**
     * The assets the declaration claims and for which the instance holds no row.
     *
     * Zero when nobody declared a number — *not* when coverage is complete. The two are told apart
     * by {@link declared}, and conflating them is the whole trap: an undeclared scope reports no
     * gap for the same reason an empty room reports no noise.
     */
    readonly unaccountedFor = computed(() => {
        const coverage = this.scope()?.coverage;
        if (!coverage || coverage.declaredAssets <= 0) {
            return 0;
        }
        return Math.max(0, coverage.declaredAssets - coverage.inScope);
    });

    /**
     * The share of the *declared* scope carrying fresh evidence, or nothing.
     *
     * Against the declared number and not against what the instance holds: dividing by what one has
     * is exactly how a tool announces one hundred per cent over a tenth of an estate.
     */
    readonly freshShare = computed<number | null>(() => {
        const coverage = this.scope()?.coverage;
        if (!coverage || coverage.declaredAssets <= 0) {
            return null;
        }
        return Math.round((100 * coverage.scannedRecently) / coverage.declaredAssets);
    });

    constructor() {
        this.complianceApi.certifiedScope().subscribe({
            next: (data) => this.scope.set(data),
            error: (failure) => this.error.set(messageOf(failure, this.i18n.t('scope.load_failed')))
        });
        this.targetsApi
            .repositories()
            .subscribe({ next: (rows) => this.repositories.set(rows), error: () => undefined });
        this.targetsApi.containers().subscribe({ next: (rows) => this.containers.set(rows), error: () => undefined });
    }

    inScope(kind: string, id: number): boolean {
        return (this.scope()?.targets ?? []).some((target) => target.kind === kind && target.id === id);
    }

    toggleRepository(id: number, next: boolean): void {
        this.complianceApi.setRepositoryInScope(id, next).subscribe({
            next: (data) => this.scope.set(data),
            error: (failure) => this.error.set(messageOf(failure, this.i18n.t('scope.update_failed')))
        });
    }

    toggleContainer(id: number, next: boolean): void {
        this.complianceApi.setContainerInScope(id, next).subscribe({
            next: (data) => this.scope.set(data),
            error: (failure) => this.error.set(messageOf(failure, this.i18n.t('scope.update_failed')))
        });
    }
}
