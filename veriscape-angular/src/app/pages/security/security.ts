import { Component, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '@/app/core/api.service';
import { saveDocument } from '@/app/core/download';
import { SecurityOverview, TargetPosture } from '@/app/core/api.models';

import { CommonModule } from '@angular/common';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';

/**
 * The security posture — the gate's verdict, shown at last.
 *
 * It had always been computed for `POST /api/v1/gate` and displayed nowhere: a team could only
 * learn whether its repository passed by running a build against it.
 *
 * **The column that matters most is not the verdict, it is the observation.** An empty backlog
 * passes every policy, so a target nobody has successfully scanned reads as "compliant" without
 * that meaning anything. The "not observed" badge is what keeps this screen from being
 * misleading, and the banner repeats it at the top.
 */
@Component({
    selector: 'zs-security',
    standalone: true,
    imports: [CommonModule, TableModule, TagModule, ButtonModule, MessageModule, RouterLink, TranslatePipe],
    templateUrl: './security.html'
})
export class Security {
    private readonly api = inject(ApiService);

    readonly overview = signal<SecurityOverview | null>(null);
    readonly error = signal<string | null>(null);

    constructor() {
        this.api.securityOverview().subscribe({
            next: (data) => this.overview.set(data),
            error: () => this.error.set('Could not load the security posture.')
        });
    }

    /**
     * The timestamp, made readable.
     *
     * The API returns the text the database holds — `2026-08-10 18:45:18.408868` — which is the
     * right thing to transport (the microsecond survives, no time zone is applied on the way)
     * and the wrong thing to display. The conversion therefore happens here, at the last
     * moment, and nowhere earlier.
     */
    formatDate(value: string | null): string {
        if (!value) return '—';
        // Explicit `Z` suffix: the value is UTC with no zone, and without it the browser would
        // read it as local time — and therefore display it shifted.
        //
        // The locale stays `fr-BE` although the interface is in English: it is a regional
        // format, not a language, and `en-US` would swap day and month for the people reading
        // this.
        const at = new Date(`${value.replace(' ', 'T')}Z`);
        return Number.isNaN(at.getTime()) ? value : at.toLocaleString('fr-BE', { dateStyle: 'short', timeStyle: 'short' });
    }

    private readonly i18n = inject(I18nService);

    observationLabel(target: TargetPosture): string {
        if (target.observation === 'never_scanned') return this.i18n.t('security.never_scanned_badge');
        if (target.observation === 'last_scan_failed') return this.i18n.t('security.last_scan_failed_badge');
        return this.i18n.t('security.scan_in_progress');
    }

    /**
     * The link to the backlog filtered on this target.
     *
     * These parameters were already produced by the Reflex version — and **never read** by its
     * Issues screen, which used URL parameters nowhere. Here the Angular router passes them on
     * and the screen honours them.
     */
    /** The row whose export is in flight, so the three buttons cannot be pressed twice. */
    readonly downloading = signal<number | null>(null);

    /**
     * Fetches an export and hands it to the browser.
     *
     * **The filename comes from `Content-Disposition`, not from here.** The server builds it
     * from the kind and the numeric id precisely because a target's name is operator-supplied
     * text; re-deriving it in the browser would put that text back in play and give the same
     * document two names depending on where it was saved from.
     */
    download(target: TargetPosture, document: string): void {
        this.downloading.set(target.targetId);
        this.api.exportDocument(target.kind, target.targetId, document).subscribe({
            next: (response) => {
                this.downloading.set(null);
                saveDocument(response, document);
            },
            error: () => {
                this.downloading.set(null);
                this.error.set('The export could not be produced.');
            }
        });
    }

    issueFilter(target: TargetPosture): Record<string, number> {
        return target.kind === 'repository' ? { repository_id: target.targetId } : { container_id: target.targetId };
    }
}

