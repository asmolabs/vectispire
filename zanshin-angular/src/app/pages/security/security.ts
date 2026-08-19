import { Component, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ButtonModule } from '@openng/optimus-ui/button';
import { MessageModule } from '@openng/optimus-ui/message';
import { TableModule } from '@openng/optimus-ui/table';
import { TagModule } from '@openng/optimus-ui/tag';
import { ApiService } from '@/app/core/api.service';
import { SecurityOverview, TargetPosture } from '@/app/core/api.models';

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
    imports: [TableModule, TagModule, ButtonModule, MessageModule, RouterLink],
    template: `
        <div class="card">
            <div class="font-semibold text-xl mb-1">Security</div>
            <p class="text-muted-color mb-4">The verdict the continuous-integration gate would return for each target, with the policy that produced it.</p>

            @if (overview(); as data) {
                <div class="flex flex-wrap gap-6 mb-4">
                    <div>
                        <span class="text-2xl font-medium" [class.text-red-500]="data.failingCount > 0">{{ data.failingCount }}</span>
                        <span class="text-muted-color ml-2">/ {{ data.totalCount }} failing</span>
                    </div>
                    <div><span class="text-2xl font-medium">{{ data.kevCount }}</span><span class="text-muted-color ml-2">open KEV</span></div>
                    <div><span class="text-2xl font-medium">{{ data.neverScannedCount }}</span><span class="text-muted-color ml-2">never scanned</span></div>
                    <div><span class="text-2xl font-medium">{{ data.lastScanFailedCount }}</span><span class="text-muted-color ml-2">last scan failed</span></div>
                </div>

                @if (data.neverScannedCount + data.lastScanFailedCount > 0) {
                    <p-message severity="warn" styleClass="w-full mb-4"
                        text="Some targets have not been observed. An empty backlog passes every policy: their verdict says nothing until a scan has succeeded." />
                }

                <p-table [value]="data.targets" [tableStyle]="{ 'min-width': '50rem' }">
                    <ng-template #header>
                        <tr>
                            <th>Target</th>
                            <th>Verdict</th>
                            <th>Evaluated</th>
                            <th>Policy</th>
                            <th>Last scan</th>
                            <th></th>
                        </tr>
                    </ng-template>
                    <ng-template #body let-target>
                        <tr>
                            <td>
                                <span class="font-medium">{{ target.name }}</span>
                                <div class="text-muted-color text-sm">{{ target.kind === 'repository' ? 'Repository' : 'Container' }}</div>
                            </td>
                            <td>
                                <p-tag [severity]="target.passed ? 'success' : 'danger'" [value]="target.passed ? 'Passing' : 'Failing'" />
                                @if (!target.observed) {
                                    <p-tag severity="warn" [value]="observationLabel(target)" styleClass="ml-2" />
                                }
                                @if (target.verdict.violations.length) {
                                    <div class="text-muted-color text-sm mt-1">{{ target.verdict.violations[0].reason }}</div>
                                }
                            </td>
                            <td>{{ target.verdict.evaluated }}</td>
                            <td class="text-muted-color">{{ target.policy.source === 'built-in' ? 'default' : target.policy.source + ' v' + target.policy.version }}</td>
                            <td class="text-muted-color">{{ formatDate(target.lastScanAt) }}</td>
                            <td>
                                <p-button label="Issues" size="small" [text]="true" [routerLink]="['/issues']" [queryParams]="issueFilter(target)" />
                                <!--
                                    Buttons and not links: the session token lives in memory and
                                    is put on requests by the interceptor, so a browser
                                    navigation to the same URL carries no credential and answers
                                    401. Going through the HTTP client is what authenticates it.
                                -->
                                <p-button label="PDF" size="small" [text]="true" [disabled]="downloading() === target.targetId"
                                          (onClick)="download(target, 'posture.pdf')" />
                                <p-button label="CSV" size="small" [text]="true" [disabled]="downloading() === target.targetId"
                                          (onClick)="download(target, 'issues.csv')" />
                                <p-button label="VEX" size="small" [text]="true" [disabled]="downloading() === target.targetId"
                                          (onClick)="download(target, 'vex')" />
                            </td>
                        </tr>
                    </ng-template>
                    <ng-template #emptymessage>
                        <tr><td colspan="6" class="text-center text-muted-color py-6">No monitored target.</td></tr>
                    </ng-template>
                </p-table>
            } @else if (error()) {
                <p-message severity="error" [text]="error()!" styleClass="w-full" />
            }
        </div>
    `
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

    observationLabel(target: TargetPosture): string {
        if (target.observation === 'never_scanned') return 'Never scanned';
        if (target.observation === 'last_scan_failed') return 'Last scan failed';
        return 'Scan in progress';
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
                const blob = response.body;
                if (!blob) return;

                const url = URL.createObjectURL(blob);
                const link = window.document.createElement('a');
                link.href = url;
                link.download = filenameOf(response.headers.get('Content-Disposition')) ?? document;
                link.click();
                // Revoked immediately: the blob holds the whole export in memory, and a tab
                // left open on this screen would accumulate one per click.
                URL.revokeObjectURL(url);
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

/** The name the server chose, or nothing when it did not say. */
function filenameOf(disposition: string | null): string | null {
    const match = disposition?.match(/filename="([^"]+)"/);
    return match ? match[1] : null;
}
