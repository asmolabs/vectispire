import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { BrandingService } from '@/app/core/branding.service';
import { TranslatePipe } from '@/app/core/i18n/translate.pipe';

@Component({
    standalone: true,
    selector: 'app-footer',
    imports: [CommonModule, TranslatePipe],
    template: `<div class="layout-footer flex flex-wrap items-center justify-between gap-3 text-xs text-muted-color px-4 py-3">
        <div>
            <span class="font-semibold text-surface-900 dark:text-surface-0">{{ branding.brandName() }}</span>
            <span class="mx-1.5 opacity-40">—</span>
            <span>{{ 'footer.tagline' | translate }}</span>
        </div>
        <div class="flex items-center gap-1.5">
            <span>{{ 'footer.powered_by' | translate }}</span>
            <a
                [href]="branding.gitlabUrl()"
                target="_blank"
                rel="noopener noreferrer"
                class="font-semibold text-primary hover:underline inline-flex items-center gap-1"
                aria-label="Vectispire GitLab repository"
            >
                <i class="pi pi-code text-xs"></i>
                <span>Vectispire</span>
            </a>
        </div>
    </div>`
})
export class AppFooter {
    branding = inject(BrandingService);
}
