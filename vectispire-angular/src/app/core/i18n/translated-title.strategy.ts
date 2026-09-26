import { Injectable, effect, inject, signal } from '@angular/core';
import { Title } from '@angular/platform-browser';
import { RouterStateSnapshot, TitleStrategy } from '@angular/router';
import { BrandingService } from '../branding.service';
import { I18nService } from './i18n.service';

/**
 * The tab says which page it holds, in the reader's language.
 *
 * <p>Every tab used to read "Vectispire" whatever it showed, so ten open screens were ten identical
 * tabs, and the browser history listed a column of the same word. A route's `title` is a
 * translation key rather than a sentence, because a sentence there would be frozen in the language
 * it was typed in — the defect `check-i18n-keys.mjs` exists to refuse, and which reads
 * `app.routes.ts` for that reason.
 *
 * <p>The key is kept, not the text, so that switching language re-translates the open tab: an
 * `effect` reads the dictionary and the brand name, and runs again when either changes.
 */
@Injectable({ providedIn: 'root' })
export class TranslatedTitleStrategy extends TitleStrategy {
    private readonly title = inject(Title);
    private readonly i18n = inject(I18nService);
    private readonly branding = inject(BrandingService);
    private readonly key = signal<string | undefined>(undefined);

    constructor() {
        super();
        effect(() => {
            const key = this.key();
            const brand = this.branding.brandName();
            this.title.setTitle(key ? `${this.i18n.t(key)} · ${brand}` : brand);
        });
    }

    override updateTitle(snapshot: RouterStateSnapshot): void {
        this.key.set(this.buildTitle(snapshot));
    }
}
