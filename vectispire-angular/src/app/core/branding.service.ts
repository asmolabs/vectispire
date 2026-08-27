import { Injectable, inject, signal } from '@angular/core';
import { ApiService } from './api.service';
import { firstValueFrom } from 'rxjs';

@Injectable({
    providedIn: 'root'
})
export class BrandingService {
    private readonly api = inject(ApiService);

    readonly brandName = signal<string>('Vectispire');
    readonly gitlabUrl = signal<string>('https://github.com/asmolabs/vectispire');
    readonly isLoaded = signal<boolean>(false);

    /**
     * Fetches public branding parameters (brand name and GitLab repository reference).
     */
    async init(): Promise<void> {
        try {
            const methods = await firstValueFrom(this.api.signInMethods());
            if (methods?.brandName) {
                this.brandName.set(methods.brandName);
            }
            if (methods?.gitlabUrl) {
                this.gitlabUrl.set(methods.gitlabUrl);
            }
            this.isLoaded.set(true);
        } catch {
            // Keep default fallback values if the API is unreachable
            this.isLoaded.set(true);
        }
    }
}
