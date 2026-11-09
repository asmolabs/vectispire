import { Injectable, inject, signal } from '@angular/core';
import { AuthApi } from './api/auth.api';
import { firstValueFrom } from 'rxjs';

@Injectable({
    providedIn: 'root'
})
export class BrandingService {
    private readonly authApi = inject(AuthApi);

    readonly brandName = signal<string>('Vectispire');
    readonly gitlabUrl = signal<string>('https://github.com/asmolabs/vectispire');
    readonly isLoaded = signal<boolean>(false);

    /**
     * Fetches public branding parameters (brand name and GitLab repository reference).
     */
    async init(): Promise<void> {
        try {
            const methods = await firstValueFrom(this.authApi.signInMethods());
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
