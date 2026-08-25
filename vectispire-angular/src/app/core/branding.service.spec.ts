import { TestBed } from '@angular/core/testing';
import { describe, beforeEach, it, expect, vi } from 'vitest';
import { of, throwError } from 'rxjs';
import { BrandingService } from './branding.service';
import { ApiService } from './api.service';

describe('BrandingService', () => {
    let service: BrandingService;
    let mockApi: { signInMethods: ReturnType<typeof vi.fn> };

    beforeEach(() => {
        mockApi = {
            signInMethods: vi.fn().mockReturnValue(
                of({
                    configured: false,
                    label: null,
                    password: true,
                    brandName: 'Acme Security',
                    gitlabUrl: 'https://gitlab.com/custom/repo'
                })
            )
        };

        TestBed.configureTestingModule({
            providers: [
                BrandingService,
                { provide: ApiService, useValue: mockApi }
            ]
        });

        service = TestBed.inject(BrandingService);
    });

    it('instantiates with default values', () => {
        expect(service.brandName()).toBe('Vectispire');
        expect(service.gitlabUrl()).toBe('https://gitlab.com/asmolabs_be/vectispire');
    });

    it('loads custom brand parameters from API', async () => {
        await service.init();
        expect(service.brandName()).toBe('Acme Security');
        expect(service.gitlabUrl()).toBe('https://gitlab.com/custom/repo');
        expect(service.isLoaded()).toBe(true);
    });

    it('falls back to defaults if API fails', async () => {
        mockApi.signInMethods.mockReturnValue(throwError(() => new Error('Network error')));
        await service.init();
        expect(service.brandName()).toBe('Vectispire');
        expect(service.gitlabUrl()).toBe('https://gitlab.com/asmolabs_be/vectispire');
        expect(service.isLoaded()).toBe(true);
    });
});
