import { TestBed } from '@angular/core/testing';
import { describe, beforeEach, it, expect, vi } from 'vitest';
import { ComponentFixture } from '@angular/core/testing';
import { AppFooter } from './app.footer';
import { BrandingService } from '@/app/core/branding.service';
import { I18nService } from '@/app/core/i18n/i18n.service';
import { of } from 'rxjs';
import { HttpClient } from '@angular/common/http';
import { ApiService } from '@/app/core/api.service';

describe('AppFooter', () => {
    let fixture: ComponentFixture<AppFooter>;
    let branding: BrandingService;

    const mockEn = {
        footer: {
            tagline: 'Application security posture management',
            powered_by: 'Powered by'
        }
    };

    beforeEach(async () => {
        const mockHttp = {
            get: vi.fn().mockReturnValue(of(mockEn))
        };
        const mockApi = {
            signInMethods: vi.fn().mockReturnValue(of({
                configured: false,
                label: null,
                password: true,
                brandName: 'Vectispire',
                gitlabUrl: 'https://github.com/asmolabs/vectispire'
            }))
        };

        await TestBed.configureTestingModule({
            imports: [AppFooter],
            providers: [
                BrandingService,
                I18nService,
                { provide: HttpClient, useValue: mockHttp },
                { provide: ApiService, useValue: mockApi }
            ]
        }).compileComponents();

        const i18n = TestBed.inject(I18nService);
        i18n.translations.set(mockEn);
        i18n.isLoaded.set(true);

        branding = TestBed.inject(BrandingService);
        fixture = TestBed.createComponent(AppFooter);
        fixture.detectChanges();
    });

    it('displays brand name and Powered by Vectispire with GitLab link', () => {
        branding.brandName.set('Acme Corp');
        branding.gitlabUrl.set('https://github.com/asmolabs/vectispire');
        fixture.detectChanges();

        const element = fixture.nativeElement as HTMLElement;
        expect(element.textContent).toContain('Acme Corp');
        expect(element.textContent).toContain('Powered by');
        expect(element.textContent).toContain('Vectispire');

        const link = element.querySelector('a');
        expect(link).toBeTruthy();
        expect(link?.getAttribute('href')).toBe('https://github.com/asmolabs/vectispire');
        expect(link?.getAttribute('target')).toBe('_blank');
    });
});
