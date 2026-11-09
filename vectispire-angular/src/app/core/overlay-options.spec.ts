import { provideHttpClientTesting } from '@angular/common/http/testing';
import { ChangeDetectionStrategy, Component, provideZonelessChangeDetection } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { FormsModule } from '@angular/forms';
import { Optimus, provideOptimus } from '@openng/optimus-ui/config';
import { SelectModule } from '@openng/optimus-ui/select';
import { describe, expect, it, vi } from 'vitest';
import { appConfig } from '../../app.config';
import { keepOpenOnResize, OVERLAY_OPTIONS } from './overlay-options';

@Component({
    imports: [FormsModule, SelectModule],
    changeDetection: ChangeDetectionStrategy.OnPush,
    template: `<p-select [options]="options" optionLabel="label" optionValue="value" [(ngModel)]="chosen" />`
})
class Host {
    readonly options = [
        { label: 'Auditor', value: 'AUDITOR' },
        { label: 'Security champion', value: 'SECURITY_CHAMPION' }
    ];
    chosen = 'SECURITY_CHAMPION';
}

async function until(condition: () => boolean, what: string): Promise<void> {
    for (let attempt = 0; attempt < 100; attempt++) {
        if (condition()) return;
        await new Promise((resolve) => setTimeout(resolve, 10));
    }
    throw new Error(`timed out waiting for ${what}`);
}

/** Opens the list, waits until its listeners are bound, then resizes the window as zoom does. */
async function openThenResize(withAppOptions: boolean): Promise<{ open: boolean; chosen: string; label: string }> {
    TestBed.configureTestingModule({
        imports: [Host],
        providers: [
            provideZonelessChangeDetection(),
            provideOptimus(withAppOptions ? { overlayOptions: OVERLAY_OPTIONS } : {})
        ]
    });
    const fixture = TestBed.createComponent(Host);
    await fixture.whenStable();
    const root = fixture.nativeElement as HTMLElement;
    const panel = () => root.querySelector('.p-select-overlay');

    (root.querySelector('.p-select') as HTMLElement).click();
    await fixture.whenStable();
    await until(() => panel() !== null, 'the list to open');
    // `Overlay` binds its window listeners when the enter transition ends, not when it starts.
    await new Promise((resolve) => setTimeout(resolve, 300));

    window.dispatchEvent(new Event('resize'));
    await fixture.whenStable();
    await new Promise((resolve) => setTimeout(resolve, 300));
    await fixture.whenStable();

    return {
        open: panel() !== null,
        chosen: fixture.componentInstance.chosen,
        label: root.querySelector('.p-select-label')?.textContent?.trim() ?? ''
    };
}

describe('drop-down lists and window resizes (browser zoom)', () => {
    it('keeps the open list open when the window is resized — zooming in to read it no longer closes it', async () => {
        const after = await openThenResize(true);

        expect(after.open).toBe(true);
        expect(after.chosen).toBe('SECURITY_CHAMPION');
        expect(after.label).toBe('Security champion');
    });

    // The library's default, kept here so that the case above is known to be able to fail: if a
    // later Optimus stopped closing on resize, or stopped binding the listener in this
    // environment, the first case would pass for a reason of its own.
    it("closes it under the library's default, and even then the chosen value stays", async () => {
        const after = await openThenResize(false);

        expect(after.open).toBe(false);
        expect(after.chosen).toBe('SECURITY_CHAMPION');
        expect(after.label).toBe('Security champion');
    });

    it('moves the panel back under its field instead of closing it', () => {
        const overlay = { alignOverlay: vi.fn() };

        expect(keepOpenOnResize.call(overlay, new Event('resize'), { type: 'resize', valid: true })).toBe(false);
        expect(overlay.alignOverlay).toHaveBeenCalledTimes(1);
    });

    it('leaves every other reason to close as the library decides it', () => {
        const overlay = { alignOverlay: vi.fn() };

        expect(keepOpenOnResize.call(overlay, new Event('click'), { type: 'outside', valid: true })).toBe(true);
        expect(keepOpenOnResize.call(overlay, new Event('click'), { type: 'outside', valid: false })).toBe(false);
        expect(keepOpenOnResize.call(overlay, new Event('scroll'), { type: 'scroll', valid: true })).toBe(true);
        expect(overlay.alignOverlay).not.toHaveBeenCalled();
    });

    // The cases above give the options to the component by hand; this one is what makes them the
    // application's. Without it, dropping the line from `app.config.ts` would leave every case green.
    it('is what the application gives Optimus', () => {
        // The testing backend after the application's own: its initializer fetches the dictionaries.
        TestBed.configureTestingModule({ providers: [...appConfig.providers, provideHttpClientTesting()] });

        expect(TestBed.inject(Optimus).overlayOptions.listener).toBe(keepOpenOnResize);
    });
});
