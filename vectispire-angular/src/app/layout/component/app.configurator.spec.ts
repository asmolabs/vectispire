import { provideHttpClient } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import Aura from '@openng/optimus-ui-themes/aura';
import Lara from '@openng/optimus-ui-themes/lara';
import Nora from '@openng/optimus-ui-themes/nora';
import { provideOptimus } from '@openng/optimus-ui/config';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { LayoutService } from '@/app/layout/service/layout.service';
import { AppConfigurator, PRESETS } from './app.configurator';

/**
 * The theme presets other than the starting one arrive when they are chosen, not with the shell.
 *
 * What must survive the move: the choice shows at once, the swatches follow the preset once it has
 * arrived, and of two choices made in quick succession the last one is the one applied — a slow
 * download finishing late must not undo the reader's second click.
 */
describe('the appearance configurator', () => {
    afterEach(() => {
        vi.restoreAllMocks();
        TestBed.resetTestingModule();
    });

    /** Aura with its emerald shade 500 replaced, so the swatch says which preset it was drawn from. */
    const marked = (shade: string): typeof Aura => ({
        ...Aura,
        primitive: { ...Aura.primitive, emerald: { ...Aura.primitive?.emerald, 500: shade } }
    });

    const mount = () => {
        TestBed.configureTestingModule({
            imports: [AppConfigurator],
            providers: [provideHttpClient(), provideRouter([]), provideOptimus({ theme: { preset: Aura } })]
        });
        const fixture = TestBed.createComponent(AppConfigurator);
        fixture.detectChanges();
        const emerald = () =>
            fixture.componentInstance.primaryColors().find((c) => c.name === 'emerald')?.palette?.[500];
        return { fixture, emerald, layout: TestBed.inject(LayoutService) };
    };

    it('starts on Aura, which the application boots with', async () => {
        const { fixture, emerald } = mount();
        await fixture.whenStable();
        expect(fixture.componentInstance.selectedPreset()).toBe('Aura');
        expect(emerald()).toBe(Aura.primitive?.emerald?.[500]);
    });

    it('fetches each preset under its own name', async () => {
        expect(await PRESETS.Aura()).toBe(Aura);
        expect(await PRESETS.Lara()).toBe(Lara);
        expect(await PRESETS.Nora()).toBe(Nora);
    });

    it('shows the choice at once, and draws its palettes once it has arrived', async () => {
        let arrive: (preset: typeof Aura) => void = () => undefined;
        vi.spyOn(PRESETS, 'Lara').mockReturnValue(new Promise((resolve) => (arrive = resolve)));
        const { fixture, emerald } = mount();
        await fixture.whenStable();

        const choice = fixture.componentInstance.onPresetChange('Lara');
        expect(fixture.componentInstance.selectedPreset()).toBe('Lara');
        expect(emerald()).toBe(Aura.primitive?.emerald?.[500]);

        arrive(marked('#000001'));
        await choice;
        expect(emerald()).toBe('#000001');
    });

    it('applies the last choice when an earlier one arrives after it', async () => {
        let arrive: (preset: typeof Aura) => void = () => undefined;
        vi.spyOn(PRESETS, 'Lara').mockReturnValue(new Promise((resolve) => (arrive = resolve)));
        vi.spyOn(PRESETS, 'Nora').mockResolvedValue(marked('#000002'));
        const { fixture, emerald, layout } = mount();
        await fixture.whenStable();

        const slow = fixture.componentInstance.onPresetChange('Lara');
        expect(layout.layoutConfig().preset).toBe('Lara');
        await fixture.componentInstance.onPresetChange('Nora');
        expect(emerald()).toBe('#000002');

        arrive(marked('#000001'));
        await slow;
        expect(layout.layoutConfig().preset).toBe('Nora');
        expect(emerald()).toBe('#000002');
    });
});
