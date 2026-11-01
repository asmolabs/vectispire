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
import {
    BUTTON_SEVERITIES,
    MESSAGE_SEVERITIES,
    READABLE_BUTTONS,
    READABLE_COMPONENTS,
    READABLE_MESSAGES,
    contrast
} from '../readable-palette';

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
    it('draws primary and muted text readable on white and on the page in the light scheme, for every choice', async () => {
        const { fixture, layout } = mount();
        await fixture.whenStable();
        const configurator = fixture.componentInstance;
        for (const preset of ['Aura', 'Nora'] as const) {
            await configurator.onPresetChange(preset);
            for (const surface of [undefined, ...configurator.surfaces]) {
                const page = surface?.palette?.[100] ?? Aura.primitive!.slate![100]!;
                for (const choice of configurator.primaryColors().filter((c) => c.name !== 'noir')) {
                    const label = `${preset}/${surface?.name ?? 'default'}/${choice.name}`;
                    layout.layoutConfig.update((state) => ({
                        ...state,
                        primary: choice.name!,
                        surface: surface?.name ?? null
                    }));
                    const light = configurator.getPresetExt().semantic.colorScheme.light as {
                        primary: { color: string };
                        text: { mutedColor: string };
                    };
                    const muted = /^\{surface\.(\d+)\}$/.exec(light.text.mutedColor)![1] as '600';
                    const surfacePalette = surface?.palette ?? Aura.primitive!.slate!;
                    expect(contrast(surfacePalette[muted]!, page), label).toBeGreaterThanOrEqual(4.5);
                    const shade = /^\{primary\.(\d+)\}$/.exec(light.primary.color)![1] as '700';
                    const colour = choice.palette![shade]!;
                    // White on a primary button, and primary text on a card or on the page.
                    expect(contrast(colour, '#ffffff'), label).toBeGreaterThanOrEqual(4.5);
                    expect(contrast(colour, page), label).toBeGreaterThanOrEqual(4.5);
                }
            }
        }
    });
    it('draws the severity buttons and messages readable in the light scheme, and keeps them through every choice', async () => {
        const { fixture, layout } = mount();
        await fixture.whenStable();
        const configurator = fixture.componentInstance;
        const page = Aura.primitive!.slate![100]!;
        const shade = (token: string) => {
            const [, palette, step] = /^\{(\w+)\.(\d+)\}$/.exec(token)!;
            return (Aura.primitive as Record<string, Record<string, string>>)[palette][step];
        };
        const light = READABLE_BUTTONS.button.colorScheme.light;
        for (const severity of Object.keys(BUTTON_SEVERITIES) as (keyof typeof BUTTON_SEVERITIES)[]) {
            // White on the solid button; the colour on a card or the page for outlined and text.
            expect(contrast(shade(light.root[severity]['background']), '#ffffff'), severity).toBeGreaterThanOrEqual(
                4.5
            );
            for (const variant of [light.outlined, light.text]) {
                expect(contrast(shade(variant[severity]['color']), '#ffffff'), severity).toBeGreaterThanOrEqual(4.5);
                expect(contrast(shade(variant[severity]['color']), page), severity).toBeGreaterThanOrEqual(4.5);
            }
        }
        // A message's text on its own 50 tint, as Aura mixes it (5% transparent over a white card).
        for (const [severity, palette] of Object.entries(MESSAGE_SEVERITIES)) {
            const colour = shade(READABLE_MESSAGES.message.colorScheme.light[severity as 'info'].color);
            const tint = (Aura.primitive as Record<string, Record<string, string>>)[palette]['50'];
            expect(contrast(colour, tint), severity).toBeGreaterThanOrEqual(4.5);
        }
        // The configurator rebuilds the theme from the preset on every choice: without the buttons in
        // its extension, the first click would put Aura's back.
        for (const preset of ['Aura', 'Nora'] as const) {
            await configurator.onPresetChange(preset);
            for (const choice of configurator.primaryColors()) {
                layout.layoutConfig.update((state) => ({ ...state, primary: choice.name! }));
                expect(configurator.getPresetExt().components, `${preset}/${choice.name}`).toBe(READABLE_COMPONENTS);
            }
        }
    });
});
