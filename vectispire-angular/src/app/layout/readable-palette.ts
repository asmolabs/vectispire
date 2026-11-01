/**
 * The light scheme's tokens that text is drawn with, darkened to meet WCAG 2.2 AA (4.5:1).
 *
 * <p><b>The presets' defaults fail it on every screen.</b> Aura draws the primary colour at shade 500
 * — emerald 500 on white is 2.5:1, and white on an emerald button the same — and muted text at
 * surface 500, 4.3:1 on the page's surface-100 background. Shade 700 passes for the primary on white
 * and on the page for every palette but yellow, which needs 800, and surface 600 for muted text on every
 * surface but soho, which needs 700 — so each shade is worked out rather than written down. The dark scheme
 * already draws both light on dark and passes.
 *
 * <p>Applied twice, because the theme is: at boot (`app.config.ts`), and by the configurator each time
 * it rebuilds the preset from a choice, which would otherwise put the defaults back.
 */

/** Slate 100, the page behind the cards when no other surface has been chosen. */
const DEFAULT_PAGE = '#f1f5f9';

/** WCAG's contrast ratio between two `#rrggbb` colours. */
export function contrast(a: string, b: string): number {
    const luminance = (hex: string) => {
        const [r, g, bl] = [1, 3, 5].map((i) => {
            const c = parseInt(hex.slice(i, i + 2), 16) / 255;
            return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
        });
        return 0.2126 * r + 0.7152 * g + 0.0722 * bl;
    };
    const [high, low] = [luminance(a), luminance(b)].sort((x, y) => y - x);
    return (high + 0.05) / (low + 0.05);
}

/**
 * The primary tokens for a palette: its lightest shade from 700 that reads at 4.5:1 on white — the
 * cards, and under white text on a button — and on the page.
 */
export function readableLightPrimary(palette?: Record<string, string | undefined>, page = DEFAULT_PAGE) {
    const readable = (shade: number) => {
        const colour = palette?.[shade];
        return !colour || (contrast(colour, '#ffffff') >= 4.5 && contrast(colour, page) >= 4.5);
    };
    const shade = readable(700) ? 700 : 800;
    return {
        color: `{primary.${shade}}`,
        contrastColor: '#ffffff',
        hoverColor: `{primary.${shade + 100}}`,
        activeColor: shade === 700 ? '{primary.900}' : '{primary.950}'
    };
}

/** Muted text in the lightest surface shade from 600 that reads at 4.5:1 on the page (surface 100). */
export function readableLightText(surface?: Record<string, string | undefined>) {
    const muted = surface?.[600];
    const page = surface?.[100] ?? DEFAULT_PAGE;
    return { mutedColor: !muted || contrast(muted, page) >= 4.5 ? '{surface.600}' : '{surface.700}' };
}

/** The severities a button can take, and the palette each is drawn from. */
export const BUTTON_SEVERITIES = {
    success: 'green',
    info: 'sky',
    warn: 'orange',
    help: 'purple',
    danger: 'red'
} as const;

/**
 * The light scheme's severity buttons at shade 700, for the same reason as the primary: Aura draws
 * them at 500 — white on red 500 is 3.8:1, orange 500 text on the page 2.6:1 — and shade 700 of each
 * passes, solid (white on it), outlined and text (it on white or on the page). Secondary text and
 * outlined buttons take surface 600, like muted text.
 */
export const READABLE_BUTTONS = (() => {
    const root: Record<string, Record<string, string>> = {};
    const outlined: Record<string, Record<string, string>> = { secondary: { color: '{surface.600}' } };
    const text: Record<string, Record<string, string>> = { secondary: { color: '{surface.600}' } };
    for (const [severity, palette] of Object.entries(BUTTON_SEVERITIES)) {
        root[severity] = {
            background: `{${palette}.700}`,
            hoverBackground: `{${palette}.800}`,
            activeBackground: `{${palette}.900}`,
            borderColor: `{${palette}.700}`,
            hoverBorderColor: `{${palette}.800}`,
            activeBorderColor: `{${palette}.900}`
        };
        outlined[severity] = { color: `{${palette}.700}` };
        text[severity] = { color: `{${palette}.700}` };
    }
    return { button: { colorScheme: { light: { root, outlined, text } } } };
})();

/** The severities a message can take, and the palette each is drawn from. */
export const MESSAGE_SEVERITIES = { info: 'blue', success: 'green', warn: 'yellow', error: 'red' } as const;

/**
 * Messages' text at shade 700 in the light scheme: Aura writes it at 600 on the 50 tint, and yellow 600
 * there is 2.8:1, green 600 3.1:1. The outlined and simple variants draw the same colour on the page.
 */
export const READABLE_MESSAGES = (() => {
    type Tokens = { color: string; outlined: { color: string }; simple: { color: string } };
    const light = {} as Record<keyof typeof MESSAGE_SEVERITIES, Tokens>;
    for (const severity of Object.keys(MESSAGE_SEVERITIES) as (keyof typeof MESSAGE_SEVERITIES)[]) {
        const colour = `{${MESSAGE_SEVERITIES[severity]}.700}`;
        light[severity] = { color: colour, outlined: { color: colour }, simple: { color: colour } };
    }
    return { message: { colorScheme: { light } } };
})();

/** Every component token this palette replaces, handed to the theme at boot and by the configurator. */
export const READABLE_COMPONENTS = { ...READABLE_BUTTONS, ...READABLE_MESSAGES };

/** The extension the application starts with: Aura, its emerald, its slate. */
export function readablePreset(palette?: Record<string, string | undefined>) {
    return {
        semantic: { colorScheme: { light: { primary: readableLightPrimary(palette), text: readableLightText() } } },
        components: READABLE_COMPONENTS
    };
}
