import type { OverlayListenerOptions, OverlayOptions } from '@openng/optimus-ui/api';
import type { Overlay } from '@openng/optimus-ui/overlay';

/**
 * An open drop-down list stays open when the window is resized, and follows its field.
 *
 * <p><b>Reported from Safari as "the selections in the combo boxes disappear when I zoom".</b>
 * The chosen value never moved: a WebKit run choosing a value and then resizing, zooming the
 * root element, pressing ⌘= over an open list and resizing again kept the label every time, in
 * a dialog form bound both ways and in a table row bound one way. What disappeared was the
 * *list*. Optimus' `Overlay` listens to `window` `resize` while a panel is open and closes it on
 * any resize from a non-touch device, and browser zoom (⌘+ / ⌘−) is a resize: the viewport's
 * width in CSS pixels changes. Open the list, zoom in to read it, and it was gone — the very gesture a person
 * who needs a larger text makes is the one that took the list away (WCAG 1.4.4).
 *
 * <p><b>Closing was the library's answer to a stale position, not a rule about lists.</b> A
 * panel placed in page coordinates (`appendTo="body"`, in the dialogs) would float away from a
 * field that a resize had moved. Repositioning answers the same problem without throwing away
 * what the person was doing — and the library itself already keeps panels open on resize for
 * touch devices, where the on-screen keyboard resizes the window all the time.
 *
 * <p>Every other reason to close is left as it was: a click outside, Escape, and a scroll of an
 * ancestor — a scroll moves the field relative to a body-attached panel just as a resize does,
 * but a person scrolling has turned to something else; a person zooming has not.
 *
 * <p><b>A plain `function`, on purpose.</b> `Overlay` calls the listener as `this.listener(...)`,
 * so `this` is the overlay whose panel is open and `alignOverlay()` is its public method. An
 * arrow function would lose it, and the panel would stay open at the wrong place.
 */
export function keepOpenOnResize(
    this: Pick<Overlay, 'alignOverlay'> | void,
    _event: Event,
    options?: OverlayListenerOptions
): boolean {
    if (options?.type !== 'resize') {
        return options?.valid ?? true;
    }
    this?.alignOverlay();
    return false;
}

/** Given to `provideOptimus`: every `p-select`, `p-multiselect`, date picker… shares one overlay. */
export const OVERLAY_OPTIONS: OverlayOptions = { listener: keepOpenOnResize };
