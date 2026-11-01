import { DOCUMENT } from '@angular/common';
import { DestroyRef, Injectable, inject } from '@angular/core';

/**
 * Gives focus back to whatever opened a dialog, once the last dialog has closed (WCAG 2.4.3).
 *
 * <p><b>Optimus traps focus inside a dialog but drops it when the dialog goes:</b> the focused element
 * is removed with the dialog, focus falls to `<body>`, and a keyboard reader starts again from the top
 * of the page after every save, cancel or Escape. Sixty-odd dialogs would each need the same three
 * lines; this does it once, for all of them, the confirmation dialogs included.
 *
 * <p>The opener is the last element focused outside any dialog. Focus is only given back when a dialog
 * has just disappeared and nothing holds focus — never on another change of the page, where moving
 * focus would take it from someone who had put it somewhere on purpose — and only to an opener still on
 * the page: a row's button redrawn by the save that closed the dialog is a different button.
 */
@Injectable({ providedIn: 'root' })
export class DialogFocusReturn {
    private readonly document = inject(DOCUMENT);
    private readonly destroyRef = inject(DestroyRef);
    private opener: HTMLElement | null = null;
    private dialogOpen = false;

    start(): void {
        const body = this.document.body;
        const onFocus = (event: FocusEvent) => {
            const target = event.target;
            if (target instanceof HTMLElement && !target.closest('.p-dialog')) this.opener = target;
        };
        this.document.addEventListener('focusin', onFocus, true);
        const observer = new MutationObserver(() => {
            const open = this.document.querySelector('.p-dialog') !== null;
            const active = this.document.activeElement;
            if (this.dialogOpen && !open && (active === null || active === body) && this.opener?.isConnected) {
                this.opener.focus();
            }
            this.dialogOpen = open;
        });
        observer.observe(body, { childList: true, subtree: true });
        this.destroyRef.onDestroy(() => {
            observer.disconnect();
            this.document.removeEventListener('focusin', onFocus, true);
        });
    }
}
