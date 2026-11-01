import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DialogFocusReturn } from './dialog-focus-return';

/** A mutation observer reports after the current task's microtasks: wait for it. */
const observed = () => new Promise((resolve) => setTimeout(resolve));

describe('focus given back after a dialog', () => {
    let opener: HTMLButtonElement;

    beforeEach(() => {
        TestBed.inject(DialogFocusReturn).start();
        opener = document.createElement('button');
        opener.textContent = 'Create';
        document.body.append(opener);
    });

    afterEach(() => {
        document.body.replaceChildren();
        TestBed.resetTestingModule();
    });

    const openDialog = async () => {
        const dialog = document.createElement('div');
        dialog.className = 'p-dialog';
        const field = document.createElement('input');
        dialog.append(field);
        document.body.append(dialog);
        field.focus();
        await observed();
        return dialog;
    };

    it('returns focus to the button that opened the dialog once it closes', async () => {
        opener.focus();
        const dialog = await openDialog();
        expect(document.activeElement).not.toBe(opener);

        dialog.remove();
        await observed();
        expect(document.activeElement).toBe(opener);
    });

    it('leaves focus alone on a change of the page with no dialog closing', async () => {
        opener.focus();
        opener.blur();
        document.body.append(document.createElement('p'));
        await observed();
        expect(document.activeElement).toBe(document.body);
    });

    it('gives nothing back to an opener the page has since removed', async () => {
        opener.focus();
        const dialog = await openDialog();
        opener.remove();
        dialog.remove();
        await observed();
        expect(document.activeElement).toBe(document.body);
    });
});
