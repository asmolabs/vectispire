import { provideHttpClient, withXhr } from '@angular/common/http';
import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { messageOf, translateProblemsWith } from './api-error';
import { I18nService } from './i18n/i18n.service';
import { PROBLEM_KEYS } from './problem-codes';
import { missingFromBundles } from './testing/bundles';
import { useEnglish, useFrench } from './testing/english';

/**
 * A refusal in the reader's language, from the problem's `code` (decision 0043 §6). The French
 * interface printed the English `detail` of every refusal the server explained.
 */
describe('a problem document in words', () => {
    const refused = (code: string, detail: string, more: Record<string, unknown> = {}) => ({
        status: 400,
        error: { title: 'Bad Request', status: 400, code, detail, ...more }
    });

    beforeEach(() => {
        TestBed.configureTestingModule({ providers: [provideHttpClient(withXhr())] });
        // The service registers the translation as it is built; every screen builds it.
        TestBed.inject(I18nService);
    });

    afterEach(() => translateProblemsWith(undefined));

    it('has a sentence in both bundles for every code it knows', () => {
        expect(missingFromBundles(Object.values(PROBLEM_KEYS))).toEqual([]);
    });

    it('speaks French for a code that says it all', () => {
        useFrench();

        expect(messageOf(refused('already-queued', 'A scan is already queued for this repository.'), 'x')).toBe(
            "Une analyse de cette cible est déjà en file d'attente."
        );
        expect(messageOf(refused('rate-limited', 'Too many attempts.', { retryAfterSeconds: 30 }), 'x')).toBe(
            'Trop de tentatives. Réessayez dans 30 secondes.'
        );
    });

    it("keeps the server's specifics where they are the point", () => {
        // An `invalid-request` without the value it refused would tell the reader nothing to correct.
        useFrench();

        expect(
            messageOf(refused('invalid-request', 'Scheme "ftp" is not allowed. Expected https, ssh or git.'), 'x')
        ).toBe('Requête refusée — le serveur précise : Scheme "ftp" is not allowed. Expected https, ssh or git.');
    });

    it('quotes the detail as it is, a replacement pattern included', () => {
        useFrench();

        expect(messageOf(refused('conflict', 'Costs $& and $1.'), 'x')).toContain('Costs $& and $1.');
    });

    it("reads the server's sentence for a code it does not know, or one missing the value it quotes", () => {
        // Codes are open (decision 0043 §1); a conflict's own cause is a code of its own.
        useFrench();

        expect(messageOf(refused('target-already-registered', 'This repository is already registered.'), 'x')).toBe(
            'This repository is already registered.'
        );
        expect(messageOf(refused('unexpected-failure', 'Unexpected failure.'), 'x')).toBe('Unexpected failure.');
    });

    it("shows the English interface the server's own sentence", () => {
        useEnglish();

        expect(messageOf(refused('not-found', 'No repository 12.'), 'x')).toBe('No repository 12.');
    });

    it('falls back on detail when no translation is registered', () => {
        translateProblemsWith(undefined);

        expect(messageOf(refused('already-queued', 'A scan is already queued.'), 'x')).toBe(
            'A scan is already queued.'
        );
    });
});
