import { describe, expect, it } from 'vitest';
import type { AuditVerification, AuthenticatedUser, Refine, Schema, TeamSummary, UserList } from './api.models';

/**
 * What the hand-written claims in `api.models.ts` are still checked against.
 *
 * Those claims exist because the document says less than the server does: it marks no property
 * nullable, and marks only primitives as always sent. Each claim is therefore written by a person,
 * and a claim nobody checks is the failure this whole conversion is meant to end — the screen that
 * kept compiling against a field the API had renamed.
 *
 * `Refine` is what checks them, and these cases say what it catches — the real one, imported
 * rather than restated, so that loosening it there fails here. They are compile-time assertions: a
 * `@ts-expect-error` that stops being an error fails `tsc`, so this file failing to typecheck *is*
 * the test. The runtime expectations below only give the runner something to report.
 */
describe('the claims the client makes about shapes the document under-describes', () => {
    it('rejects a claim about a property the schema does not have', () => {
        // @ts-expect-error `TeamSummary.name` was not renamed to `nom` — and if it ever is, the
        // claim below stops being an error and this test fails, which is the point.
        type Renamed = Refine<Schema<'TeamSummary'>, { nom: string }>;

        expect(true satisfies boolean).toBe(true);
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-type-assertion -- the reference keeps the type alive
        return undefined as unknown as Renamed | undefined;
    });

    it('rejects a scalar claim the schema could not hold', () => {
        // @ts-expect-error `name` is a string in the document; claiming it is a number would make
        // every screen that reads it compile against something the server never sends.
        type Retyped = Refine<Schema<'TeamSummary'>, { name: number }>;

        expect(true satisfies boolean).toBe(true);
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-type-assertion -- the reference keeps the type alive
        return undefined as unknown as Retyped | undefined;
    });

    it('accepts widening a property to null, which is the claim the document cannot make', () => {
        const team: TeamSummary = {
            id: 4,
            name: 'plateforme',
            description: null,
            memberCount: 0,
            targetCount: 0,
            notified: false
        };
        const user: AuthenticatedUser = {
            username: 'c.moreau',
            role: 'USER',
            displayName: null,
            mustChangePassword: false,
            mfaEnabled: false
        };
        const broken: AuditVerification['broken'] = null;

        expect([team.description, user.displayName, broken]).toEqual([null, null, null]);
    });

    it('carries a refined type through a nested one', () => {
        const listing: UserList = { users: [], currentUserId: null };

        // `users` is `UserSummary[]`, not the document's looser shape: reading `email` off an
        // element gives `string | null` rather than `string | undefined`.
        expect(listing.users.map((account) => account.email)).toEqual([]);
    });
});
