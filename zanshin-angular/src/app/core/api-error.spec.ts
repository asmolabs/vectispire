import { describe, expect, it } from 'vitest';
import { messageOf } from './api-error';

/**
 * The field a refusal actually arrives in.
 *
 * Every screen read `error.message`, which the server never sends: Spring answers in RFC 7807,
 * where the sentence is `detail`. Nothing failed — the fallback simply replaced every explanation
 * the server had taken care to write. These cases are the real shapes, taken from the running
 * application, so the next person changing this reads what the server does rather than what a
 * call site assumed.
 */
describe('the message a refused request carries', () => {
    it('reads RFC 7807 detail, which is what the server sends', () => {
        const refusal = {
            error: {
                detail: 'Scheme "" is not allowed. Expected https, ssh or git.',
                title: 'Bad Request',
                status: 400
            }
        };

        expect(messageOf(refusal, 'Could not add this repository.')).toBe(
            'Scheme "" is not allowed. Expected https, ssh or git.'
        );
    });

    it('still reads a plain message, because a hand-built body looks like that', () => {
        expect(messageOf({ error: { message: 'A scan is already queued.' } }, 'fallback')).toBe(
            'A scan is already queued.'
        );
    });

    it('prefers detail when both are present', () => {
        // Not arbitrary: `detail` is what this server produces, and a body carrying both is a
        // body somebody is in the middle of changing.
        expect(messageOf({ error: { detail: 'precise', message: 'vague' } }, 'fallback')).toBe('precise');
    });

    it('falls back when the body says nothing useful', () => {
        // A network failure has no body at all; a blank detail is worse than the fallback,
        // because an empty error box reads as "nothing happened".
        expect(messageOf({ status: 0 }, 'Server unreachable.')).toBe('Server unreachable.');
        expect(messageOf({ error: { detail: '   ' } }, 'Saving failed.')).toBe('Saving failed.');
        expect(messageOf(null, 'The deletion failed.')).toBe('The deletion failed.');
    });

    it('handles a string body, which is what a blob request fails with', () => {
        // The export buttons ask for `responseType: 'blob'`; their failures do not arrive as
        // parsed JSON, and reading `.detail` off a string would silently give the fallback.
        expect(messageOf({ error: 'Upstream is unreachable.' }, 'fallback')).toBe('Upstream is unreachable.');
    });
});
