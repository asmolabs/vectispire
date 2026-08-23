/**
 * The message a refused request carries.
 *
 * **One place that knows the shape of an error, instead of twenty-three that guess it.** Every
 * screen used to read `response.error.message` — a field the server does not send. Spring
 * answers in RFC 7807 Problem Details, where the sentence lives under `detail`:
 *
 * ```json
 * { "detail": "Scheme \"\" is not allowed. Expected https, ssh or git.",
 *   "title": "Bad Request", "status": 400 }
 * ```
 *
 * So every refusal the server took care to explain — a malformed URL, an unreadable key, "a scan
 * is already queued", "you cannot remove your own privileges" — was replaced by whatever generic
 * fallback the call site happened to hold. Nothing failed and nothing was logged; the most useful
 * sentence on the screen simply never appeared. The comments at those call sites all said the
 * opposite, which is how it survived: the intent was right and the field was wrong.
 *
 * `message` is still read after `detail`, because a plain `{ "message": … }` is what a hand-built
 * error body looks like and there is no reason to refuse one.
 */
export function messageOf(response: unknown, fallback: string): string {
    const body = (response as { error?: unknown } | null)?.error;

    // A `responseType: 'blob'` request fails with a Blob body, not JSON. Reading it needs an
    // async call the caller cannot make here, so the fallback is the honest answer.
    if (typeof body === 'string') {
        return body.trim() || fallback;
    }
    if (body && typeof body === 'object') {
        const problem = body as { detail?: unknown; message?: unknown };
        const detail = typeof problem.detail === 'string' ? problem.detail.trim() : '';
        if (detail) return detail;

        const message = typeof problem.message === 'string' ? problem.message.trim() : '';
        if (message) return message;
    }
    return fallback;
}
