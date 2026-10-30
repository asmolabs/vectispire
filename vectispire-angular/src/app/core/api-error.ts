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
    const translated = translateProblem(response);
    if (translated) return translated;

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

/**
 * A problem document as the translation reads it: the token, and the values a sentence may quote.
 */
export interface ProblemWords {
    code: string;
    detail: string;
    retryAfterSeconds?: number;
    correlationId?: string;
}

/** Answers a sentence for a code it knows, nothing for one it does not. */
export type ProblemTranslator = (problem: ProblemWords) => string | undefined;

let translator: ProblemTranslator | undefined;

/**
 * Lets the interface's language speak for the server's `detail` (decision 0019).
 *
 * **Since 0.11.0 every problem carries `code`** (decision 0043 §6), and the French interface still
 * printed the English `detail` of every refusal. The translator is registered once by `I18nService`
 * rather than passed to each of the eighty call sites of {@link messageOf}: those sites already hand
 * it the response, and a screen that forgot to pass a translator would show English again with
 * nothing failing. Without one — a unit test that builds no service — `detail` is shown, as before.
 */
export function translateProblemsWith(next: ProblemTranslator | undefined): void {
    translator = next;
}

function translateProblem(response: unknown): string | undefined {
    if (!translator) return undefined;
    const body = (response as { error?: unknown } | null)?.error;
    if (!body || typeof body !== 'object') return undefined;
    const problem = body as { code?: unknown; detail?: unknown; retryAfterSeconds?: unknown; correlationId?: unknown };
    if (typeof problem.code !== 'string' || typeof problem.detail !== 'string' || !problem.detail.trim()) {
        return undefined;
    }
    const sentence = translator({
        code: problem.code,
        detail: problem.detail.trim(),
        retryAfterSeconds: typeof problem.retryAfterSeconds === 'number' ? problem.retryAfterSeconds : undefined,
        correlationId: typeof problem.correlationId === 'string' ? problem.correlationId : undefined
    });
    return sentence?.trim() || undefined;
}
