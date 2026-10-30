import type { I18nService } from './i18n/i18n.service';
import { keyFor } from './i18n/literal-keys';
import type { ProblemWords } from './api-error';

/**
 * The sentence of each problem `code` (docs-site/reference/errors.md), with literal keys (decision 0019).
 *
 * **The bundle decides how much of `detail` to keep.** Where the code says all there is to say — a
 * credential refused, a scan already queued — the sentence is the code's, in the reader's language.
 * Where `detail` carries the one fact that matters — the value refused by an `invalid-request`, the
 * ceiling of a `content-too-large` — the sentence quotes it as `{{detail}}`, which is English: a
 * translated lead with the server's specifics beats a translated sentence that dropped them. The
 * English bundle quotes `detail` whole for every code, since the server already wrote it in English,
 * for this request, more precisely than a sentence per code can.
 *
 * **The three `integration-*` codes have an English sentence of their own**, the one exception to quoting
 * `detail`: the server's sentence names `PUT /api/v1/integrations/{key}/enabled`, written before the screen
 * existed, and a reader of this interface is better sent to *Administration → Integrations*. Each quotes the
 * key the problem names in `integration`.
 *
 * A code missing here — a conflict's own cause (`target-already-registered`), an `http-<status>`, a
 * code a newer server added — reads `detail` as sent: codes are open (decision 0043 §1).
 */
export const PROBLEM_KEYS = {
    'invalid-request': 'problem.invalid_request',
    'authentication-required': 'problem.authentication_required',
    forbidden: 'problem.forbidden',
    'credential-not-accepted': 'problem.credential_not_accepted',
    'password-change-required': 'problem.password_change_required',
    'import-refused': 'problem.import_refused',
    'not-found': 'problem.not_found',
    'no-such-route': 'problem.no_such_route',
    'method-not-allowed': 'problem.method_not_allowed',
    'not-acceptable': 'problem.not_acceptable',
    'unsupported-media-type': 'problem.unsupported_media_type',
    conflict: 'problem.conflict',
    'already-queued': 'problem.already_queued',
    'not-attestable': 'problem.not_attestable',
    'solution-not-empty': 'problem.solution_not_empty',
    'plugin-conflict': 'problem.plugin_conflict',
    'integration-disabled': 'problem.integration_disabled',
    'integration-in-use': 'problem.integration_in_use',
    'integration-not-switchable': 'problem.integration_not_switchable',
    'precondition-failed': 'problem.precondition_failed',
    'encryption-key-missing': 'problem.encryption_key_missing',
    'credential-withheld': 'problem.credential_withheld',
    'content-too-large': 'problem.content_too_large',
    'unsafe-url': 'problem.unsafe_url',
    unprocessable: 'problem.unprocessable',
    'rate-limited': 'problem.rate_limited',
    'unexpected-failure': 'problem.unexpected_failure',
    unavailable: 'problem.unavailable'
} as const;

/**
 * The codes whose sentence quotes a member of its own: without it the sentence would print the
 * placeholder, so the server's `detail` — which carries the same fact — is shown instead.
 */
const NEEDS: Partial<Record<keyof typeof PROBLEM_KEYS, keyof ProblemWords>> = {
    'rate-limited': 'retryAfterSeconds',
    'unexpected-failure': 'correlationId',
    'integration-disabled': 'integration',
    'integration-in-use': 'integration',
    'integration-not-switchable': 'integration'
};

export function problemSentence(i18n: Pick<I18nService, 't'>, problem: ProblemWords): string | undefined {
    const key = keyFor(PROBLEM_KEYS, problem.code);
    if (!key) return undefined;
    const needed = NEEDS[problem.code as keyof typeof PROBLEM_KEYS];
    if (needed && problem[needed] === undefined) return undefined;
    const sentence = i18n.t(key, {
        detail: problem.detail,
        retryAfterSeconds: problem.retryAfterSeconds ?? '',
        correlationId: problem.correlationId ?? '',
        integration: problem.integration ?? ''
    });
    // A bundle not loaded yet answers the key itself: the server's sentence is better than a path.
    return sentence === key ? undefined : sentence;
}
