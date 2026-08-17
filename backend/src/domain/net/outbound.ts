/**
 * Zanshin's outbound call, with the policy that goes with it.
 *
 * **`validateOutboundUrl` only protects the first request.** Node follows redirects by
 * default: a validated destination answering `302 Location: http://169.254.169.254/` is
 * followed with nothing re-checking anything, and the whole URL guard falls. Verified by
 * standing up two local servers — the request did reach the internal target.
 *
 * The costliest case is not the webhook but **the model review**: its guard demands an
 * internal destination precisely because it receives the scanned repository's source code. A
 * redirect outward would make it a perfectly silent exfiltration channel, well formed, and
 * invisible to any anti-SSRF check done upstream.
 *
 * **One single definition, so the sixth call inherits the rule.** It was missing from all
 * five existing calls — every one of them needed it, none had it — and copying it five times
 * would have guaranteed the next one goes without.
 *
 * Refusing rather than re-issuing to the new address: an endpoint that redirects is
 * misconfigured, and the error names the problem where silently following would hide it.
 */

/** What every outbound Zanshin request carries, whatever its destination. */
export interface OutboundRequest {
    method?: string;
    body?: unknown;
    headers?: Record<string, string>;
    timeoutMs: number;
}

/**
 * Issues the request and returns the response. **Throws on a redirect as on an error
 * status** — the caller decides whether that is fatal.
 */
export async function outboundFetch(url: string, request: OutboundRequest): Promise<Response> {
    const { method = 'GET', body, headers = {}, timeoutMs } = request;

    const response = await fetch(url, {
        method,
        headers: body === undefined ? headers : { 'content-type': 'application/json', ...headers },
        body: body === undefined ? undefined : JSON.stringify(body),
        // The line that carries this module's entire point.
        redirect: 'error',
        signal: AbortSignal.timeout(timeoutMs)
    });

    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response;
}

/** The same, when the response is JSON we want to read. */
export async function outboundJson<T>(url: string, request: OutboundRequest): Promise<T> {
    return (await outboundFetch(url, request)).json() as Promise<T>;
}
