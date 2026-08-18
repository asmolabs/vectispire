package com.asmolabs.zanshin.common.domain.net;

/**
 * What kind of destination a given setting is allowed to name.
 *
 * <p>Three named policies rather than two booleans. The original carried
 * {@code allowPrivate} and {@code requirePrivate}, which spells four states for three
 * meanings — and the fourth, {@code (allowPrivate: false, requirePrivate: true)}, asks for a
 * destination that must be internal and may not be. It could be written, it read as
 * plausible, and it refused every URL. Here it cannot be written.
 */
public enum OutboundPolicy {

    /**
     * Public destinations only — the notification webhook.
     *
     * <p>Anything internal is refused, link-local first among them.
     */
    PUBLIC_ONLY,

    /**
     * Private and loopback accepted — the local scan side-car.
     *
     * <p>But <b>never link-local</b>. Nothing legitimate lives in {@code 169.254.0.0/16}, and
     * that is precisely the address the attack wants: the instance metadata endpoint hands out
     * the host's credentials to whoever asks.
     */
    INTERNAL_ALLOWED,

    /**
     * Internal destinations only — the Ollama server.
     *
     * <p><b>The mirror image, and the one that is easy to miss.</b> Ollama receives the scanned
     * repository's <em>source code</em>. The risk is not that the URL points inward, it is that
     * it points <em>outward</em>: a well-formed public URL is exactly what an exfiltration
     * channel looks like, and no anti-SSRF check would flag it.
     */
    INTERNAL_REQUIRED
}
