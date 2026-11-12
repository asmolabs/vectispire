//! What kind of destination a given setting is allowed to name — `OutboundPolicy`.
//!
//! Three named policies rather than two booleans: the original carried `allowPrivate` and
//! `requirePrivate`, which spells four states for three meanings — and the fourth asks for a
//! destination that must be internal and may not be. It could be written, it read as plausible, and
//! it refused every URL. Here it cannot be written.

/// A destination policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OutboundPolicy {
    /// Public destinations only — the notification webhook. Anything internal is refused,
    /// link-local first among them.
    PublicOnly,
    /// Private and loopback accepted — the local scan side-car. **Never link-local**: nothing
    /// legitimate lives in `169.254.0.0/16`, and that is precisely the address the attack wants.
    InternalAllowed,
    /// Internal destinations only — the Ollama server. The mirror image, and the one that is easy to
    /// miss: it receives the scanned repository's *source code*, so the risk is not that the URL
    /// points inward, it is that it points outward — a well-formed public URL is exactly what an
    /// exfiltration channel looks like, and no anti-SSRF check would flag it.
    InternalRequired,
}

impl OutboundPolicy {
    /// The name the Java enum has, which the reference sets and the audit trail quote.
    pub fn name(self) -> &'static str {
        match self {
            OutboundPolicy::PublicOnly => "PUBLIC_ONLY",
            OutboundPolicy::InternalAllowed => "INTERNAL_ALLOWED",
            OutboundPolicy::InternalRequired => "INTERNAL_REQUIRED",
        }
    }

    pub const ALL: [OutboundPolicy; 3] =
        [OutboundPolicy::PublicOnly, OutboundPolicy::InternalAllowed, OutboundPolicy::InternalRequired];
}
