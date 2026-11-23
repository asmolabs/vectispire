//! Which certificate authorities the agent trusts.
//!
//! **One trust for every HTTPS connection the agent opens** — the control plane's and every forge's —
//! as on the Java agent, whose JVM truststore serves both. And like that truststore, **a bundle
//! replaces the built-in authorities rather than adding to them**: the Helm chart's
//! `agents.trustStore` "replaces the JVM's own: include every authority the agent must trust, the
//! forges' included", and an operator moving from the Java agent to this one must not find that a
//! public CA they had removed is trusted again.
//!
//! - Without `VECTISPIRE_TLS_CA_BUNDLE`, the Mozilla authorities compiled into the binary
//!   (`webpki-roots`) — the image is `scratch`, with no system store to read, and a store compiled in
//!   is the same on every host.
//! - With it, the PEM certificates of that file and nothing else. A file that holds none, or does not
//!   parse, stops the agent at start: a trust that silently fell back to the defaults would let the
//!   operator believe their internal CA was the only one.
//! - **A Java truststore named without a bundle stops the start too.** The chart's `agents.trustStore`
//!   reaches the Java agent as `-Djavax.net.ssl.trustStore=` in `JDK_JAVA_OPTIONS`, which this agent does not
//!   read (the PKCS12 is not parsed here: the README's "In a cluster" says why). Started from that chart with
//!   the store alone, it would have trusted the compiled-in authorities instead — the operator's private CA
//!   refused, which is loud, but every public CA they had left out trusted again, which is not. So it refuses,
//!   and names the PEM form the chart passes beside the store (`agents.trustStore.pemKey`).

use std::path::{Path, PathBuf};

/// The variable naming the bundle.
pub const BUNDLE_VARIABLE: &str = "VECTISPIRE_TLS_CA_BUNDLE";

/// The variables a JVM reads its options from, and so where a Java agent's truststore is named: the launcher's
/// `JDK_JAVA_OPTIONS` (the chart's) and the VM's own `JAVA_TOOL_OPTIONS`.
pub const JAVA_OPTION_VARIABLES: [&str; 2] = ["JDK_JAVA_OPTIONS", "JAVA_TOOL_OPTIONS"];

/// The option naming a Java truststore. With its `=`: `-Djavax.net.ssl.trustStorePassword=` and `…Type=` name none.
const JAVA_TRUST_STORE_OPTION: &str = "-Djavax.net.ssl.trustStore=";

/// The authorities trusted.
#[derive(Clone)]
pub enum TlsTrust {
    /// The Mozilla authorities compiled in.
    BuiltIn,
    /// An operator's bundle, alone.
    Bundle { path: PathBuf, certificates: Vec<reqwest::Certificate> },
}

impl std::fmt::Debug for TlsTrust {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsTrust::BuiltIn => formatter.write_str("TlsTrust::BuiltIn"),
            TlsTrust::Bundle { path, certificates } => {
                write!(formatter, "TlsTrust::Bundle({}, {} certificate(s))", path.display(), certificates.len())
            }
        }
    }
}

/// Why the bundle cannot be the agent's trust.
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("{BUNDLE_VARIABLE} names {path}, which could not be read: {cause}")]
    Unreadable { path: String, cause: String },
    #[error("{BUNDLE_VARIABLE} names {path}, which holds no PEM certificate: {cause}")]
    NoCertificate { path: String, cause: String },
    #[error(
        "{variable} names a Java truststore ({store}), which this agent does not read, and {BUNDLE_VARIABLE} names no PEM \
         bundle: started on its compiled-in authorities instead, it would trust every public CA the store left out. Give \
         it the store's certificates in PEM — with the Helm chart, beside the store in its Secret, named by \
         agents.trustStore.pemKey."
    )]
    JavaTrustStoreOnly { variable: &'static str, store: String },
}

impl TlsTrust {
    /// The trust `VECTISPIRE_TLS_CA_BUNDLE` describes.
    pub fn from_environment() -> Result<TlsTrust, TrustError> {
        TlsTrust::from_lookup(|name| std::env::var(name).ok())
    }

    /// The trust the variables `lookup` answers describe: the bundle if one is named — whatever a Java option says,
    /// since the chart passes both forms of one store — else the compiled-in authorities, unless a Java truststore
    /// is named, which refuses.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<TlsTrust, TrustError> {
        if let Some(path) = lookup(BUNDLE_VARIABLE).filter(|value| !value.is_empty()) {
            return TlsTrust::from_bundle(Path::new(&path));
        }
        for variable in JAVA_OPTION_VARIABLES {
            if let Some(store) = lookup(variable).as_deref().and_then(java_trust_store) {
                return Err(TrustError::JavaTrustStoreOnly { variable, store });
            }
        }
        Ok(TlsTrust::BuiltIn)
    }

    /// The certificates of a PEM file, alone.
    pub fn from_bundle(path: &Path) -> Result<TlsTrust, TrustError> {
        let shown = path.display().to_string();
        let pem = std::fs::read(path)
            .map_err(|error| TrustError::Unreadable { path: shown.clone(), cause: error.to_string() })?;
        let certificates = reqwest::Certificate::from_pem_bundle(&pem)
            .map_err(|error| TrustError::NoCertificate { path: shown.clone(), cause: error.to_string() })?;
        if certificates.is_empty() {
            return Err(TrustError::NoCertificate { path: shown, cause: "no certificate in it".to_owned() });
        }
        Ok(TlsTrust::Bundle { path: path.to_owned(), certificates })
    }

    /// The client builder, trusting these authorities and nothing else — and following no redirect,
    /// which every client of the agent's needs (the control plane's answers and the forges' alike).
    pub fn blocking_client(&self) -> reqwest::blocking::ClientBuilder {
        let builder = reqwest::blocking::Client::builder().redirect(reqwest::redirect::Policy::none()).https_only(true);
        match self {
            TlsTrust::BuiltIn => builder,
            TlsTrust::Bundle { certificates, .. } => {
                certificates.iter().fold(builder.tls_built_in_root_certs(false), |builder, certificate| {
                    builder.add_root_certificate(certificate.clone())
                })
            }
        }
    }

    /// The asynchronous client builder, under the same rules.
    pub fn client(&self) -> reqwest::ClientBuilder {
        let builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
        match self {
            TlsTrust::BuiltIn => builder,
            TlsTrust::Bundle { certificates, .. } => {
                certificates.iter().fold(builder.tls_built_in_root_certs(false), |builder, certificate| {
                    builder.add_root_certificate(certificate.clone())
                })
            }
        }
    }
}

/// The truststore a JVM's options name, if any. Read as `Places` reads `-Djava.io.tmpdir=` from the same variable — split
/// on whitespace — with a leading quote set aside, since the launcher reads `"-Dx=a b"` as one option: an option this
/// reading would miss is one whose store the agent then silently replaced, so it errs towards seeing one.
fn java_trust_store(options: &str) -> Option<String> {
    options.split_whitespace().find_map(|option| {
        option.trim_start_matches(['"', '\'']).strip_prefix(JAVA_TRUST_STORE_OPTION).map(str::to_owned)
    })
}
