//! A CA pinned for one destination — the part of `PinnedCa` the sender needs.
//!
//! A forge on a private network is verified against the CA its administrator pasted, **in place of**
//! the public ones for that request, never beside them: pinning changes whom to trust, never whether
//! the name is checked. What is read here is the form: PEM only, a ceiling on its size and on the
//! number of certificates, and nothing but certificates in it — a private key pasted by mistake is
//! refused by name rather than ignored, which is what a PEM reader that skips what it does not
//! recognise would do.
//!
//! **Not here yet:** the Java class also reads each certificate's X.509 fields — it must be a CA
//! (basic constraints), allowed to sign (key usage), and current (`not_before`/`not_after`, with the
//! subject in the message). That needs an X.509 parser, which this workspace does not carry, and is
//! the forge-connection module's input check rather than the door's; it arrives with that module.

/// At most this many characters of PEM.
pub const MAX_LENGTH: usize = 16_384;
/// At most this many certificates.
pub const MAX_CERTIFICATES: usize = 8;

/// Which field the PEM came from, and which server it is meant for, for the messages.
#[derive(Clone, Debug)]
pub struct Subject {
    pub field: String,
    pub server: String,
}

/// The PEM was not usable. `InvalidInputException`: the message is shown to whoever pasted it.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidInput(pub String);

/// A CA, as the sender trusts it.
#[derive(Clone)]
pub struct PinnedCa {
    pem: String,
    certificates: Vec<reqwest::Certificate>,
}

impl std::fmt::Debug for PinnedCa {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "PinnedCa({} certificate(s))", self.certificates.len())
    }
}

impl PinnedCa {
    /// Reads the PEM, or says why it cannot be one.
    pub fn read(pem: Option<&str>, subject: &Subject) -> Result<PinnedCa, InvalidInput> {
        let field = &subject.field;
        let value = pem.unwrap_or("").trim_matches(|c: char| c <= ' ');
        if value.is_empty() {
            return Err(InvalidInput(format!("{field} is empty.")));
        }
        let length = value.chars().count();
        if length > MAX_LENGTH {
            return Err(InvalidInput(format!(
                "{field} is {length} characters long; at most {MAX_LENGTH} are accepted."
            )));
        }
        let mut certificates = 0usize;
        for line in value.lines() {
            let Some(label) = line.trim().strip_prefix("-----BEGIN ").and_then(|rest| rest.strip_suffix("-----"))
            else {
                continue;
            };
            if label != "CERTIFICATE" {
                // The object is not named: if it is a private key, its type is all this says.
                return Err(InvalidInput(format!(
                    "{field} holds something other than certificates. Paste the CA's certificate in PEM form \
                     (-----BEGIN CERTIFICATE-----); a private key never belongs here."
                )));
            }
            if certificates == MAX_CERTIFICATES {
                return Err(InvalidInput(format!("{field} holds more than {MAX_CERTIFICATES} certificates.")));
            }
            certificates += 1;
        }
        if certificates == 0 {
            return Err(InvalidInput(format!(
                "{field} holds no certificate. Paste it in PEM form, -----BEGIN CERTIFICATE----- included."
            )));
        }
        let parsed = reqwest::Certificate::from_pem_bundle(value.as_bytes())
            .map_err(|_| InvalidInput(format!("{field} is not a readable PEM certificate.")))?;
        if parsed.len() != certificates {
            return Err(InvalidInput(format!("{field} is not a readable PEM certificate.")));
        }
        Ok(PinnedCa { pem: value.to_owned(), certificates: parsed })
    }

    pub fn pem(&self) -> &str {
        &self.pem
    }

    pub(crate) fn certificates(&self) -> &[reqwest::Certificate] {
        &self.certificates
    }
}
