//! The deployment key, read before anything reaches the network — `GitClone.loadKey`.
//!
//! **Parsed first because a key that does not parse would otherwise fail as a refused one**: the
//! transport parses lazily, at connection time, and the operator would be sent to the provider's
//! settings for a key that never parsed here. The key stays in memory and is handed to libssh2 from
//! there — no 0600 file to race against, nothing left behind if the process is killed.

use crate::{CloneError, Kind};

/// The key as libssh2 is handed it: terminated by a newline, which a copy out of a browser loses and
/// ssh refuses without saying so.
pub(crate) fn readable(private_key: &str) -> Result<String, CloneError> {
    let material = if private_key.ends_with('\n') { private_key.to_owned() } else { format!("{private_key}\n") };
    let unreadable = |reason: String| {
        CloneError::new(
            Kind::Credential,
            format!("The deployment key attached to this repository could not be read: {reason}"),
        )
    };
    if material.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
        let key =
            ssh_key::PrivateKey::from_openssh(material.as_bytes()).map_err(|error| unreadable(error.to_string()))?;
        if key.is_encrypted() {
            // Nobody is there to type a passphrase, and none is stored.
            return Err(unreadable("it is protected by a passphrase, which a scan cannot supply.".to_owned()));
        }
        return Ok(material);
    }
    // PEM keys (PKCS#1, SEC1, PKCS#8) are read by libssh2's OpenSSL; checked here for their armour, so
    // that something that is not a key at all is told apart from a key the forge refused.
    let pem = ["RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY"].iter().any(|label| {
        material.contains(&format!("-----BEGIN {label}-----")) && material.contains(&format!("-----END {label}-----"))
    });
    if pem {
        return Ok(material);
    }
    Err(unreadable("no key recognized in it. Expected an OpenSSH or PEM private key.".to_owned()))
}
