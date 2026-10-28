//! A collector's or a forge's CA is pasted by an operator, and read — the PEM text, the Base64, then each
//! certificate's DER by a reader written for it (`domain::x509`). Whatever is pasted, reading must answer, never
//! panic; what it accepts has at least one anchor, every anchor a subject and its DER, and nothing longer than the
//! ceiling; what a paste is accepted with was read whole, a certificate for every `-----BEGIN`. Seeded with the
//! reference set's certificates, so the fuzzer starts inside the DER.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vectispire_domain::instant::Instant;
use vectispire_domain::siem::CollectorCa;
use vectispire_domain::siem::collector_ca::{MAX_CERTIFICATES, MAX_LENGTH};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    match CollectorCa::read(Some(text)) {
        Ok(ca) => {
            assert!(!ca.anchors().is_empty() && ca.anchors().len() <= MAX_CERTIFICATES);
            assert!(ca.pem().encode_utf16().count() <= MAX_LENGTH);
            assert!(ca.anchors().iter().all(|anchor| !anchor.der.is_empty() && anchor.not_before.to_java_string().is_some()));
            let now = Instant::of_epoch_second(1_790_856_000);
            let _ = CollectorCa::parse(Some(text), now);
            if let Ok(pasted) = CollectorCa::parse_pasted(Some(text), now) {
                assert_eq!(pasted.pem().matches("-----BEGIN").count(), pasted.anchors().len(), "a paste read in part");
            }
        }
        Err(refused) => assert!(refused.0.starts_with("The collector CA") || refused.0.starts_with('"')),
    }
});
