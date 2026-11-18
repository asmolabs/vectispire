//! The threat-intelligence domain against Java's answers in `reference/threatintel/domain.json`, written by
//! `ThreatIntelReferenceSetTest`: the KEV catalogue, the EPSS file built from each case's description — its bytes
//! first proved to be Java's, then read as Java's sink read them —, the comparability rule, the risk matrix, and the
//! two small readings.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::io::Write;

use serde_json::Value;
use sha2::{Digest, Sha256};
use vectispire_cp_threatintel::epss_file::{self, EpssReader};
use vectispire_cp_threatintel::kev_catalog::KevCatalog;
use vectispire_cp_threatintel::risk_matrix;
use vectispire_cp_threatintel::status::{Exploitation, State};
use vectispire_domain::wire::java_double_to_string;

fn set() -> Value {
    vectispire_testkit::read_json("threatintel/domain.json")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn the_kev_catalogue() {
    for case in set()["kev"].as_array().unwrap() {
        let document = case["document"].as_str().unwrap();
        let parsed = KevCatalog::parse(&serde_json::from_str(document).unwrap());
        match (&parsed, case.get("unreadable")) {
            (Err(refused), Some(Value::String(expected))) => assert_eq!(&refused.0, expected, "{document}"),
            (Ok(catalog), None) => {
                let expected = &case["catalog"];
                assert_eq!(catalog.version.as_deref(), expected["version"].as_str(), "{document}");
                assert_eq!(
                    catalog.released.and_then(|at| at.to_java_string()).as_deref(),
                    expected["released"].as_str(),
                    "{document}"
                );
                let added: Vec<(String, Option<String>)> = catalog
                    .added
                    .iter()
                    .map(|(cve, day)| (cve.clone(), day.and_then(|day| day.to_java_string())))
                    .collect();
                let wanted: Vec<(String, Option<String>)> = expected["added"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|pair| (pair[0].as_str().unwrap().to_owned(), pair[1].as_str().map(str::to_owned)))
                    .collect();
                assert_eq!(added, wanted, "{document}");
            }
            (parsed, expected) => panic!("{document}: Rust {parsed:?}, Java {expected:?}"),
        }
    }
}

/// Row `i`, as `ThreatIntelReferenceSetTest.generated` writes it.
fn generated(i: u64) -> String {
    format!("CVE-{}-{i:05},0.{:03},0.{:03}", 2000 + i % 20, i % 1000, (i * 7) % 1000)
}

/// `GZIPOutputStream`'s bytes: its ten-byte header, zlib's raw deflate at the default level, CRC-32 and size.
fn gzip(plain: &[u8]) -> Vec<u8> {
    let mut deflated = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    deflated.write_all(plain).unwrap();
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    out.extend(deflated.finish().unwrap());
    let mut crc = flate2::Crc::new();
    crc.update(plain);
    out.extend(crc.sum().to_le_bytes());
    out.extend(u32::try_from(plain.len() & 0xffff_ffff).unwrap().to_le_bytes());
    out
}

fn build(spec: &Value) -> Vec<u8> {
    let ending = spec["ending"].as_str().unwrap();
    let inject: BTreeMap<u64, String> = spec["inject"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(at, line)| (at.parse().unwrap(), line.as_str().unwrap().to_owned()))
        .collect();
    let mut text = String::new();
    for line in spec["head"].as_array().unwrap() {
        text.push_str(line.as_str().unwrap());
        text.push_str(ending);
    }
    for i in 0..spec["rows"].as_u64().unwrap() {
        if let Some(line) = inject.get(&i) {
            text.push_str(line);
            text.push_str(ending);
        }
        text.push_str(&generated(i));
        text.push_str(ending);
    }
    for line in spec["tail"].as_array().unwrap() {
        text.push_str(line.as_str().unwrap());
        text.push_str(ending);
    }
    let plain = text.into_bytes();
    let cut = |mut bytes: Vec<u8>, by: usize| {
        bytes.truncate(bytes.len() - by);
        bytes
    };
    match spec["compression"].as_str().unwrap() {
        "none" => plain,
        "gzip" => gzip(&plain),
        "gzip-two-members" => {
            let half = plain.len() / 2;
            let mut both = gzip(&plain[..half]);
            both.extend(gzip(&plain[half..]));
            both
        }
        "gzip-cut-4" => cut(gzip(&plain), 4),
        "gzip-cut-2000" => cut(gzip(&plain), 2_000),
        "gzip-bad-crc" => {
            let mut archive = gzip(&plain);
            let at = archive.len() - 8;
            archive[at] ^= 0x5a;
            archive
        }
        other => panic!("{other}"),
    }
}

#[test]
fn the_epss_file() {
    for case in set()["epss"].as_array().unwrap() {
        let spec = &case["spec"];
        let name = spec["name"].as_str().unwrap();
        let bytes = build(spec);
        assert_eq!(hex(&Sha256::digest(&bytes)), case["bytes"].as_str().unwrap(), "{name}: not Java's bytes");

        let batch = usize::try_from(spec["batch"].as_u64().unwrap()).unwrap();
        let mut sizes = Vec::new();
        let mut digest = Sha256::new();
        let outcome = (|| {
            let mut reader = EpssReader::open(&bytes)?;
            if spec["stop"].as_bool().unwrap() {
                return Ok((reader.header().clone(), 0, true));
            }
            while let Some(scores) = reader.next_batch(batch)? {
                sizes.push(scores.len());
                for score in scores {
                    digest.update(format!(
                        "{},{},{}\n",
                        score.cve,
                        java_double_to_string(score.score),
                        java_double_to_string(score.percentile)
                    ));
                }
            }
            Ok::<_, epss_file::Unreadable>((reader.header().clone(), reader.rows(), false))
        })();
        match (outcome, case.get("unreadable")) {
            (Err(refused), Some(Value::String(expected))) => assert_eq!(&refused.0, expected, "{name}"),
            (Ok((header, rows, stopped)), None) => {
                let read = &case["read"];
                assert_eq!(header.model_version, read["modelVersion"].as_str().unwrap(), "{name}");
                assert_eq!(header.score_date.to_java_string().unwrap(), read["scoreDate"].as_str().unwrap(), "{name}");
                assert_eq!(rows, read["rows"].as_u64().unwrap(), "{name}");
                assert_eq!(stopped, read["stopped"].as_bool().unwrap(), "{name}");
            }
            (outcome, expected) => panic!("{name}: Rust {outcome:?}, Java {expected:?}"),
        }
        let expected: Vec<usize> = case["batches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|size| usize::try_from(size.as_u64().unwrap()).unwrap())
            .collect();
        assert_eq!(sizes, expected, "{name}: the batches");
        assert_eq!(hex(&digest.finalize()), case["digest"].as_str().unwrap(), "{name}: the rows");
    }
}

#[test]
fn the_comparability_rule() {
    for case in set()["comparable"].as_array().unwrap() {
        let outcome = epss_file::require_comparable(case[0].as_u64().unwrap(), case[1].as_u64().unwrap());
        assert_eq!(outcome.err().map(|refused| refused.0).as_deref(), case[2].as_str(), "{case}");
    }
}

#[test]
fn the_risk_matrix() {
    for case in set()["matrix"].as_array().unwrap() {
        let (cvss, epss, kev) = (case[0].as_f64(), case[1].as_f64(), case[2].as_bool().unwrap());
        if !case[3].is_null() {
            assert_eq!(i64::from(risk_matrix::priority_score(cvss, epss, kev)), case[3].as_i64().unwrap(), "{case}");
            assert_eq!(risk_matrix::tier(cvss, epss, kev), case[4].as_str().unwrap(), "{case}");
        }
        assert_eq!(risk_matrix::action(case[4].as_str().unwrap(), kev).name(), case[5].as_str().unwrap(), "{case}");
    }
}

#[test]
fn a_cve_and_a_stored_state() {
    for case in set()["cves"].as_array().unwrap() {
        assert_eq!(Exploitation::names_a_cve(case[0].as_str()), case[1].as_bool().unwrap(), "{case}");
    }
    for case in set()["states"].as_array().unwrap() {
        assert_eq!(State::of(case[0].as_str()).name(), case[1].as_str().unwrap(), "{case}");
    }
}
