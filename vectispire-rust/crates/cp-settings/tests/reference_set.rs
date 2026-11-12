//! The catalog held to the Java side's (`reference/settings/`, written by `SettingsReferenceSetTest`): every
//! setting's definition and the rules on it, every validation answer, the thresholds, the digits `parseInt` reads.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::Value;
use vectispire_cp_settings::types::{DIGIT_ZEROS, decimal_digit, parse_int};
use vectispire_cp_settings::{Setting, SettingType, THRESHOLDS};
use vectispire_testkit::{read, read_json};

#[test]
fn the_catalog_is_java_s_setting_by_setting() {
    let java = read_json("settings/catalog.json");
    let java = java.as_array().unwrap();
    assert_eq!(java.len(), Setting::ALL.len(), "as many settings");
    for (setting, java) in Setting::ALL.iter().zip(java) {
        let name = setting.name();
        assert_eq!(name, java["name"].as_str().unwrap(), "the same order");
        let checks: [(&str, Value); 14] = [
            ("key", setting.key().into()),
            ("type", setting.setting_type().name().into()),
            ("section", setting.section().name().into()),
            ("sectionLabel", setting.section().label().into()),
            ("label", setting.label().into()),
            ("help", setting.help().into()),
            ("defaultValue", setting.default_value().into()),
            ("sensitivity", setting.sensitivity().name().into()),
            ("isSecret", setting.is_secret().into()),
            ("isEncrypted", setting.is_encrypted().into()),
            ("directsCredential", setting.directs_credential().map(|target| target.name()).into()),
            ("administratorOnly", setting.administrator_only().into()),
            ("governorOnly", setting.governor_only().into()),
            ("governsSecurity", setting.governs_security().into()),
        ];
        for (field, rust) in checks {
            assert_eq!(rust, java[field], "{name}.{field}");
        }
        assert_eq!(Setting::by_key(setting.key()), Some(*setting));
    }
    assert_eq!(Setting::by_key("no_such_setting"), None, "a removed setting is simply not asked for");
}

#[test]
fn every_value_is_accepted_or_refused_in_java_s_words() {
    let cases = read_json("settings/validation.json");
    let cases = cases.as_array().unwrap();
    assert!(cases.len() > 3_000, "the set has its cases");
    for case in cases {
        let setting = Setting::ALL.into_iter().find(|setting| setting.name() == case["setting"]).unwrap();
        let input = match case.get("repeat") {
            Some(repeat) => {
                let units = usize::try_from(case["units"].as_u64().unwrap()).unwrap();
                match case["tail"].as_str() {
                    Some(tail) => repeat.as_str().unwrap().repeat(units - tail.encode_utf16().count()) + tail,
                    None => repeat.as_str().unwrap().repeat(units),
                }
            }
            None => match case["input"].as_str() {
                Some(text) => text.to_owned(),
                None => {
                    assert_eq!(
                        setting.validate(None).as_deref(),
                        case["refusal"].as_str(),
                        "{} of null",
                        setting.name()
                    );
                    continue;
                }
            },
        };
        assert_eq!(
            setting.validate(Some(&input)).as_deref(),
            case["refusal"].as_str(),
            "{} of {input:?}",
            setting.name()
        );
    }
}

#[test]
fn the_thresholds_are_java_s() {
    assert_eq!(read("settings/thresholds.txt").lines().collect::<Vec<_>>(), THRESHOLDS);
}

#[test]
fn the_digits_parse_int_reads_are_java_s() {
    let java: Vec<u32> =
        read("settings/digit-zeros.txt").lines().map(|line| u32::from_str_radix(line, 16).unwrap()).collect();
    assert_eq!(DIGIT_ZEROS.to_vec(), java);
    // Each block of ten, and not one character past it.
    for zero in DIGIT_ZEROS {
        for offset in 0..10 {
            assert_eq!(decimal_digit(char::from_u32(zero + offset).unwrap()), Some(offset));
        }
    }
    assert_eq!(decimal_digit('a'), None);
    assert_eq!(parse_int("\u{0661}\u{0662}"), Some(12));
    assert_eq!(parse_int(" -2147483648 "), Some(i32::MIN));
    assert_eq!(parse_int("2147483648"), None);
    assert_eq!(parse_int(&"9".repeat(10_000)), None, "stops early, refuses");
}

#[test]
fn every_integer_default_parses_and_every_default_is_valid() {
    for setting in Setting::ALL {
        if setting.setting_type() == SettingType::Integer {
            assert!(parse_int(setting.default_value()).is_some(), "{}", setting.name());
        }
        assert_eq!(setting.validate(Some(setting.default_value())), None, "{}'s own default", setting.name());
    }
}
