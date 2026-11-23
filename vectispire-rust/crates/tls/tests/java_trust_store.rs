//! What the agent trusts when it is started where a Java agent was: the Helm chart's `agents.trustStore` names a
//! PKCS12 store in `JDK_JAVA_OPTIONS`, and passes its PEM form in `VECTISPIRE_TLS_CA_BUNDLE` when the operator gave one.
//!
//! **The one outcome that must never happen is the compiled-in authorities while a store is named**: the operator's
//! store replaced the JVM's own, so a public CA they left out would be trusted again, with nothing said.

use std::collections::BTreeMap;

use vectispire_tls::{TlsTrust, TrustError};

/// A self-signed authority, made for these tests (`openssl req -x509`, P-256, a century of validity).
const BUNDLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/test-ca.pem");

/// The chart's options for an agent given a truststore, as `templates/agents/deployment.yaml` renders them.
const CHART_OPTIONS: &str = "-Djava.io.tmpdir=/var/lib/vectispire/agent-work -Duser.home=/var/lib/vectispire/agent-work/home \
                             -Djavax.net.ssl.trustStore=/etc/vectispire/trust/truststore.p12 -Djavax.net.ssl.trustStoreType=PKCS12";

fn trust(variables: &[(&str, &str)]) -> Result<TlsTrust, TrustError> {
    let variables: BTreeMap<String, String> =
        variables.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect();
    TlsTrust::from_lookup(|name| variables.get(name).cloned())
}

fn refused_naming(variables: &[(&str, &str)], variable: &str, store: &str) {
    match trust(variables) {
        Err(TrustError::JavaTrustStoreOnly { variable: named, store: found }) => {
            assert_eq!((named, found.as_str()), (variable, store));
        }
        other => panic!("expected a refusal naming {variable}'s {store}, got {other:?}"),
    }
}

#[test]
fn nothing_named_is_the_compiled_in_authorities() {
    assert!(matches!(trust(&[]), Ok(TlsTrust::BuiltIn)));
    assert!(matches!(trust(&[("JDK_JAVA_OPTIONS", "-Djava.io.tmpdir=/w -Duser.home=/w/home")]), Ok(TlsTrust::BuiltIn)));
}

#[test]
fn the_chart_store_alone_refuses_the_start() {
    refused_naming(&[("JDK_JAVA_OPTIONS", CHART_OPTIONS)], "JDK_JAVA_OPTIONS", "/etc/vectispire/trust/truststore.p12");
    // An empty bundle variable is no bundle: the chart renders none, an operator's override may render it blank.
    refused_naming(
        &[("JDK_JAVA_OPTIONS", CHART_OPTIONS), ("VECTISPIRE_TLS_CA_BUNDLE", "")],
        "JDK_JAVA_OPTIONS",
        "/etc/vectispire/trust/truststore.p12",
    );
}

#[test]
fn a_store_named_in_the_vm_options_refuses_too() {
    // `JAVA_TOOL_OPTIONS` is read by the VM itself, so a Java agent honours a store named there as well.
    refused_naming(&[("JAVA_TOOL_OPTIONS", "-Djavax.net.ssl.trustStore=/t.p12")], "JAVA_TOOL_OPTIONS", "/t.p12");
    refused_naming(
        &[
            ("JDK_JAVA_OPTIONS", "-Duser.home=/h"),
            ("JAVA_TOOL_OPTIONS", "-Xmx1g \"-Djavax.net.ssl.trustStore=/t.p12\""),
        ],
        "JAVA_TOOL_OPTIONS",
        "/t.p12\"",
    );
}

#[test]
fn the_store_password_and_type_name_no_store() {
    // The chart's own check passes the password this way: it is not a store, and refusing it would refuse every
    // installation that gave the store's PEM form beside it.
    let options = "-Djavax.net.ssl.trustStorePassword=secret -Djavax.net.ssl.trustStoreType=PKCS12";
    assert!(matches!(trust(&[("JAVA_TOOL_OPTIONS", options)]), Ok(TlsTrust::BuiltIn)));
}

#[test]
fn the_pem_form_beside_the_store_is_the_trust() {
    for variables in [
        vec![("JDK_JAVA_OPTIONS", CHART_OPTIONS), ("VECTISPIRE_TLS_CA_BUNDLE", BUNDLE)],
        vec![("VECTISPIRE_TLS_CA_BUNDLE", BUNDLE)],
    ] {
        match trust(&variables) {
            Ok(TlsTrust::Bundle { certificates, .. }) => assert_eq!(certificates.len(), 1),
            other => panic!("expected the bundle alone, got {other:?}"),
        }
    }
}

#[test]
fn an_unreadable_bundle_still_refuses_beside_a_store() {
    // The bundle is read first and its failure is its own: a store named beside it is no fallback.
    let refused = trust(&[("JDK_JAVA_OPTIONS", CHART_OPTIONS), ("VECTISPIRE_TLS_CA_BUNDLE", "/nonexistent/ca.pem")]);
    assert!(matches!(refused, Err(TrustError::Unreadable { .. })), "{refused:?}");
}

#[test]
fn the_refusal_says_what_to_give() {
    let Err(refusal) = trust(&[("JDK_JAVA_OPTIONS", CHART_OPTIONS)]) else { panic!("not refused") };
    let said = refusal.to_string();
    for words in [
        "JDK_JAVA_OPTIONS",
        "/etc/vectispire/trust/truststore.p12",
        "VECTISPIRE_TLS_CA_BUNDLE",
        "agents.trustStore.pemKey",
    ] {
        assert!(said.contains(words), "{said:?} does not name {words}");
    }
}
