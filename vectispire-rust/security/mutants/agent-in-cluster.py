#!/usr/bin/env python3
"""Mutation check of the agent's trust when it is started where the Java agent was (2026-11-20): a Java truststore named
in the JVM's options without a PEM bundle refuses the start, rather than leaving the agent on its compiled-in authorities.
Each mutant must turn a test red. See README.md.

All are killed by `vectispire-tls`'s `java_trust_store` test, which needs nothing but the crate.
"""
import sys

import _runner

T = "crates/tls/src/lib.rs"
TESTS = ["-p", "vectispire-tls", "--test", "java_trust_store"]

MUTANTS = [
    ("a named store falls back to the built-in authorities", T,
     "                return Err(TrustError::JavaTrustStoreOnly { variable, store });\n", "", TESTS),
    ("the VM's own options not read", T, 'pub const JAVA_OPTION_VARIABLES: [&str; 2] = ["JDK_JAVA_OPTIONS", "JAVA_TOOL_OPTIONS"];',
     'pub const JAVA_OPTION_VARIABLES: [&str; 2] = ["JDK_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"];', TESTS),
    ("the store's password read as a store", T, 'const JAVA_TRUST_STORE_OPTION: &str = "-Djavax.net.ssl.trustStore=";',
     'const JAVA_TRUST_STORE_OPTION: &str = "-Djavax.net.ssl.trustStore";', TESTS),
    ("a quoted option missed", T, ".trim_start_matches(['\"', '\\''])", "", TESTS),
    ("the store wins over the bundle beside it", T,
     "        if let Some(path) = lookup(BUNDLE_VARIABLE).filter(|value| !value.is_empty()) {\n"
     "            return TlsTrust::from_bundle(Path::new(&path));\n        }\n",
     "", TESTS,
     [("        Ok(TlsTrust::BuiltIn)\n    }\n\n    /// The certificates",
       "        match lookup(BUNDLE_VARIABLE).filter(|value| !value.is_empty()) {\n"
       "            Some(path) => TlsTrust::from_bundle(Path::new(&path)),\n"
       "            None => Ok(TlsTrust::BuiltIn),\n        }\n    }\n\n    /// The certificates")]),
    ("an empty bundle variable read as a bundle", T,
     "        if let Some(path) = lookup(BUNDLE_VARIABLE).filter(|value| !value.is_empty()) {",
     "        if let Some(path) = lookup(BUNDLE_VARIABLE) {", TESTS),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900))
