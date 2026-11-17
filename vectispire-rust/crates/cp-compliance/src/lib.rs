//! Compliance — Java's `core/compliance`: the framework matrix and its per-scope reading, the statement of
//! applicability, the certified scope, the monthly history, the OWASP Top 10 grid with its weekly record, and the
//! OWASP report. The pure decisions are `vectispire_domain::compliance` and `owasp_coverage`; this crate holds what
//! reads and writes, in the module layout every ported module keeps (`persistence` beneath the services).

pub mod persistence;
