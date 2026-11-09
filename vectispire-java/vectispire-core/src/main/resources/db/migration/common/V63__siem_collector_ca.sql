-- A syslog-over-TLS collector can pin the CA its certificate is verified against.
--
-- Until now the collector's certificate was verified against the Java runtime's trust store, so a
-- collector with a private CA needed that CA imported into the JVM's `cacerts` — which made every
-- outbound TLS connection of the control plane trust it as well. `tls_ca_pem` holds one or a few CA
-- certificates in PEM, used for the SIEM connection only and in place of the runtime's store; null
-- keeps the runtime's store. A CA is public, so the column is not encrypted; the save bounds it to
-- 16,384 characters and refuses anything but current CA certificates (`CollectorCa`).
--
-- Written once, in common: an added nullable column.

alter table t_siem_config add column tls_ca_pem ${text};
