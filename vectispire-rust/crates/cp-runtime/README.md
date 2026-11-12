# cp-runtime

What the control plane runs on, apart from what it does. See `vectispire-rust/README.md`, "The control plane's crates", for how it relates
to the other crates and what differs from the Java side.

- `property` + `settings`: **108 properties** — 70 from `application.yaml` (the placeholder chain and the default are compared with the file),
  25 `@Value("${key:default}")` expressions (looked up in the Java sources), 13 defaults of `@ConfigurationProperties` records. Nine are secrets
  and never print. `Settings::load` reports every problem at once.
- `secret_file`: a secret given as a file (`ENCRYPTION_KEY_FILE`, …), refused when empty, unreadable, or beside the value it replaces.
- `audit_mirror`: the NDJSON file, appended one write per line, in Jackson's bytes.
- `metrics` + `actuator`: the answers of `/actuator`, `/actuator/health[/liveness|/readiness]`, `/actuator/info` and `/actuator/metrics[/{name}]`, as
  documents and a status — the HTTP stack mounts them and enforces `actuator::access`. Byte-compared with what rc.3 answered.
- `telemetry`: Spring's console format, or JSON.
- `shutdown` + `app`: the order of a graceful stop — readiness out of service, then the signal to the service, then a bounded wait (30 s).

`cargo run -p vectispire-cp-app -- --check-config` prints every setting, where its value came from, and no secret.
