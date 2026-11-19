//! A file of the audited tree as the API discovery reads it — a specification in JSON or YAML, an ingress, a Spring,
//! Express, NestJS, FastAPI, Flask or Gin source — in the agent's own process: whatever it holds, every reader
//! answers, never panics. The bytes up to the first NUL are the file's name, the rest its content, decoded as Java
//! decodes it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vectispire_scanners::{api_discovery, jackson_tree, source_files};

fuzz_target!(|data: &[u8]| {
    let (name, content) = match data.iter().position(|&byte| byte == 0) {
        Some(at) => (data.get(..at).unwrap_or_default(), data.get(at + 1..).unwrap_or_default()),
        None => (&b"openapi.json"[..], data),
    };
    let name = String::from_utf8_lossy(name);
    let content = source_files::java_utf8(content);
    let _ = api_discovery::read_one(&name, &content);
    let _ = jackson_tree::read_text(&content);
});
