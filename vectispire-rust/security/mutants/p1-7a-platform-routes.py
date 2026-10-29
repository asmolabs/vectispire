#!/usr/bin/env python3
"""Mutation check of the platform port's first stage (a follow-up of Phase 1 task 1.7): the audit-log and crypto routes in crates/cp-platform/src/web — each route's marker, the verification's answer to a request missing its payload or signature, the Jackson binding of its body, the refusals' statuses (a pasted key 400, no ENCRYPTION_KEY 412), the public key's download headers, the query parameters read as Spring binds them (the default for an empty value only, the first int, every string joined), and the binary's registry serving them. See README.md.

The audit-log answers end to end are held by the golden replay of their recordings, which these runs do not include.
"""
import sys

import _runner

LIB = ["-p", "vectispire-cp-platform", "--lib", "web::"]
CONTRACT = ["-p", "vectispire-cp-platform", "--test", "contract"]
AL = "crates/cp-platform/src/web/audit_log.rs"
CR = "crates/cp-platform/src/web/crypto.rs"
RD = "crates/cp-platform/src/web/read.rs"
AUTHZ = ["-p", "vectispire-cp-app", "--test", "route_authorization"]
REG = "crates/cp-app/src/registry.rs"

MUTANTS = [
    # ---- markers ----
    ("audit list open to accounts", AL, "entries.push(Route::get(LIST).requires(Access::GovernanceRead)", "entries.push(Route::get(LIST).requires(Access::Account)", CONTRACT),
    ("audit verify open to accounts", AL, "entries.push(Route::get(VERIFY).requires(Access::GovernanceRead)", "entries.push(Route::get(VERIFY).requires(Access::Account)", CONTRACT),
    ("public key behind an account", CR, "Route::get(PUBLIC_KEY).requires(Access::Anonymous)", "Route::get(PUBLIC_KEY).requires(Access::Account)", CONTRACT),
    ("verify anonymous", CR, "Route::post(VERIFY).requires(Access::Account)", "Route::post(VERIFY).requires(Access::Anonymous)", CONTRACT),
    # ---- the verification ----
    ("missing signature checked as empty", CR, "    let (Some(payload), Some(signature)) = (request.payload, request.signature) else {\n        return ok(&VerifyResponse::incomplete());\n    };", "    let (payload, signature) = (request.payload.unwrap_or_default(), request.signature.unwrap_or_default());", LIB),
    ("supplied key ignored", CR, "verify_with(payload.as_bytes(), &signature, request.public_key.as_deref())", "verify_with(payload.as_bytes(), &signature, None)", LIB),
    ("an array read as text", CR, "            Some(_) => Err(Problem::handler(StatusCode::BAD_REQUEST, UNREADABLE)),\n        };", "            Some(other) => Ok(Some(other.to_string())),\n        };", LIB),
    ("a null body refused", CR, "            Value::Null => return Ok(VerifyRequest::default()),", "            Value::Null => return Err(Problem::handler(StatusCode::BAD_REQUEST, UNREADABLE)),", LIB),
    ("a pasted key is a 500", CR, "        SigningError::InvalidPublicKey => bad_request(SigningError::InvalidPublicKey.to_string()),\n", "", LIB),
    ("no encryption key is a 500", CR, "        SigningError::MissingKey => {\n            Problem::handler(StatusCode::PRECONDITION_FAILED, SigningError::MissingKey.to_string()).into_response()\n        }\n", "", LIB),
    ("key not a named download", CR, "        HeaderValue::from_static(\"attachment; filename=\\\"vectispire-signing-key.pub\\\"\"),", "        HeaderValue::from_static(\"inline\"),", LIB),
    ("cosign looks up the log", CR, "    cosign_verify_manifest: \"cosign verify-blob --key vectispire-signing-key.pub --insecure-ignore-tlog=true \\", "    cosign_verify_manifest: \"cosign verify-blob --key vectispire-signing-key.pub \\", LIB),
    # ---- query parameters ----
    ("blank is the default", RD, "    if first.is_empty() {\n        return Ok(default);", "    if first.trim().is_empty() {\n        return Ok(default);", LIB),
    ("empty int refused", RD, "    if first.is_empty() {\n        return Ok(default);\n    }\n", "", LIB),
    ("last int counts", RD, "    let Some(first) = values(query, name).into_iter().next() else {", "    let Some(first) = values(query, name).into_iter().last() else {", LIB),
    ("first string only", RD, "if all.is_empty() { None } else { Some(all.join(\",\")) }", "all.into_iter().next()", LIB),
    ("plus not a space", RD, "percent_encoding::percent_decode_str(&text.replace('+', \" \"))", "percent_encoding::percent_decode_str(text)", LIB),
    ("int overflow wraps", RD, "        value = value.checked_mul(radix)?.checked_sub(i32::try_from(digit).ok()?)?;", "        value = value.wrapping_mul(radix).wrapping_sub(i32::try_from(digit).ok()?);", LIB),
    # ---- the composition: the binary's registry serves the routes that left the list ----
    ("registry without platform", REG, "    list.extend(vectispire_cp_platform::routes(platform.trail, platform.signing));\n", "    let _ = platform;\n", AUTHZ),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=600))
