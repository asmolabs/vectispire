//! Does a body say what the document says it says?
//!
//! Every schema of `openapi.json` is JSON Schema 2020-12 (OpenAPI 3.1), and the Java generator
//! writes a nullable field as `"type": ["string", "null"]` — which is plain JSON Schema, so the
//! validator needs no dialect of its own. What it must not do is **reach out**: schemas are
//! resolved inside the one embedded `components`, and the crate is built without the validator's
//! network and file resolvers, so a `$ref` to anywhere else is an error and not a download.
//!
//! The older `nullable: true` and the `oneOf: [{…}, {"type": "null"}]` shape are both handled too,
//! because the nullability work planned for 0.12 emits the second for a nullable `$ref`, and a
//! check that rejected the contract's own encodings would only be silenced.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use jsonschema::Validator;
use serde::Serialize;
use serde_json::{Value, json};

use crate::document::{Document, Media, Operation};

/// One violation of a schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaError {
    /// A JSON Pointer into the checked body, `""` for the root.
    pub instance_path: String,
    pub message: String,
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let at = if self.instance_path.is_empty() { "the body" } else { &self.instance_path };
        write!(out, "{at}: {}", self.message)
    }
}

/// What checking one body against an operation's declared media found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Check {
    /// The body satisfies the schema.
    Valid,
    /// It does not.
    Invalid(Vec<SchemaError>),
    /// The document declares nothing for this status or media type — the Java application answers
    /// `404`, `400` and `401` without documenting them, so this is a count and not a failure.
    Undeclared(String),
    /// Declared, but there is nothing to check a JSON schema against: a PDF, a CSV, a ZIP.
    NotChecked(String),
}

/// The schemas of one document, compiled on first use.
#[derive(Debug)]
pub struct Schemas {
    components: Value,
    nullable_enums_admit_null: bool,
    compiled: Mutex<HashMap<String, Arc<Validator>>>,
}

impl Schemas {
    /// The schemas of `document`.
    #[must_use]
    pub fn of(document: &Document) -> Schemas {
        Schemas::new(document.components().clone())
    }

    /// The schemas of a `components` object.
    #[must_use]
    pub fn new(mut components: Value) -> Schemas {
        // Once, here: the schemas under `components` are the ones most `$ref`s reach, and they are
        // as likely as an operation's own to say "or null" in the older way.
        normalise(&mut components);
        Schemas { components, nullable_enums_admit_null: false, compiled: Mutex::new(HashMap::new()) }
    }

    /// Reads `{"type": ["string", "null"], "enum": ["a", "b"]}` as admitting `null`.
    ///
    /// **Off by default, because the schema as written does not**: JSON Schema applies `enum` as well
    /// as `type`, so on the 0.11.1 line a response whose nullable enum field is `null` — which the
    /// Java application sends — violates its own document. The 0.12 contract adds `null` to those
    /// enums (the nullability customizer). Until then a replay of recorded Java traffic turns this
    /// on, so that the known defect does not hide every other finding, and the defect itself stays
    /// pinned by a test that runs with it off.
    #[must_use]
    pub fn admitting_null_in_nullable_enums(mut self, yes: bool) -> Schemas {
        self.nullable_enums_admit_null = yes;
        if yes {
            admit_null_in_enums(&mut self.components);
        }
        self.compiled = Mutex::new(HashMap::new());
        self
    }

    /// Checks `instance` against the schema called `name` under `components/schemas`.
    pub fn validate_named(&self, name: &str, instance: &Value) -> Result<(), Vec<SchemaError>> {
        let schema = json!({ "$ref": format!("#/components/schemas/{name}") });
        self.validate(&schema, instance)
    }

    /// Checks that `value`, serialized the way a handler would answer it, satisfies the schema
    /// called `name` — what a type's `Serialize` implementation must not drift from.
    pub fn assert_serializes_as<T: Serialize>(&self, name: &str, value: &T) -> Result<(), Vec<SchemaError>> {
        match serde_json::to_value(value) {
            Ok(instance) => self.validate_named(name, &instance),
            Err(error) => {
                Err(vec![SchemaError { instance_path: String::new(), message: format!("not serializable: {error}") }])
            }
        }
    }

    /// Checks `instance` against any schema of this document: inline, or a `$ref` into it.
    pub fn validate(&self, schema: &Value, instance: &Value) -> Result<(), Vec<SchemaError>> {
        let validator = match self.validator(schema) {
            Ok(validator) => validator,
            Err(message) => return Err(vec![SchemaError { instance_path: String::new(), message }]),
        };
        let errors: Vec<SchemaError> = validator
            .iter_errors(instance)
            .map(|error| SchemaError { instance_path: error.instance_path().to_string(), message: error.to_string() })
            .collect();
        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// Checks a response body of `operation` as `status` with `content_type`.
    #[must_use]
    pub fn check_response(
        &self,
        operation: &Operation,
        status: u16,
        content_type: Option<&str>,
        body: &Value,
    ) -> Check {
        let Some(declared) = declared_for_status(operation, status) else {
            return Check::Undeclared(format!("{} {} declares no {status} response", operation.method, operation.path));
        };
        self.check_media(
            declared,
            content_type,
            body,
            &format!("a {status} response of {} {}", operation.method, operation.path),
        )
    }

    /// Checks a request body of `operation` with `content_type`.
    #[must_use]
    pub fn check_request(&self, operation: &Operation, content_type: Option<&str>, body: &Value) -> Check {
        if !operation.has_request_body {
            return Check::Undeclared(format!("{} {} declares no request body", operation.method, operation.path));
        }
        self.check_media(
            &operation.request,
            content_type,
            body,
            &format!("the request of {} {}", operation.method, operation.path),
        )
    }

    fn check_media(&self, declared: &[Media], content_type: Option<&str>, body: &Value, what: &str) -> Check {
        if declared.is_empty() {
            return Check::NotChecked(format!("{what} declares no content"));
        }
        let actual = content_type.map_or_else(String::new, essence);
        if !actual.is_empty() && !is_json(&actual) {
            return Check::NotChecked(format!("{what} is {actual}, not JSON"));
        }
        let candidate = if actual.is_empty() {
            declared.iter().find(|media| media.schema.is_some() && is_json(&essence(&media.media_type)))
        } else {
            best_media(declared, &actual)
        };
        let Some(media) = candidate else {
            return Check::Undeclared(format!("{what} declares no media type matching {actual:?}"));
        };
        let Some(schema) = &media.schema else {
            return Check::NotChecked(format!("{what} declares no schema for {}", media.media_type));
        };
        match self.validate(schema, body) {
            Ok(()) => Check::Valid,
            Err(errors) => Check::Invalid(errors),
        }
    }

    fn validator(&self, schema: &Value) -> Result<Arc<Validator>, String> {
        let key = schema.to_string();
        if let Ok(cache) = self.compiled.lock()
            && let Some(found) = cache.get(&key)
        {
            return Ok(Arc::clone(found));
        }
        let mut subject = schema.clone();
        normalise(&mut subject);
        if self.nullable_enums_admit_null {
            admit_null_in_enums(&mut subject);
        }
        // The checked schema sits beside `components`, so a `$ref` of `#/components/schemas/X`
        // resolves against this one root and against nothing else.
        let root = json!({ "components": self.components, "allOf": [subject] });
        let built = jsonschema::draft202012::options()
            .should_validate_formats(true)
            .build(&root)
            .map_err(|error| format!("the schema does not compile: {error}"))?;
        let built = Arc::new(built);
        if let Ok(mut cache) = self.compiled.lock() {
            cache.insert(key, Arc::clone(&built));
        }
        Ok(built)
    }
}

/// The declared media of `status`: the exact code, else its class (`2XX`), else `default`.
fn declared_for_status(operation: &Operation, status: u16) -> Option<&Vec<Media>> {
    let exact = status.to_string();
    let class = format!("{}XX", status / 100);
    operation
        .responses
        .get(&exact)
        .or_else(|| operation.responses.get(&class))
        .or_else(|| operation.responses.get(&class.to_ascii_lowercase()))
        .or_else(|| operation.responses.get("default"))
}

/// `type/subtype` in lower case, parameters (`; charset=…`) dropped.
fn essence(media_type: &str) -> String {
    media_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
}

fn is_json(essence: &str) -> bool {
    essence == "application/json" || essence.ends_with("+json") || essence == "*/*"
}

/// The declared media type that best matches `actual`: the exact one, then `type/*+json`, then
/// `type/*`, then `*/*`.
fn best_media<'a>(declared: &'a [Media], actual: &str) -> Option<&'a Media> {
    let (actual_type, actual_subtype) = actual.split_once('/')?;
    let rank = |media: &Media| -> Option<u8> {
        let pattern = essence(&media.media_type);
        let (kind, subtype) = pattern.split_once('/')?;
        if pattern == actual {
            Some(4)
        } else if kind == actual_type && subtype.starts_with("*+") && actual_subtype.ends_with(&subtype[1..]) {
            Some(3)
        } else if kind == actual_type && subtype == "*" {
            Some(2)
        } else if pattern == "*/*" {
            Some(1)
        } else {
            None
        }
    };
    declared
        .iter()
        .filter_map(|media| rank(media).map(|score| (score, media)))
        .max_by_key(|(score, _)| *score)
        .map(|(_, media)| media)
}

/// Adds `null` to an `enum` whose `type` already admits it.
fn admit_null_in_enums(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            for value in object.values_mut() {
                admit_null_in_enums(value);
            }
            let admits_null =
                object.get("type").and_then(Value::as_array).is_some_and(|kinds| kinds.contains(&json!("null")));
            if admits_null
                && let Some(Value::Array(allowed)) = object.get_mut("enum")
                && !allowed.contains(&Value::Null)
            {
                allowed.push(Value::Null);
            }
        }
        Value::Array(items) => {
            for item in items {
                admit_null_in_enums(item);
            }
        }
        _ => {}
    }
}

/// Rewrites the two other ways a schema says "or null" into JSON Schema 2020-12's own:
/// `nullable: true` beside a `type` or a `$ref`.
fn normalise(schema: &mut Value) {
    match schema {
        Value::Object(object) => {
            for value in object.values_mut() {
                normalise(value);
            }
            if object.get("nullable") == Some(&Value::Bool(true)) {
                object.remove("nullable");
                match object.get("type").cloned() {
                    Some(Value::String(kind)) => {
                        object.insert("type".to_owned(), json!([kind, "null"]));
                    }
                    Some(Value::Array(mut kinds)) => {
                        if !kinds.contains(&json!("null")) {
                            kinds.push(json!("null"));
                        }
                        object.insert("type".to_owned(), Value::Array(kinds));
                    }
                    _ => {
                        let inner = Value::Object(std::mem::take(object));
                        object.insert("anyOf".to_owned(), json!([inner, { "type": "null" }]));
                    }
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                normalise(item);
            }
        }
        _ => {}
    }
}
