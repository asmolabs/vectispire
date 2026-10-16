//! A toy contract and a toy control plane that keeps it, for the tests that need a document they
//! can break one thing in.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use vectispire_cp_contract::{Document, RecordingRouter, RouteDecl};

pub const TOY: &str = r##"{
  "openapi": "3.1.0",
  "info": { "title": "Toy", "version": "1.0.0" },
  "security": [ { "BearerAuth": [] } ],
  "paths": {
    "/api/v1/things": {
      "get": {
        "operationId": "listThings",
        "parameters": [
          { "name": "limit", "in": "query", "required": false, "schema": { "type": "integer" } },
          { "name": "X-Trace", "in": "header", "required": false, "schema": { "type": "string" } }
        ],
        "responses": { "200": { "description": "OK", "content": { "*/*": { "schema": { "$ref": "#/components/schemas/Things" } } } } }
      },
      "post": {
        "operationId": "createThing",
        "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Thing" } } } },
        "responses": { "201": { "description": "Created", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Thing" } } } } }
      }
    },
    "/api/v1/things/{id}": {
      "get": {
        "operationId": "getThing",
        "parameters": [ { "name": "id", "in": "path", "required": true, "schema": { "type": "integer", "format": "int64" } } ],
        "responses": {
          "200": { "description": "OK", "content": { "*/*": { "schema": { "$ref": "#/components/schemas/Thing" } } } },
          "404": { "description": "Not found", "content": { "application/problem+json": { "schema": { "$ref": "#/components/schemas/Problem" } } } }
        }
      },
      "delete": {
        "operationId": "deleteThing",
        "security": [ { "BearerAuth": [], "ApiKeyAuth": [] } ],
        "parameters": [ { "name": "id", "in": "path", "required": true, "schema": { "type": "integer", "format": "int64" } } ],
        "responses": { "204": { "description": "Gone" } }
      }
    },
    "/api/v1/things/export": {
      "get": {
        "operationId": "exportThings",
        "responses": { "200": { "description": "OK", "content": { "text/csv": { "schema": { "type": "string" } } } } }
      }
    }
  },
  "components": {
    "securitySchemes": {
      "BearerAuth": { "type": "http", "scheme": "bearer" },
      "ApiKeyAuth": { "type": "apiKey", "in": "header", "name": "X-API-Key" }
    },
    "schemas": {
      "Thing": {
        "type": "object",
        "required": ["id", "name"],
        "properties": {
          "id": { "type": "integer", "format": "int64" },
          "name": { "type": ["string", "null"] },
          "tags": { "type": "array", "items": { "type": "string" } },
          "created": { "type": "string", "format": "date-time" },
          "owner": { "oneOf": [ { "$ref": "#/components/schemas/Owner" }, { "type": "null" } ] },
          "legacy": { "type": "string", "nullable": true }
        }
      },
      "Owner": { "type": "object", "required": ["login"], "properties": { "login": { "type": "string" } } },
      "Things": { "type": "array", "items": { "$ref": "#/components/schemas/Thing" } },
      "Problem": { "type": "object", "required": ["status"], "properties": { "status": { "type": "integer" }, "detail": { "type": "string" } } }
    }
  }
}"##;

pub const TOY_PUBLISHED: &str = "\
# a comment\n\
GET /api/v1/things listThings\n\
POST /api/v1/things createThing\n\
GET /api/v1/things/{id} getThing\n\
DELETE /api/v1/things/{id} deleteThing\n\
GET /api/v1/things/export exportThings\n";

pub fn toy_document() -> Document {
    Document::parse(TOY).unwrap()
}

const THING: &str = r#"{"id":7,"name":"seven","tags":["a","b"]}"#;

/// A control plane that keeps the toy contract, with handlers that answer fixed text so that a
/// golden can pin key order and number spelling.
pub fn toy_control_plane() -> RecordingRouter {
    RecordingRouter::new()
        .route(
            RouteDecl::new("GET", "/api/v1/things", "listThings").query("limit", false).header("X-Trace", false),
            get(|| async { ([("content-type", "application/json")], format!("[{THING}]")) }),
        )
        .route(
            RouteDecl::new("POST", "/api/v1/things", "createThing"),
            post(|| async { (StatusCode::CREATED, [("content-type", "application/json")], THING.to_owned()) }),
        )
        .route(
            RouteDecl::new("GET", "/api/v1/things/{id}", "getThing"),
            get(|| async { ([("content-type", "application/json")], THING.to_owned()) }),
        )
        .route(
            RouteDecl::new("DELETE", "/api/v1/things/{id}", "deleteThing").security(&["ApiKeyAuth", "BearerAuth"]),
            delete(|| async { StatusCode::NO_CONTENT }),
        )
        .route(
            RouteDecl::new("GET", "/api/v1/things/export", "exportThings"),
            get(|| async { ([("content-type", "text/csv")], "id,name\n7,seven\n".to_owned()) }),
        )
}
