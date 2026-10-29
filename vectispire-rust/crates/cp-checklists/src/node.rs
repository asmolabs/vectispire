//! A rule as a tree, read and written as the Java side's Jackson reads and writes it.
//!
//! `serde_json::Value` would do but for one thing: a decimal there is a double, and a rule's ratio is exact. So the
//! reader keeps Jackson's node kinds — an integral number apart from a decimal, as `isIntegralNumber` tells them,
//! and the decimal's own digits — and the route builds the same tree from its form, with the request's digits.

use std::collections::BTreeMap;

use serde_json::Value;
use vectispire_domain::wire::write_string;

use crate::decimal::Decimal;

/// A `JsonNode`, as far as a rule reads one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Null,
    Bool(bool),
    /// An `IntNode`, `LongNode` or `BigIntegerNode`: its decimal text.
    Integer(String),
    /// A `DecimalNode` — a number written with a fraction or an exponent, which `isIntegralNumber` is false for.
    Decimal(Decimal),
    Text(String),
    Array(Vec<Node>),
    /// Members in document order; a member given twice keeps its first place and its last value, as Jackson's
    /// `ObjectNode` keeps them.
    Object(Vec<(String, Node)>),
}

impl Node {
    /// The tree of a parsed document. A number written with a fraction or an exponent is a decimal, as
    /// `USE_BIG_DECIMAL_FOR_FLOATS` reads it; its digits are the shortest that read back as the double serde_json
    /// parsed, which are the written ones for every ratio of up to fifteen significant digits.
    pub fn of(value: &Value) -> Node {
        match value {
            Value::Null => Node::Null,
            Value::Bool(flag) => Node::Bool(*flag),
            Value::Number(number) if number.is_i64() || number.is_u64() => Node::Integer(number.to_string()),
            Value::Number(number) => Decimal::parse(&number.to_string()).map_or(Node::Null, Node::Decimal),
            Value::String(text) => Node::Text(text.clone()),
            Value::Array(items) => Node::Array(items.iter().map(Node::of).collect()),
            Value::Object(members) => {
                Node::Object(members.iter().map(|(name, value)| (name.clone(), Node::of(value))).collect())
            }
        }
    }

    /// `node.get(name)`: a member of an object, `None` for a missing member or anything but an object.
    pub fn get(&self, name: &str) -> Option<&Node> {
        match self {
            Node::Object(members) => members.iter().find(|(member, _)| member == name).map(|(_, value)| value),
            _ => None,
        }
    }

    /// Absent or `null`: what every reader of a rule skips.
    pub fn is_null(node: Option<&Node>) -> bool {
        matches!(node, None | Some(Node::Null))
    }

    /// `isNumber` and `decimalValue()`.
    pub fn decimal(&self) -> Option<Decimal> {
        match self {
            Node::Integer(text) => Decimal::of_integer(text),
            Node::Decimal(decimal) => Some(decimal.clone()),
            _ => None,
        }
    }

    /// `isIntegralNumber() && canConvertToInt()`, and `intValue()`.
    pub fn int(&self) -> Option<i32> {
        match self {
            Node::Integer(text) => text.parse().ok(),
            _ => None,
        }
    }
}

/// What the canonical form is written from: every object's members sorted by name, as `TreeMap` sorts the
/// ASCII names a rule writes.
#[derive(Debug, Clone)]
pub enum Out {
    Text(String),
    Int(i64),
    Bool(bool),
    /// A number already in the form `BigDecimal.toString` writes.
    Number(String),
    Array(Vec<Out>),
    Object(BTreeMap<&'static str, Out>),
}

impl Out {
    /// Compact, as `ObjectMapper.writeValueAsString` writes.
    pub fn write(&self, out: &mut String) {
        match self {
            Out::Text(text) => write_string(out, text),
            Out::Int(value) => out.push_str(&value.to_string()),
            Out::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
            Out::Number(text) => out.push_str(text),
            Out::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Out::Object(members) => {
                out.push('{');
                for (index, (name, value)) in members.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write_string(out, name);
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }
}
