//! An instant a control-plane crate serialises names its wire format.
//!
//! `time`'s own `Serialize` writes an `OffsetDateTime` as an array of its parts — `[2090,1,0,3,22,0,0,0,0]` —
//! where Java's Jackson writes `"2090-01-01T00:03:22Z"`. It compiles, it round-trips through serde, and every
//! client parsing the field as a date breaks. Eight fields of the issues module's exceptions register and triage
//! history went out that way, and only the replay of Java's recorded traffic saw it (2026-10-26): the issues routes
//! were not yet in the replay CI runs. So the rule reads the source instead: a field of a struct deriving
//! `Serialize` whose type is `OffsetDateTime`, `PrimitiveDateTime` or `Date` — bare or in an `Option` — carries a
//! `#[serde(…)]` naming its format (`with`, `serialize_with`) or keeping it off the wire (`skip`,
//! `skip_serializing`).

use syn::visit::Visit;

use crate::graph::Workspace;
use crate::model::{Config, Kind};
use crate::source::read_text;

const TIME_TYPES: [&str; 3] = ["OffsetDateTime", "PrimitiveDateTime", "Date"];

/// Every violation, and how many files were read.
pub fn check(config: &Config, workspace: &Workspace) -> (Vec<String>, usize) {
    let mut violations = Vec::new();
    let mut read: usize = 0;
    for package in workspace.members() {
        if !matches!(
            config.classify(&package.name),
            Kind::Module(_) | Kind::Infrastructure(_) | Kind::UnknownControlPlane
        ) {
            continue;
        }
        for (rel, text) in read_text(&package.dir, &["src"]) {
            read = read.saturating_add(1);
            match syn::parse_file(&text) {
                Ok(file) => {
                    let mut visitor = Fields { found: Vec::new() };
                    visitor.visit_file(&file);
                    violations.extend(visitor.found.into_iter().map(|field| {
                        format!("{}: {rel}: `{field}` is serialised with `time`'s default, an array of numbers: name its format", package.name)
                    }));
                }
                Err(error) => violations.push(format!("{}: {rel}: unreadable: {error}", package.name)),
            }
        }
    }
    violations.sort();
    (violations, read)
}

struct Fields {
    found: Vec<String>,
}

impl<'ast> Visit<'ast> for Fields {
    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        if derives_serialize(&item.attrs) {
            for field in &item.fields {
                if is_time(&field.ty) && !names_its_format(&field.attrs) {
                    let name = field.ident.as_ref().map_or_else(|| "_".to_owned(), ToString::to_string);
                    self.found.push(format!("{}.{name}", item.ident));
                }
            }
        }
        syn::visit::visit_item_struct(self, item);
    }
}

fn derives_serialize(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().filter(|attr| attr.path().is_ident("derive")).any(|attr| {
        let mut found = false;
        // A derive list that does not parse as paths derives nothing this rule can see.
        let _ = attr.parse_nested_meta(|meta| {
            found |= meta.path.segments.last().is_some_and(|segment| segment.ident == "Serialize");
            Ok(())
        });
        found
    })
}

/// `OffsetDateTime`, `time::OffsetDateTime`, `Option<OffsetDateTime>` and the like.
fn is_time(ty: &syn::Type) -> bool {
    let syn::Type::Path(path) = ty else { return false };
    let Some(last) = path.path.segments.last() else { return false };
    if TIME_TYPES.iter().any(|name| last.ident == name) {
        return true;
    }
    if last.ident == "Option"
        && let syn::PathArguments::AngleBracketed(arguments) = &last.arguments
    {
        return arguments
            .args
            .iter()
            .any(|argument| matches!(argument, syn::GenericArgument::Type(inner) if is_time(inner)));
    }
    false
}

fn names_its_format(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().filter(|attr| attr.path().is_ident("serde")).any(|attr| {
        let mut named = false;
        let _ = attr.parse_nested_meta(|meta| {
            named |= ["with", "serialize_with", "skip", "skip_serializing"].iter().any(|key| meta.path.is_ident(key));
            // `default`, `rename = "…"`: a value to step over, or none.
            if meta.input.peek(syn::Token![=]) {
                let _: syn::Expr = meta.value()?.parse()?;
            }
            Ok(())
        });
        named
    })
}
