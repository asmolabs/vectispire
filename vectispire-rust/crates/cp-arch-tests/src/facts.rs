//! What a source file says, read once with `syn`: the paths it names, the string literals it holds, where it
//! says `unsafe`, which modules it declares.
//!
//! **A syntactic read, and honest about it.** ArchUnit reads the classes the compiler produced, where every
//! reference is resolved; this reads the text. What it sees: every `use`, every path in an expression, a type
//! or an attribute, and the paths and literals inside a macro's tokens (`sqlx::query!("…")` is a macro, and the
//! SQL is in its tokens). What it cannot see: a name brought in by a glob import of a re-exporting crate, or a
//! type reached only through inference. The rules that depend on such a name are therefore also held by Rust's
//! own privacy (a module declared without `pub` cannot be reached from another crate) and by `edges.rs`, which
//! reads the resolved graph. Code under `#[cfg(test)]` is skipped, as ArchUnit imports no tests.

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::Visit;

#[derive(Debug, Clone)]
pub struct PathUse {
    pub segments: Vec<String>,
    pub line: usize,
    /// The inline `mod` blocks the use sits in, inside its file.
    pub inline: Vec<String>,
    pub in_macro: bool,
}

#[derive(Debug, Clone)]
pub struct Literal {
    pub value: String,
    pub line: usize,
    /// `Type::function`, or `function`, the nearest enclosing one.
    pub context: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ModDecl {
    pub name: String,
    /// Declared `pub`, not `pub(crate)` or private.
    pub public: bool,
    /// Carries `#[path = "…"]`: its place cannot be read from the tree.
    pub path_attribute: bool,
    pub line: usize,
    pub parent: Vec<String>,
    pub inline: bool,
}

#[derive(Debug, Default)]
pub struct Facts {
    pub paths: Vec<PathUse>,
    pub literals: Vec<Literal>,
    pub unsafes: Vec<usize>,
    pub mods: Vec<ModDecl>,
    /// The file opens with `#![forbid(unsafe_code)]`.
    pub forbids_unsafe: bool,
}

pub fn read(source: &str) -> Result<Facts, String> {
    let file = syn::parse_file(source).map_err(|error| {
        let start = error.span().start();
        format!("{}:{}: {error}", start.line, start.column)
    })?;
    let mut collector = Collector::default();
    // A file that opens with `#![cfg(test)]` is a test module kept in a file of its own — the inline `#[cfg(test)]
    // mod` of the items below, written where it does not crowd its module — and is skipped as they are.
    if file.attrs.iter().any(|attribute| matches!(attribute.style, syn::AttrStyle::Inner(_)))
        && is_cfg_test(&file.attrs)
    {
        return Ok(collector.facts);
    }
    collector.facts.forbids_unsafe = file.attrs.iter().any(|attribute| {
        matches!(attribute.style, syn::AttrStyle::Inner(_))
            && attribute.path().is_ident("forbid")
            && tokens_of(attribute).split(|c: char| !c.is_alphanumeric() && c != '_').any(|word| word == "unsafe_code")
    });
    collector.visit_file(&file);
    Ok(collector.facts)
}

fn tokens_of(attribute: &syn::Attribute) -> String {
    match &attribute.meta {
        syn::Meta::List(list) => list.tokens.to_string(),
        syn::Meta::NameValue(value) => quote_free(&value.value),
        syn::Meta::Path(_) => String::new(),
    }
}

fn quote_free(expr: &syn::Expr) -> String {
    match expr {
        syn::Expr::Lit(lit) => match &lit.lit {
            syn::Lit::Str(text) => text.value(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

fn is_cfg_test(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg") && {
            let tokens = tokens_of(attribute);
            let words: Vec<&str> = tokens.split(|c: char| !c.is_alphanumeric() && c != '_').collect();
            words.contains(&"test") && !words.contains(&"not")
        }
    })
}

fn attributes_of(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(i) => &i.attrs,
        syn::Item::Enum(i) => &i.attrs,
        syn::Item::ExternCrate(i) => &i.attrs,
        syn::Item::Fn(i) => &i.attrs,
        syn::Item::ForeignMod(i) => &i.attrs,
        syn::Item::Impl(i) => &i.attrs,
        syn::Item::Macro(i) => &i.attrs,
        syn::Item::Mod(i) => &i.attrs,
        syn::Item::Static(i) => &i.attrs,
        syn::Item::Struct(i) => &i.attrs,
        syn::Item::Trait(i) => &i.attrs,
        syn::Item::TraitAlias(i) => &i.attrs,
        syn::Item::Type(i) => &i.attrs,
        syn::Item::Union(i) => &i.attrs,
        syn::Item::Use(i) => &i.attrs,
        _ => &[],
    }
}

#[derive(Default)]
struct Collector {
    facts: Facts,
    inline: Vec<String>,
    context: Vec<String>,
    in_macro: usize,
}

impl Collector {
    fn context(&self) -> Option<String> {
        if self.context.is_empty() { None } else { Some(self.context.join("::")) }
    }

    fn record(&mut self, segments: Vec<String>, line: usize) {
        self.facts.paths.push(PathUse { segments, line, inline: self.inline.clone(), in_macro: self.in_macro > 0 });
    }

    fn flatten(&mut self, tree: &syn::UseTree, prefix: &mut Vec<String>) {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                self.flatten(&path.tree, prefix);
                prefix.pop();
            }
            syn::UseTree::Name(name) => {
                prefix.push(name.ident.to_string());
                self.record(prefix.clone(), name.ident.span().start().line);
                prefix.pop();
            }
            syn::UseTree::Rename(rename) => {
                prefix.push(rename.ident.to_string());
                self.record(prefix.clone(), rename.ident.span().start().line);
                prefix.pop();
            }
            syn::UseTree::Glob(glob) => {
                prefix.push("*".to_owned());
                self.record(prefix.clone(), glob.star_token.spans[0].start().line);
                prefix.pop();
            }
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    self.flatten(item, prefix);
                }
            }
        }
    }

    /// The paths, literals and `unsafe` keywords inside a macro's tokens — where `sqlx::query!` keeps its SQL.
    fn walk_tokens(&mut self, stream: TokenStream) {
        let tokens: Vec<TokenTree> = stream.into_iter().collect();
        let colon = |token: &TokenTree| matches!(token, TokenTree::Punct(p) if p.as_char() == ':');
        let mut i = 0;
        while i < tokens.len() {
            match &tokens[i] {
                TokenTree::Group(group) => {
                    self.walk_tokens(group.stream());
                    i += 1;
                }
                TokenTree::Ident(ident) => {
                    let line = ident.span().start().line;
                    if ident == "unsafe" {
                        self.facts.unsafes.push(line);
                    }
                    let mut segments = vec![ident.to_string()];
                    let mut j = i + 1;
                    while j + 2 < tokens.len() && colon(&tokens[j]) && colon(&tokens[j + 1]) {
                        if let TokenTree::Ident(next) = &tokens[j + 2] {
                            segments.push(next.to_string());
                            j += 3;
                        } else {
                            break;
                        }
                    }
                    if segments.len() >= 2 {
                        self.record(segments, line);
                    }
                    i = j;
                }
                TokenTree::Literal(literal) => {
                    if let Ok(text) = syn::parse_str::<syn::LitStr>(&literal.to_string()) {
                        self.facts.literals.push(Literal {
                            value: text.value(),
                            line: literal.span().start().line,
                            context: self.context(),
                        });
                    }
                    i += 1;
                }
                TokenTree::Punct(_) => i += 1,
            }
        }
    }
}

impl<'ast> Visit<'ast> for Collector {
    fn visit_item(&mut self, node: &'ast syn::Item) {
        if is_cfg_test(attributes_of(node)) {
            return;
        }
        syn::visit::visit_item(self, node);
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        self.flatten(&node.tree, &mut Vec::new());
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        if node.segments.len() >= 2 {
            let line = node.segments[0].ident.span().start().line;
            self.record(node.segments.iter().map(|segment| segment.ident.to_string()).collect(), line);
        }
        syn::visit::visit_path(self, node);
    }

    /// `#[derive(sqlx::FromRow)]` names a path in tokens, as a macro call does.
    fn visit_attribute(&mut self, node: &'ast syn::Attribute) {
        if let syn::Meta::List(list) = &node.meta {
            self.in_macro += 1;
            self.walk_tokens(list.tokens.clone());
            self.in_macro -= 1;
        }
        syn::visit::visit_attribute(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        self.visit_path(&node.path);
        self.in_macro += 1;
        self.walk_tokens(node.tokens.clone());
        self.in_macro -= 1;
    }

    fn visit_lit_str(&mut self, node: &'ast syn::LitStr) {
        self.facts.literals.push(Literal {
            value: node.value(),
            line: node.span().start().line,
            context: self.context(),
        });
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        self.facts.mods.push(ModDecl {
            name: node.ident.to_string(),
            public: matches!(node.vis, syn::Visibility::Public(_)),
            path_attribute: node.attrs.iter().any(|attribute| attribute.path().is_ident("path")),
            line: node.ident.span().start().line,
            parent: self.inline.clone(),
            inline: node.content.is_some(),
        });
        if let Some((_, items)) = &node.content {
            self.inline.push(node.ident.to_string());
            for item in items {
                self.visit_item(item);
            }
            self.inline.pop();
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if node.sig.unsafety.is_some() {
            self.facts.unsafes.push(node.sig.ident.span().start().line);
        }
        self.context.push(node.sig.ident.to_string());
        syn::visit::visit_item_fn(self, node);
        self.context.pop();
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if node.unsafety.is_some() {
            self.facts.unsafes.push(node.impl_token.span.start().line);
        }
        let name = match &*node.self_ty {
            syn::Type::Path(path) => path.path.segments.last().map(|segment| segment.ident.to_string()),
            _ => None,
        };
        let pushed = name.is_some();
        if let Some(name) = name {
            self.context.push(name);
        }
        syn::visit::visit_item_impl(self, node);
        if pushed {
            self.context.pop();
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if is_cfg_test(&node.attrs) {
            return;
        }
        if node.sig.unsafety.is_some() {
            self.facts.unsafes.push(node.sig.ident.span().start().line);
        }
        self.context.push(node.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, node);
        self.context.pop();
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        if node.unsafety.is_some() {
            self.facts.unsafes.push(node.ident.span().start().line);
        }
        syn::visit::visit_item_trait(self, node);
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast syn::ItemForeignMod) {
        if node.unsafety.is_some() {
            self.facts.unsafes.push(node.abi.extern_token.span.start().line);
        }
        syn::visit::visit_item_foreign_mod(self, node);
    }

    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        self.facts.unsafes.push(node.unsafe_token.span.start().line);
        syn::visit::visit_expr_unsafe(self, node);
    }
}
