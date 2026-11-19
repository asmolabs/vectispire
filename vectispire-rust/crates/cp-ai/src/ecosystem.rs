//! `Ecosystem`: the package ecosystems an upgrade command can be written for, named by a purl's type.
//!
//! **A command only for the ecosystem the component is in.** The advice offered Maven's and npm's side by side whatever
//! the component; the purl the scanner recorded says which ecosystem it belongs to, and a component without one, or of
//! a type not listed here, gets no command — none is better than one that looks right and is not. RubyGems is left out
//! for that reason: Bundler has no one command that moves a gem already in the Gemfile to a given version.

use vectispire_domain::java;

/// An upgrade to copy: the command line, and the dependency declaration for an ecosystem whose manifest is edited by
/// hand (empty otherwise).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upgrade {
    pub command: String,
    pub descriptor: String,
}

/// A purl's type, namespace and name, decoded; the version, qualifiers and subpath dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Coordinates {
    kind: String,
    namespace: Option<String>,
    name: String,
}

impl Coordinates {
    fn qualified_name(&self, separator: &str) -> String {
        match &self.namespace {
            None => self.name.clone(),
            Some(namespace) => format!("{namespace}{separator}{}", self.name),
        }
    }

    fn parse(purl: Option<&str>) -> Option<Coordinates> {
        let purl = java::trim(purl?);
        let mut value = purl.strip_prefix("pkg:")?;
        for separator in ['#', '?'] {
            if let Some((before, _)) = value.split_once(separator) {
                value = before;
            }
        }
        if let Some(at) = value.rfind('@').filter(|at| *at > 0) {
            value = value.get(..at).unwrap_or(value);
        }
        // `String.split("/")`: trailing empty parts dropped.
        let mut parts: Vec<&str> = value.split('/').collect();
        while parts.len() > 1 && parts.last().is_some_and(|part| part.is_empty()) {
            parts.pop();
        }
        let (first, rest) = parts.split_first()?;
        let (last, middle) = rest.split_last()?;
        let kind = java::to_lower_root(first);
        let name = decode(last)?;
        let namespace = if middle.is_empty() { None } else { Some(decode(&middle.join("/"))?) };
        // A name a shell would read as something else never reaches a command.
        if !safe_part(&name) || namespace.as_deref().is_some_and(|namespace| !safe_part(namespace)) {
            return None;
        }
        Some(Coordinates { kind, namespace, name })
    }
}

/// `URLDecoder.decode(part.replace("+", "%2B"), UTF_8)`, none when malformed or blank.
fn decode(part: &str) -> Option<String> {
    let bytes = part.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        if byte == b'%' {
            let high = bytes.get(at.saturating_add(1)).and_then(|digit| char::from(*digit).to_digit(16))?;
            let low = bytes.get(at.saturating_add(2)).and_then(|digit| char::from(*digit).to_digit(16))?;
            decoded.push(u8::try_from(high.saturating_mul(16).saturating_add(low)).ok()?);
            at = at.saturating_add(3);
        } else {
            decoded.push(byte);
            at = at.saturating_add(1);
        }
    }
    let text = String::from_utf8_lossy(&decoded).into_owned();
    (!java::is_blank(&text)).then_some(text)
}

/// `[A-Za-z0-9@][A-Za-z0-9._~/@-]*`.
fn safe_part(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|first| first.is_ascii_alphanumeric() || first == '@')
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '/' | '@' | '-'))
}

/// `[A-Za-z0-9][A-Za-z0-9.+_~-]*`: one version, no list and nothing a shell reads — a scanner records several fixed
/// versions for several release lines, and which applies is the reader's choice, not a command to copy.
fn one_version(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next().is_some_and(|first| first.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '_' | '~' | '-'))
}

/// `upgradeOf`: none when the purl is missing or unreadable, its type is not one listed here, or the version is not
/// one version.
pub fn upgrade_of(purl: Option<&str>, version: Option<&str>) -> Option<Upgrade> {
    let version = java::trim(version?);
    if !one_version(version) {
        return None;
    }
    let component = Coordinates::parse(purl)?;
    let plain = |command: String| Some(Upgrade { command, descriptor: String::new() });
    match component.kind.as_str() {
        "maven" => {
            let namespace = component.namespace.as_ref()?;
            Some(Upgrade {
                command: format!(
                    "mvn versions:use-dep-version -Dincludes={namespace}:{} -DdepVersion={version} -DforceVersion=true",
                    component.name
                ),
                descriptor: format!(
                    "<dependency>\n    <groupId>{namespace}</groupId>\n    <artifactId>{}</artifactId>\n    \
                     <version>{version}</version>\n</dependency>",
                    component.name
                ),
            })
        }
        "npm" => plain(format!("npm install {}@{version}", component.qualified_name("/"))),
        "pypi" => plain(format!("pip install \"{}=={version}\"", component.name)),
        "cargo" => plain(format!("cargo update -p {} --precise {version}", component.name)),
        "nuget" => plain(format!("dotnet add package {} --version {version}", component.name)),
        "composer" => plain(format!("composer require {}:{version}", component.qualified_name("/"))),
        "golang" => {
            // A Go module version is semver with its leading v, which `go get` requires.
            let tagged = if version.starts_with('v') { version.to_owned() } else { format!("v{version}") };
            plain(format!("go get {}@{tagged}", component.qualified_name("/")))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(purl: &str, version: &str) -> Option<String> {
        upgrade_of(Some(purl), Some(version)).map(|upgrade| upgrade.command)
    }

    #[test]
    fn a_command_for_the_ecosystem_the_purl_names() {
        assert_eq!(command("pkg:npm/%40scope/lib@1.0.0", "1.2.3").as_deref(), Some("npm install @scope/lib@1.2.3"));
        assert_eq!(command("pkg:npm/lodash", " 4.17.21 ").as_deref(), Some("npm install lodash@4.17.21"));
        assert_eq!(command("pkg:pypi/django@3.2", "3.2.25").as_deref(), Some("pip install \"django==3.2.25\""));
        assert_eq!(command("pkg:cargo/serde@1", "1.0.200").as_deref(), Some("cargo update -p serde --precise 1.0.200"));
        assert_eq!(
            command("pkg:nuget/Newtonsoft.Json@12", "13.0.1").as_deref(),
            Some("dotnet add package Newtonsoft.Json --version 13.0.1")
        );
        assert_eq!(
            command("pkg:composer/laravel/framework@8", "8.83.27").as_deref(),
            Some("composer require laravel/framework:8.83.27")
        );
        assert_eq!(
            command("pkg:golang/golang.org/x/net@v0.1.0", "0.23.0").as_deref(),
            Some("go get golang.org/x/net@v0.23.0")
        );
        assert_eq!(command("pkg:golang/github.com/a/b", "v1.2.0").as_deref(), Some("go get github.com/a/b@v1.2.0"));
        let maven = upgrade_of(Some("pkg:maven/org.example/thing@1?type=jar#x"), Some("2.0")).unwrap();
        assert_eq!(
            maven.descriptor,
            "<dependency>\n    <groupId>org.example</groupId>\n    <artifactId>thing</artifactId>\n    <version>2.0</version>\n</dependency>"
        );
    }

    #[test]
    fn none_rather_than_one_that_looks_right() {
        assert_eq!(command("pkg:maven/thing@1", "2.0"), None, "maven needs a group");
        assert_eq!(command("pkg:gem/rails@6", "7.0"), None, "no one Bundler command");
        assert_eq!(command("pkg:npm/lodash", "2.12.2, 2.16.0"), None, "a list of versions");
        assert_eq!(command("pkg:npm/lodash", "1;rm -rf"), None);
        assert_eq!(command("pkg:npm/lo%20dash", "1.0"), None, "a space in a name");
        assert_eq!(command("pkg:npm/%zz", "1.0"), None, "malformed escape");
        assert_eq!(command("npm/lodash", "1.0"), None, "not a purl");
        assert_eq!(command("pkg:npm", "1.0"), None, "no name");
        assert_eq!(upgrade_of(None, Some("1.0")), None);
        assert_eq!(upgrade_of(Some("pkg:npm/lodash"), None), None);
        assert_eq!(
            command("pkg:npm/lodash/", "1.0").as_deref(),
            Some("npm install lodash@1.0"),
            "a trailing slash dropped"
        );
        assert_eq!(command("PKG:npm/lodash", "1.0"), None, "the scheme is case-sensitive");
        assert_eq!(command("pkg:NPM/lodash", "1.0").as_deref(), Some("npm install lodash@1.0"), "the type is not");
    }
}
