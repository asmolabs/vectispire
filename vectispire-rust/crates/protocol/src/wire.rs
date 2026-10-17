//! The bodies, as the control plane writes and reads them.
//!
//! **Read leniently, as the Java agent's mapper reads** (`FAIL_ON_UNKNOWN_PROPERTIES` off): a field a
//! newer control plane adds is passed over, a field it leaves out reads as absent, and a `null` reads
//! as the field's absence. What is *not* lenient is what Jackson refuses too — an unknown target kind,
//! an unknown step — which leaves the claim unreadable rather than a task run some other way.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeSet;
use vectispire_domain::secret::Secret;

/// What the agent says about itself at hello — `HelloRequest`, in its snake case.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Description {
    pub contract_version: &'static str,
    pub hostname: String,
    pub platform: String,
    pub scanner_engine: String,
    /// Unsigned, for a control plane older than decision 0031; a current one believes only the
    /// signed announcement that follows the hello.
    pub sealing_public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// What the control plane answers at hello — `HelloResponse`, in its camel case.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub id: Option<String>,
    pub name: Option<String>,
    pub contract_version: Option<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub max_concurrent: i32,
    pub credentials_mode: Option<String>,
}

/// How the agent's clones are credentialed — `CredentialsMode`, by its lower-case wire name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialsMode {
    /// The agent's own git access. The default and the recommendation.
    Local,
    /// The control plane seals each repository's key or token to this process.
    Delegated,
}

impl CredentialsMode {
    pub fn by_wire_name(value: Option<&str>) -> Option<CredentialsMode> {
        match value? {
            "local" => Some(CredentialsMode::Local),
            "delegated" => Some(CredentialsMode::Delegated),
            _ => None,
        }
    }

    /// Whether a key may be decrypted for this agent at all.
    pub fn delivers_credentials(self) -> bool {
        self == CredentialsMode::Delegated
    }
}

/// A claimed scan — `AssignedTask`. Read by the agent; written by the control plane, field for field as
/// Spring MVC writes `ScanDispatcher.AgentTask` (`server::write`).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssignedTask {
    pub scan_id: i64,
    /// Which attempt of the scan the claim is, which a failure report names; absent from a control
    /// plane older than the report, which has no route to send it to either.
    pub attempt: Option<i32>,
    pub task: ScanTask,
}

/// What a scan has to do — `ScanTask`. Decided by the control plane, executed by the runner.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanTask {
    pub target: Target,
    /// The uploaded rule set that must be used, or absent for the bundled rules alone. Carried by the
    /// task rather than read by the executor, so two agents cannot scan with two sets.
    pub rules_hash: Option<String>,
    /// Written in the enum's order. Java writes `Set.copyOf`'s, which changes with each start of the JVM;
    /// the agent reads a set either way.
    #[serde(default, deserialize_with = "null_as_default")]
    pub steps: BTreeSet<Step>,
    /// The plugins this scan runs, each by id and manifest digest. Absent from an older control
    /// plane: no plugin step, which ingestion reads as absent.
    #[serde(default, deserialize_with = "null_as_default")]
    pub plugins: Vec<PluginRef>,
}

impl ScanTask {
    pub fn runs(&self, step: Step) -> bool {
        self.steps.contains(&step)
    }

    /// The directory of the repository to scan, for a repository target that names one.
    pub fn sub_path(&self) -> Option<&str> {
        match &self.target {
            Target::Repository(repository) => repository.sub_path.as_deref(),
            Target::Image(_) => None,
        }
    }

    /// The secrets this task carries, in the clear once opened — what a failure reason is scrubbed of.
    pub fn secrets(&self) -> Vec<&Secret> {
        match &self.target {
            Target::Repository(repository) => repository
                .private_key
                .iter()
                .chain(repository.https.as_ref().and_then(|https| https.token.as_ref()))
                .collect(),
            Target::Image(_) => Vec::new(),
        }
    }
}

/// What a scan can run — `ScanTask.Step`, by the Java enum's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Step {
    Dependencies,
    Secrets,
    Iac,
    Sast,
}

/// A repository or an image, never both — `ScanTask.Target`, discriminated by `kind`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Target {
    Repository(Repository),
    Image(Image),
}

/// A repository to clone — `ScanTask.Target.Repository`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Repository {
    pub url: String,
    pub branch: Option<String>,
    pub sub_path: Option<String>,
    /// The deployment key: sealed to this process on the wire, in the clear once opened; absent for a
    /// public repository or an agent in `local` mode.
    #[serde(default, deserialize_with = "secret", serialize_with = "sealed")]
    pub private_key: Option<Secret>,
    /// A token for one host (decision 0022); never set together with `private_key`.
    pub https: Option<HttpsCredential>,
}

/// A token for one host — `ScanTask.Target.HttpsCredential`. The host travels with the token so that
/// the clone presents it to that host and to no other, whatever the URL or a redirect names.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpsCredential {
    pub host: Option<String>,
    /// What the forge expects beside the token; blank sends a fixed placeholder.
    pub username: Option<String>,
    #[serde(default, deserialize_with = "secret", serialize_with = "sealed")]
    pub token: Option<Secret>,
}

/// An image to scan — `ScanTask.Target.Image`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Image {
    pub reference: ImageReference,
    /// The variant to pull: the image scanned must be the one that runs.
    pub platform: Option<String>,
}

/// `ImageReference`: a registry (blank for Docker Hub's default), a name, and a tag or a digest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageReference {
    pub registry: Option<String>,
    pub image_name: String,
    pub tag: String,
}

impl ImageReference {
    /// As a pull names it — `ImageReference.format`: a digest joins with `@`, a tag with `:`.
    pub fn format(&self) -> String {
        let base = match self.registry.as_deref() {
            None | Some("") => self.image_name.clone(),
            Some(registry) => format!("{registry}/{}", self.image_name),
        };
        if self.tag.starts_with("sha256:") { format!("{base}@{}", self.tag) } else { format!("{base}:{}", self.tag) }
    }
}

/// A plugin as a task names it — `PluginRef`: its id and the digest of the manifest to run.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginRef {
    pub id: String,
    pub digest: String,
    /// The platform governor waived the signature requirement for this plugin (decision 0017 §9.1).
    /// Absent from an older control plane's task, which reads as no waiver: the safe side.
    #[serde(default, deserialize_with = "null_as_default")]
    pub runs_unsigned: bool,
}

/// A file of an uploaded Semgrep rule set — `RuleSet.StoredFile`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredFile {
    /// `rule-0001.yaml`: the name Vectispire chose, never the upload's.
    pub path: String,
    pub original_name: Option<String>,
    pub content: String,
}

/// A `null` read as the type's default, as the Java records' compact constructors turn a `null` list
/// into an empty one.
fn null_as_default<'de, D: Deserializer<'de>, T: Default + Deserialize<'de>>(deserializer: D) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// A credential as the control plane writes it into a claim: the envelope sealed to the agent's announced
/// key (`crypto::seal`), never a key in the clear — the claim crosses the channel the sealing distrusts.
fn sealed<S: Serializer>(value: &Option<Secret>, serializer: S) -> Result<S::Ok, S::Error> {
    value.as_ref().map(Secret::expose).serialize(serializer)
}

/// A credential, held as a [`Secret`] from the moment it is read.
fn secret<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Secret>, D::Error> {
    Ok(Option::<String>::deserialize(deserializer)?.map(Secret::new))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repository_task_is_read_with_its_credential_held_secret() {
        let assigned: AssignedTask = serde_json::from_str(
            r#"{"scanId":7,"attempt":2,"task":{"target":{"kind":"repository","url":"https://h/p.git","branch":"main",
            "subPath":null,"privateKey":null,"https":{"host":"h","username":null,"token":"invented-token"}},
            "rulesHash":"abc","steps":["SECRETS","SAST"],"plugins":[{"id":"a","digest":"d"},
            {"id":"b","digest":"d","runsUnsigned":true}],"aFieldFromTheFuture":1}}"#,
        )
        .unwrap();
        assert_eq!((assigned.scan_id, assigned.attempt), (7, Some(2)));
        assert!(assigned.task.runs(Step::Secrets) && !assigned.task.runs(Step::Iac));
        assert_eq!(assigned.task.plugins[1], PluginRef { id: "b".into(), digest: "d".into(), runs_unsigned: true });
        assert!(!assigned.task.plugins[0].runs_unsigned, "absent is no waiver");
        assert_eq!(assigned.task.secrets().len(), 1);
        let dump = format!("{assigned:?}");
        assert!(!dump.contains("invented-token"), "a task's debug dump holds no credential: {dump}");
    }

    #[test]
    fn an_older_control_plane_s_claim_is_read_without_its_attempt_or_its_plugins() {
        let assigned: AssignedTask = serde_json::from_str(
            r#"{"scanId":7,"task":{"target":{"kind":"image","reference":{"registry":"docker.io",
            "imageName":"library/alpine","tag":"3"},"platform":null},"steps":null}}"#,
        )
        .unwrap();
        assert_eq!(assigned.attempt, None);
        assert!(assigned.task.steps.is_empty() && assigned.task.plugins.is_empty());
        let Target::Image(image) = &assigned.task.target else { panic!("an image") };
        assert_eq!(image.reference.format(), "docker.io/library/alpine:3");
    }

    #[test]
    fn what_jackson_refuses_is_refused_here_too() {
        for refused in [
            r#"{"scanId":1,"task":{"target":{"kind":"bucket","url":"s3://x"}}}"#,
            r#"{"scanId":1,"task":{"target":{"kind":"image","reference":{"imageName":"a","tag":"1"}},"steps":["FUZZ"]}}"#,
            r#"{"scanId":1,"task":{"steps":[]}}"#,
        ] {
            assert!(serde_json::from_str::<AssignedTask>(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn a_digest_joins_with_an_at_sign_and_a_blank_registry_is_left_out() {
        let reference =
            ImageReference { registry: Some(String::new()), image_name: "a/b".into(), tag: "sha256:ff".into() };
        assert_eq!(reference.format(), "a/b@sha256:ff");
    }
}
