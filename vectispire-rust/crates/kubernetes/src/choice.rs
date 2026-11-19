//! What runs the scanners on this agent, chosen once at start (decision 0045) — `ExecutorChoice` and
//! `AgentProperties.Executor`/`Kubernetes`, for the Kubernetes side.
//!
//! **Refused at start, never discovered at the first scan.** An unknown kind, a Kubernetes executor with no namespace
//! or an unreadable placement stops the agent with the property named. A misconfigured executor that started would
//! claim scans and fail every one of them. Then, against the cluster: this agent's leftovers swept, the scans'
//! namespace proved to refuse a privileged pod, and scan pods proved cut off from the API server — each a refusal to
//! start when it does not hold.
//!
//! Held to Java by `reference/kubernetes/choice.json`.

use crate::address::{self, ClusterAddress};
use crate::api::KubernetesApi;
use crate::executor::{HELPER_IMAGE, Isolation, KubernetesExecutor, MatcherCache, Settings};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;
use vectispire_container::ScannerLimits;

/// `vectispire.agent.executor.kubernetes.*`, as configured — `AgentProperties.Kubernetes`, its strings trimmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesConfig {
    /// `VECTISPIRE_SCANS_NAMESPACE`: required.
    pub namespace: String,
    /// `VECTISPIRE_AGENT_NAME`: this agent's name on its scan pods, stable across restarts.
    pub name: String,
    /// `VECTISPIRE_KUBERNETES_HELPER_IMAGE`: blank keeps the pinned busybox.
    pub helper_image: String,
    /// `VECTISPIRE_KUBERNETES_SCAN_USER`: `uid:gid`, blank for this process's own.
    pub user: String,
    /// `VECTISPIRE_KUBERNETES_START_TIMEOUT`, 5 minutes by default.
    pub start_timeout: Duration,
    /// `VECTISPIRE_KUBERNETES_PLACEMENT`: `nodeSelector`, `tolerations` and `affinity`, as JSON.
    pub placement: String,
    /// `VECTISPIRE_KUBERNETES_REQUIRE_ISOLATION`, true by default.
    pub require_isolation: bool,
    /// The address the probe tries; blank is the API server as this pod is told it.
    pub probe_target: String,
    /// `VECTISPIRE_KUBERNETES_SCAN_CPU_MILLIS`, 2000 by default — set, never derived from this host's cores, which are
    /// the agent pod's view of its node: scan pods asking for all but one of them could not be scheduled (measured).
    pub cpu_millis: i64,
    /// `VECTISPIRE_KUBERNETES_SCAN_MEMORY_MIB`, 2048 by default.
    pub memory_mib: i64,
    /// `VECTISPIRE_KUBERNETES_MATCHER_CACHE_CLAIM`: blank copies the matcher's database into each pod.
    pub matcher_cache_claim: String,
    /// `VECTISPIRE_KUBERNETES_NODE_NAME`: where every pod mounting the cache goes.
    pub node_name: String,
    /// `VECTISPIRE_KUBERNETES_REGISTRY_CREDENTIALS`: a Docker configuration directory.
    pub registry_credentials: String,
}

impl Default for KubernetesConfig {
    fn default() -> KubernetesConfig {
        KubernetesConfig {
            namespace: String::new(),
            name: "vectispire-agent".to_owned(),
            helper_image: String::new(),
            user: String::new(),
            start_timeout: Duration::from_secs(300),
            placement: String::new(),
            require_isolation: true,
            probe_target: String::new(),
            cpu_millis: 2000,
            memory_mib: 2048,
            matcher_cache_claim: String::new(),
            node_name: String::new(),
            registry_credentials: String::new(),
        }
    }
}

/// `AgentProperties.Executor.kind`: blank is `docker`; otherwise trimmed and lower-cased.
pub fn kind(configured: &str) -> String {
    if vectispire_domain::java::is_blank(configured) {
        "docker".to_owned()
    } else {
        vectispire_domain::java::to_lower_root(vectispire_domain::java::trim(configured))
    }
}

/// The refusal of a kind that is neither.
pub fn unknown_kind(kind: &str) -> String {
    format!(
        "vectispire.agent.executor.kind (VECTISPIRE_AGENT_EXECUTOR) is \"{kind}\": docker or kubernetes. The agent does \
         not start."
    )
}

/// The refusal of a scan pod with no limit.
pub fn check_resources(cpu_millis: i64, memory_mib: i64) -> Result<(), String> {
    if cpu_millis <= 0 || memory_mib <= 0 {
        return Err("vectispire.agent.executor.kubernetes.cpu-millis and memory-mib are positive: a scan pod with no \
                    limit is not in the closed shape. The agent does not start."
            .to_owned());
    }
    Ok(())
}

/// `ExecutorChoice.placement`: blank is no placement; otherwise a JSON object — its first value, as Jackson reads one.
pub fn placement(text: &str) -> Result<Map<String, Value>, String> {
    if text.is_empty() {
        return Ok(Map::new());
    }
    match crate::json::read_tree(text.as_bytes()) {
        Some(Value::Object(object)) => Ok(object),
        _ => {
            Err("vectispire.agent.executor.kubernetes.placement (VECTISPIRE_KUBERNETES_PLACEMENT) is a JSON object of \
                  nodeSelector, tolerations and affinity. The agent does not start."
                .to_owned())
        }
    }
}

const NO_NAMESPACE: &str = "vectispire.agent.executor.kubernetes.namespace (VECTISPIRE_SCANS_NAMESPACE) is required with \
                            the Kubernetes executor: the namespace whose Role this agent holds. The agent does not start.";

/// What the start needs that only the agent knows: the matcher's database directory, and this process's own user.
#[derive(Debug, Clone)]
pub struct Context {
    /// The database root, whose `generations` the cache serves.
    pub matcher_database: PathBuf,
    /// This process's `uid:gid`: the owner of every workspace it clones, so the default for a run that names none.
    pub own_user: Option<String>,
}

/// The Kubernetes executor, every setting checked before the cluster is asked for — a refusal names the property, not
/// a missing pod — and then the cluster checked: leftovers swept, Pod Security proved, isolation proved.
///
/// `cluster` builds the API client as this pod sees it, asked only once the settings hold; `address` is the API
/// server's address for the probe, asked only when no target is configured.
pub async fn kubernetes(
    config: &KubernetesConfig,
    context: &Context,
    cluster: impl FnOnce() -> Result<KubernetesApi, String>,
    address: impl FnOnce() -> Result<ClusterAddress, String>,
) -> Result<KubernetesExecutor, String> {
    check_resources(config.cpu_millis, config.memory_mib)?;
    if config.namespace.is_empty() {
        return Err(NO_NAMESPACE.to_owned());
    }
    let user = if config.user.is_empty() {
        context.own_user.clone().ok_or_else(|| {
            "This file system reports no owner: set vectispire.agent.executor.kubernetes.user.".to_owned()
        })?
    } else {
        config.user.clone()
    };
    let defaults = ScannerLimits::default_for_this_host();
    // The pod's own resources, never the default's CPU count.
    let limits = ScannerLimits {
        memory: config.memory_mib.saturating_mul(1024 * 1024),
        nano_cpus: config.cpu_millis.saturating_mul(1_000_000),
        ..defaults
    };
    let cache = (!config.matcher_cache_claim.is_empty()).then(|| {
        MatcherCache::new(
            config.matcher_cache_claim.clone(),
            &context.matcher_database.join(GENERATIONS),
            config.node_name.clone(),
        )
    });
    let helper = if config.helper_image.is_empty() { HELPER_IMAGE } else { config.helper_image.as_str() };
    let placement = placement(&config.placement)?;
    let mut settings = Settings::new(
        &config.namespace,
        &config.name,
        helper,
        &user,
        config.start_timeout,
        limits,
        placement,
        cache,
        None,
    )?;
    if !config.registry_credentials.is_empty() {
        let credentials = Path::new(&config.registry_credentials);
        // At start, not at the first plugin: a secret mounted under another key would otherwise read as "no
        // credentials held" on the day a plugin is verified, the refusal blaming the registry.
        if std::fs::read(credentials.join("config.json")).is_err() {
            return Err(format!(
                "vectispire.agent.executor.kubernetes.registry-credentials (VECTISPIRE_KUBERNETES_REGISTRY_CREDENTIALS) \
                 names {}, which holds no readable config.json: mount the pull secret's .dockerconfigjson there as \
                 config.json. The agent does not start.",
                credentials.display()
            ));
        }
    }
    // After the settings: a placement they refuse stops the start whatever the cluster's address.
    let target =
        if config.require_isolation { Some(address::probe_target(&config.probe_target, address)?) } else { None };
    settings.cut_off_from = target.clone();
    let executor = KubernetesExecutor::new(cluster()?, settings);
    // What a crash of this agent left: its pods carry its name, and nobody else removes them.
    executor.sweep().await.map_err(|error| error.to_string())?;
    require_pod_security(&executor, &config.namespace).await?;
    match target {
        Some(target) => require_isolation(&executor, &target).await?,
        None => tracing::warn!(
            "vectispire.agent.executor.kubernetes.require-isolation is false: whether scan pods are cut off from the \
             network is not checked. Scanners read hostile trees."
        ),
    }
    Ok(executor)
}

/// The database's directory of generations — `VulnerabilityDatabase.GENERATIONS`, which both agents share on disk.
const GENERATIONS: &str = "generations";

/// **Refuses the start unless scan pods are cut off**, offline and online alike, from the API server (decision 0045
/// §5). A CNI that does not enforce NetworkPolicy accepts the chart's policies and ignores them; an agent that scanned
/// there would run every scanner with the cluster in reach. A probe that could not run is a refusal too: an unknown is
/// not a proof.
pub async fn require_isolation(executor: &KubernetesExecutor, target: &str) -> Result<(), String> {
    let (host, port) = address::address(target)?;
    for online in [false, true] {
        let found = executor.probe(&host, port, online).await.map_err(|unknown| {
            format!("Whether scan pods are cut off from the network could not be checked: {unknown} The agent does not start.")
        })?;
        if found != Isolation::Enforced {
            return Err(format!(
                "An {} scan pod reached the API server at {target}: scan pods are not cut off. This cluster's CNI does \
                 not enforce NetworkPolicy, or the chart's policies for the scans' namespace are missing. The agent \
                 does not start; scanners read hostile trees.",
                if online { "online" } else { "offline" }
            ));
        }
    }
    tracing::info!(
        "Scan pods are cut off from the API server at {target}, offline and online: the policies are enforced."
    );
    Ok(())
}

/// **Refuses the start unless the scans' namespace refuses a privileged pod** — Pod Security `restricted`, the ceiling
/// on what this agent's Role can start (decision 0045 §3). Not something to turn off: a namespace without it lets a
/// compromised agent start a root pod on any node (review of 2026-10-26, M1).
pub async fn require_pod_security(executor: &KubernetesExecutor, namespace: &str) -> Result<(), String> {
    let found = executor.pod_security().await.map_err(|unknown| {
        format!(
            "Whether the scans' namespace {namespace} refuses a privileged pod could not be checked: {unknown} The agent \
             does not start."
        )
    })?;
    if found != Isolation::Enforced {
        return Err(format!(
            "The scans' namespace {namespace} would admit a privileged pod: label it \
             pod-security.kubernetes.io/enforce=restricted. The agent does not start; its Role creates pods there."
        ));
    }
    tracing::info!("The scans' namespace {namespace} refuses a privileged pod: Pod Security restricted is enforced.");
    Ok(())
}
