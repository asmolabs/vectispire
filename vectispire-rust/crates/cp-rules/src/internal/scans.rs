//! `scanning`'s `ScanRuleSets`, answered by this module's rule set store.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, RwLock};

use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_scanning::ports::{
    BUNDLED_RULE_FILES, PortError, ScanRuleSets, languages_read as scan_languages_read,
};
use vectispire_protocol::StoredFile;

use crate::coverage::rule_tree_path;
use crate::persistence::SemgrepRuleSetRepository;

const REMEMBERED: usize = 16;

/// `ScanRuleSets` port implementation backed by `t_semgrep_rule_set`.
#[derive(Clone)]
pub struct RuleSetsForScans {
    repo: Arc<SemgrepRuleSetRepository>,
    cache: Arc<RwLock<HashMap<String, BTreeSet<&'static str>>>>,
}

impl std::fmt::Debug for RuleSetsForScans {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleSetsForScans").finish_non_exhaustive()
    }
}

impl RuleSetsForScans {
    pub fn new(repo: Arc<SemgrepRuleSetRepository>) -> Self {
        Self { repo, cache: Arc::new(RwLock::new(HashMap::new())) }
    }
}

impl ScanRuleSets for RuleSetsForScans {
    fn active_hash(&self) -> BoxFuture<'_, Result<Option<String>, PortError>> {
        Box::pin(async move {
            let row = self.repo.find_active().await.map_err(|e| Box::new(e) as PortError)?;
            Ok(row.map(|r| r.content_hash))
        })
    }

    fn files_of<'a>(&'a self, content_hash: &'a str) -> BoxFuture<'a, Result<Vec<StoredFile>, PortError>> {
        Box::pin(async move {
            let Some(row) = self
                .repo
                .find_first_by_content_hash_order_by_id_asc(content_hash)
                .await
                .map_err(|e| Box::new(e) as PortError)?
            else {
                return Ok(Vec::new());
            };

            let files: Vec<StoredFile> = serde_json::from_str(&row.files).map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("The stored rules of set {} cannot be read back: {e}", row.id),
                )) as PortError
            })?;

            Ok(files)
        })
    }

    fn languages_read<'a>(
        &'a self,
        content_hash: Option<&'a str>,
    ) -> BoxFuture<'a, Result<BTreeSet<&'static str>, PortError>> {
        Box::pin(async move {
            let bundled = scan_languages_read(BUNDLED_RULE_FILES);
            let Some(hash) = content_hash else {
                return Ok(bundled);
            };

            if let Some(cached) = self.cache.read().ok().and_then(|guard| guard.get(hash).cloned()) {
                let mut all = bundled.clone();
                all.extend(cached);
                return Ok(all);
            }

            let files = self.files_of(hash).await?;
            if files.is_empty() {
                return Ok(bundled);
            }

            let tree_paths: Vec<String> = files.iter().map(rule_tree_path).collect();
            let paths_refs: Vec<&str> = tree_paths.iter().map(String::as_str).collect();
            let discovered = scan_languages_read(paths_refs);

            if let Ok(mut guard) = self.cache.write() {
                if guard.len() >= REMEMBERED {
                    guard.clear();
                }
                guard.insert(hash.to_owned(), discovered.clone());
            }

            let mut all = bundled;
            all.extend(discovered);
            Ok(all)
        })
    }
}
