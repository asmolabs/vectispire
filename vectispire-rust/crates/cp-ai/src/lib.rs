//! The model review's advisor — Java's `core/ai`: a vulnerability explained by the configured model, or by this
//! product when none answers, within what the caller may see, with the exploitation the stored feeds hold.
//!
//! The OWASP report the same model writes is `compliance`'s; the settings' AI section and its endpoint test are
//! `platform`'s. This crate holds what the three advisor routes need: the provider read from the settings and switched
//! by the integrations' registry, the model list, the chat call, and the advice.

#![forbid(unsafe_code)]

pub mod advice;
pub mod advisor;
pub mod ecosystem;
pub mod review;
mod web;

pub use web::{Services, routes};

use std::sync::Arc;

/// What the module is composed over.
#[allow(missing_debug_implementations)] // pools and ports
pub struct AiParts {
    pub settings: vectispire_cp_settings::Settings,
    pub integrations: Arc<vectispire_cp_settings::Integrations>,
    /// The outbound door the model is reached through: the guard decides how far it may be.
    pub post: vectispire_cp_outbound::post::OutboundPost,
    /// Opens the stored OpenAI key.
    pub encryption: Arc<vectispire_cp_crypto::Encryption>,
    pub issues: Arc<vectispire_cp_issues::IssueCatalog>,
    pub feeds: vectispire_cp_threatintel::feeds::ThreatIntel,
}

impl Services {
    /// The module as the binary composes it. Here, not in `web`: a route holds nothing of the pool.
    pub fn new(parts: AiParts) -> Services {
        let AiParts { settings, integrations, post, encryption, issues, feeds } = parts;
        let reviews = review::AiReviewService::new(settings, integrations, post, encryption);
        Services { advisor: advisor::AiAdvisorService::new(reviews.clone(), issues, feeds), reviews }
    }
}
