//! `ContainerAdministrationService`: the container images under watch — listing them within an allowance, and
//! changing the inventory. As for repositories, each write is one transaction committed before its entry.

use std::collections::BTreeSet;

use vectispire_cp_audit::{AuditOperation, RequestActor};
use vectispire_cp_db::{ScanTarget, Visibility};
use vectispire_domain::asset_tier::AssetTier;
use vectispire_domain::bounded_text;
use vectispire_domain::image_reference::ImageReference;
use vectispire_domain::list_window::ListWindow;

use crate::error::TargetError;
use crate::persistence::{self, ContainerRow, StoreError};
use crate::ports::{LatestScan, QueueError, Queued};
use crate::schedule::{self, COLUMN_LENGTH, ScheduleChoice};
use crate::views::ContainerView;
use crate::{Targets, deletion, naming, schedules_in_force};

/// An image as the inventory shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub container: ContainerView,
    pub latest_scan: Option<LatestScan>,
    pub open_issues: i64,
    pub project_name: Option<String>,
    pub schedule: vectispire_domain::schedules::InForce,
}

/// What an operator asked for; `None` leaves a field alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes {
    pub registry: Option<String>,
    pub image_name: Option<String>,
    pub tag: Option<String>,
    pub scan_interval_minutes: Option<i32>,
    pub scan_cron: Option<String>,
    pub required_agent_label: Option<String>,
    pub tier: Option<String>,
    pub scan_manual_only: Option<bool>,
}

/// A scan queued on request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Triggered {
    pub container: ContainerView,
    pub scan: Queued,
}

/// The reference a `docker pull` receives.
pub fn reference_of(container: &ContainerView) -> ImageReference {
    ImageReference::new(container.registry.as_deref(), Some(&container.image_name), Some(&container.tag))
}

fn reference_of_row(row: &ContainerRow) -> ImageReference {
    ImageReference::new(row.registry.as_deref(), Some(&row.image_name), Some(&row.tag))
}

impl Targets {
    /// Every image the allowance permits, or one page of them, cut from what the caller sees.
    pub async fn list_containers(
        &self,
        allowed: &Visibility,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<Listed>, TargetError> {
        let window = ListWindow::requested(limit, offset).map_err(TargetError::Invalid)?;
        self.containers_listed(allowed, window).await
    }

    async fn containers_listed(
        &self,
        allowed: &Visibility,
        window: Option<ListWindow>,
    ) -> Result<Vec<Listed>, TargetError> {
        let latest = self.scans.latest_per_container().await.map_err(TargetError::Unexpected)?;
        let open = self.backlog.open_per_container().await.map_err(TargetError::Unexpected)?;
        let permitted = persistence::visible_containers(&self.db, allowed).await?;
        let visible = match window {
            Some(page) => page.of(&permitted),
            None => permitted,
        };
        // Named for the visible rows only, as the repository list does.
        let projects: BTreeSet<i64> = visible.iter().filter_map(|row| row.project_id).collect();
        let mut tx = persistence::read(&self.db).await?;
        let project_names = naming::project_names(&mut tx, &projects).await?;
        tx.commit().await.map_err(StoreError::from)?;
        let default_minutes = self.default_interval_minutes().await?;
        Ok(visible
            .iter()
            .map(|row| {
                let view = ContainerView::from(row);
                let schedule = schedules_in_force(
                    view.scan_manual_only,
                    view.scan_cron.as_deref(),
                    view.scan_interval_minutes,
                    default_minutes,
                );
                Listed {
                    latest_scan: latest.get(&row.id).cloned(),
                    open_issues: open.get(&row.id).copied().unwrap_or(0),
                    project_name: row.project_id.and_then(|project| project_names.get(&project).cloned()),
                    schedule,
                    container: view,
                }
            })
            .collect())
    }

    /// One row of the list, read the same way.
    pub async fn listed_container(&self, allowed: &Visibility, id: i64) -> Result<Option<Listed>, TargetError> {
        Ok(self.containers_listed(allowed, None).await?.into_iter().find(|listed| listed.container.id == id))
    }

    /// Files a new image. Validated at the entry point, like a repository URL: a reference reaching a `docker pull`
    /// unchecked is whatever the operator's daemon will fetch.
    pub async fn create_container(
        &self,
        changes: &Changes,
        actor: &RequestActor,
    ) -> Result<ContainerView, TargetError> {
        let tag = schedule::trim(changes.tag.as_deref());
        let reference = ImageReference::new(
            schedule::optional(changes.registry.as_deref()).as_deref(),
            Some(schedule::trim(changes.image_name.as_deref())),
            Some(if tag.is_empty() { "latest" } else { tag }),
        );
        require_fits(&reference)?;
        if let Some(message) = reference.validate() {
            return Err(TargetError::Invalid(message));
        }
        let choice = ScheduleChoice::NONE.apply(
            changes.scan_manual_only,
            changes.scan_interval_minutes,
            changes.scan_cron.as_deref(),
        )?;
        let mut row = ContainerRow {
            registry: reference.registry.clone(),
            image_name: reference.image_name.clone().unwrap_or_default(),
            tag: reference.tag.clone().unwrap_or_default(),
            required_agent_label: schedule::required_label(changes.required_agent_label.as_deref())?,
            tier: AssetTier::from_input(changes.tier.as_deref()).map_err(TargetError::Invalid)?.name().to_owned(),
            ..ContainerRow::default()
        };
        apply_schedule(&mut row, choice);
        let mut tx = persistence::write(&self.db).await?;
        row.id = persistence::insert_container(&mut tx, &row).await?;
        tx.commit().await.map_err(StoreError::from)?;
        self.audit
            .record(actor.entry(
                AuditOperation::SettingUpdated,
                &row.id.to_string(),
                &format!("Image added: {}", reference_of_row(&row).format()),
            ))
            .await;
        Ok(ContainerView::from(&row))
    }

    /// Applies what was sent. Validated as a whole and not field by field: a registry, a name and a tag are only legal
    /// together.
    pub async fn update_container(
        &self,
        id: i64,
        changes: &Changes,
        allowed: &Visibility,
        actor: &RequestActor,
    ) -> Result<ContainerView, TargetError> {
        let mut tx = persistence::write(&self.db).await?;
        let outcome = async {
            // Absent and hidden refused in one sentence, as for a repository.
            let found = persistence::container(&mut tx, id).await?;
            let mut row = vectispire_cp_access::rows::require_visible_row(found, ScanTarget::Container(id), allowed)?;
            let previous = reference_of_row(&row).format();
            let registry = match changes.registry.as_deref() {
                Some(registry) => schedule::optional(Some(registry)),
                None => row.registry.clone(),
            };
            let image_name = match changes.image_name.as_deref() {
                Some(name) => schedule::trim(Some(name)).to_owned(),
                None => row.image_name.clone(),
            };
            let tag = match changes.tag.as_deref() {
                Some(tag) if schedule::trim(Some(tag)).is_empty() => "latest".to_owned(),
                Some(tag) => schedule::trim(Some(tag)).to_owned(),
                None => row.tag.clone(),
            };
            let reference = ImageReference::new(registry.as_deref(), Some(&image_name), Some(&tag));
            require_fits(&reference)?;
            if let Some(message) = reference.validate() {
                return Err(TargetError::Invalid(message));
            }
            row.registry = registry;
            row.image_name = image_name;
            row.tag = tag;
            let choice = ScheduleChoice {
                manual_only: row.scan_manual_only,
                interval_minutes: row.scan_interval_minutes,
                cron: row.scan_cron.clone(),
            }
            .apply(
                changes.scan_manual_only,
                changes.scan_interval_minutes,
                changes.scan_cron.as_deref(),
            )?;
            apply_schedule(&mut row, choice);
            if changes.required_agent_label.is_some() {
                // Normalized on update as on create.
                row.required_agent_label = schedule::required_label(changes.required_agent_label.as_deref())?;
            }
            if changes.tier.is_some() {
                row.tier =
                    AssetTier::from_input(changes.tier.as_deref()).map_err(TargetError::Invalid)?.name().to_owned();
            }
            persistence::update_container(&mut tx, &row).await?;
            Ok::<_, TargetError>((row, previous))
        }
        .await;
        let (row, previous) = match outcome {
            Ok(done) => done,
            Err(refusal) => {
                let _ = tx.rollback().await;
                return Err(refusal);
            }
        };
        tx.commit().await.map_err(StoreError::from)?;
        let now = reference_of_row(&row).format();
        let moved = if now == previous { String::new() } else { format!(" (was {previous})") };
        self.audit
            .record(actor.entry(
                AuditOperation::SettingUpdated,
                &id.to_string(),
                &format!("Image updated: {now}{moved}"),
            ))
            .await;
        Ok(ContainerView::from(&row))
    }

    /// Queues a scan of the image, within the caller's allowance (an integration key is narrowed to its target).
    pub async fn trigger_container(
        &self,
        id: i64,
        allowed: &Visibility,
        actor: &RequestActor,
    ) -> Result<Triggered, TargetError> {
        let mut tx = persistence::read(&self.db).await?;
        let found = persistence::container(&mut tx, id).await?;
        tx.commit().await.map_err(StoreError::from)?;
        let row = vectispire_cp_access::rows::require_visible_row(found, ScanTarget::Container(id), allowed)?;
        let view = ContainerView::from(&row);
        let scan = self.scans.queue_container(&view).await.map_err(|error| match error {
            QueueError::AlreadyQueued(message) => TargetError::Conflict { message, cause: None, members: Vec::new() },
            QueueError::Failed(failure) => TargetError::Unexpected(failure),
        })?;
        self.audit
            .record(actor.entry(
                AuditOperation::ScanTriggered,
                &scan.id.to_string(),
                &format!("Scan requested: {}", reference_of_row(&row).format()),
            ))
            .await;
        Ok(Triggered { container: view, scan })
    }

    /// Deletes the image and everything hanging off it — "Image not found." for an absent or hidden one.
    pub async fn delete_container(
        &self,
        id: i64,
        allowed: &Visibility,
        actor: &RequestActor,
    ) -> Result<(), TargetError> {
        let mut tx = persistence::write(&self.db).await?;
        let outcome = async {
            let found = persistence::container(&mut tx, id).await?;
            let row = found
                .filter(|_| allowed.permits(ScanTarget::Container(id)))
                .ok_or_else(|| TargetError::not_found(IMAGE_NOT_FOUND))?;
            let revoked = deletion::delete_container(&self.purge, &mut tx, id).await?;
            Ok::<_, TargetError>((row, revoked))
        }
        .await;
        let (row, revoked) = match outcome {
            Ok(done) => done,
            Err(refusal) => {
                let _ = tx.rollback().await;
                return Err(refusal);
            }
        };
        tx.commit().await.map_err(StoreError::from)?;
        tracing::info!(container = id, "Container deleted.");
        deletion::record(
            self.audit.as_ref(),
            actor,
            id,
            &format!("image {id}"),
            &format!("Image deleted: {}", reference_of_row(&row).format()),
            &revoked,
        )
        .await;
        Ok(())
    }
}

/// The deletion's refusal, absent and hidden alike.
pub const IMAGE_NOT_FOUND: &str = "Image not found.";

fn require_fits(reference: &ImageReference) -> Result<(), TargetError> {
    if let Some(registry) = reference.registry.as_deref() {
        bounded_text::within(registry, COLUMN_LENGTH, "The registry")?;
    }
    if let Some(name) = reference.image_name.as_deref() {
        bounded_text::within(name, COLUMN_LENGTH, "The image name")?;
    }
    if let Some(tag) = reference.tag.as_deref() {
        bounded_text::within(tag, COLUMN_LENGTH, "The tag")?;
    }
    Ok(())
}

fn apply_schedule(row: &mut ContainerRow, choice: ScheduleChoice) {
    row.scan_manual_only = choice.manual_only;
    row.scan_interval_minutes = choice.interval_minutes;
    row.scan_cron = choice.cron;
}
