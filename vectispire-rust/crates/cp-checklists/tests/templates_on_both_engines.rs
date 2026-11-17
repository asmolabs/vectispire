//! A template's life on a real database of each engine the run selects: imported as a draft, one draft at a time, its
//! layout confirmed at the revision read and refused at a stale one, published, retired once — and a deleted project's
//! rows purged through `ProjectDeleted`'s listener. The routes' answers are the golden replay's; this holds the
//! statements and the conditional updates to the engines.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use serde_json::Value;
use vectispire_cp_audit::{AuditLog, NoMirror, RequestActor};
use vectispire_cp_checklists::error::{Cause, ChecklistError};
use vectispire_cp_checklists::templates::{AnswerWordsForm, ChecklistTemplates, Editor, HeaderCellForm, LayoutForm};
use vectispire_cp_db::testing::{TestDatabase, runs_on};
use vectispire_cp_db::{Engine, Mode};
use vectispire_cp_targets::ProjectPurge;

/// The first version of the workbook reference set: its workbook and the layout Java confirmed on it.
fn fixture() -> (Vec<u8>, LayoutForm) {
    use base64::Engine as _;
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/checklists/workbooks.json");
    let set: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let version = &set["versions"][0];
    let workbook = &set["workbooks"][version["workbook"].as_u64().unwrap() as usize];
    let bytes = base64::engine::general_purpose::STANDARD.decode(workbook["xlsx"].as_str().unwrap()).unwrap();
    let layout = &version["layout"];
    let pairs = |value: &Value| -> Vec<Vec<Option<String>>> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| pair.as_array().unwrap().iter().map(|part| part.as_str().map(str::to_owned)).collect())
            .collect()
    };
    let answers = layout["answers"].as_array().unwrap();
    let form = LayoutForm {
        sheet: layout["sheet"].as_str().map(str::to_owned),
        columns: Some(
            pairs(&layout["columns"]).into_iter().map(|pair| (pair[0].clone().unwrap(), pair[1].clone())).collect(),
        ),
        first_item_row: layout["firstItemRow"].as_i64().map(|row| row as i32),
        last_item_row: layout["lastItemRow"].as_i64().map(|row| row as i32),
        header: Some(
            pairs(&layout["header"])
                .into_iter()
                .map(|cell| {
                    (cell[0].clone().unwrap(), Some(HeaderCellForm { label: cell[1].clone(), value: cell[2].clone() }))
                })
                .collect(),
        ),
        answers: Some(AnswerWordsForm {
            yes: answers[0].as_str().map(str::to_owned),
            no: answers[1].as_str().map(str::to_owned),
            not_applicable: answers[2].as_str().map(str::to_owned),
        }),
    };
    (bytes, form)
}

fn editor(account_id: i64, name: &str) -> Editor {
    Editor {
        account_id,
        actor: RequestActor { username: Some(name.into()), ip_address: Some("127.0.0.1".into()), user_agent: None },
    }
}

fn cause(result: Result<impl std::fmt::Debug, ChecklistError>) -> Option<Cause> {
    result.err().and_then(|error| error.cause())
}

async fn on(engine: Engine) {
    let database = TestDatabase::start(engine).await;
    let db = database.connect().await;
    let settings = Arc::new(vectispire_cp_settings::Settings::new(db.clone()));
    let audit =
        Arc::new(AuditLog::new(db.clone(), Arc::new(NoMirror), Arc::new(vectispire_cp_audit::SystemClock), Vec::new()));
    let templates = ChecklistTemplates::new(
        db.clone(),
        settings.clone(),
        audit,
        vectispire_cp_access::independence::ApproverIndependence::new(db.clone(), settings),
        Arc::new(vectispire_cp_targets::SystemClock),
        10 * 1024 * 1024,
    );
    let (workbook, layout) = fixture();
    let who = editor(1, "lead");
    let reviewer = editor(2, "reviewer");

    let draft = templates.import_workbook(Some("release"), Some("Release"), None, &workbook, &who).await.unwrap();
    assert_eq!((draft.version.ordinal, draft.version.status.as_str(), draft.version.revision), (1, "draft", 1));
    assert_eq!(
        cause(templates.import_workbook(Some("release"), None, None, &workbook, &who).await),
        Some(Cause::TemplateHasDraft),
        "one draft at a time"
    );

    let confirmed = templates.confirm_layout(Some("release"), 1, Some(1), Some(&layout), &who).await.unwrap();
    assert_eq!(confirmed.version.revision, 2);
    assert!(!confirmed.items.is_empty(), "the items are read from the workbook by the layout");
    assert_eq!(
        cause(templates.confirm_layout(Some("release"), 1, Some(1), Some(&layout), &who).await),
        Some(Cause::TemplateChanged),
        "a stale revision is refused"
    );

    // Four-eyes is on unless set off: an author does not publish what they wrote, in a name reused either.
    assert_eq!(cause(templates.publish(Some("release"), 1, Some(2), &who).await), Some(Cause::FourEyes));
    assert_eq!(
        cause(templates.publish(Some("release"), 1, Some(2), &editor(9, " LEAD ")).await),
        Some(Cause::FourEyes)
    );
    let published = templates.publish(Some("release"), 1, Some(2), &reviewer).await.unwrap();
    assert_eq!((published.version.status.as_str(), published.version.revision), ("published", 3));
    assert!(published.version.published_at.is_some());

    let derived = templates.derive(Some("release"), 1, Some("next"), &who).await.unwrap();
    assert_eq!((derived.version.ordinal, derived.version.previous_ordinal), (2, Some(1)));
    assert_eq!(derived.items.len(), published.items.len(), "the same items under the same keys");

    let retired = templates.retire(Some("release"), 1, &reviewer).await.unwrap();
    assert_eq!(retired.version.status, "retired");
    assert_eq!(cause(templates.retire(Some("release"), 1, &reviewer).await), Some(Cause::TemplateRetired));
    let listed = templates.list(None, None).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].versions.len(), 2);

    // `ProjectDeleted`: nothing left naming the project, in the deletion's transaction.
    let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
    vectispire_cp_checklists::ChecklistPurge.purge(&mut tx, 4242).await.unwrap();
    tx.commit().await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn a_template_s_life_on_both_engines() {
    for engine in Engine::ALL {
        if runs_on(engine) {
            on(engine).await;
        }
    }
}
