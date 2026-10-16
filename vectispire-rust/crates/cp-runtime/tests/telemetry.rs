//! The plain log line, through a real subscriber: Spring Boot's console format.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io;
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;
use vectispire_cp_runtime::telemetry::Spring;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Captured {
    type Writer = Captured;

    fn make_writer(&'a self) -> Captured {
        self.clone()
    }
}

#[test]
fn a_plain_line_has_the_shape_the_java_control_plane_logs() {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(captured.clone())
        .event_format(Spring { application: "vectispire".to_owned(), pid: 3278 })
        .finish();
    std::thread::Builder::new()
        .name("SpringApplicationShutdownHook".to_owned())
        .spawn(move || {
            tracing::subscriber::with_default(subscriber, || {
                tracing::info!("Graceful shutdown complete");
                tracing::warn!(scans = 3, "Outbox is behind");
                tracing::error!(target: "com::asmolabs::vectispire::core::audit::internal::FileAuditMirror", "Audit entry could not be mirrored");
            });
        })
        .unwrap()
        .join()
        .unwrap();

    let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{text}");

    // `2026-10-16T21:00:00.123Z` then the level right-aligned to five, the pid, `---`, the application,
    // the thread cut to its last fifteen characters, the logger padded to forty, ` : `, the message.
    let shape = |line: &str| -> (String, String) {
        let (instant, rest) = line.split_once(' ').unwrap();
        assert_eq!(instant.len(), 24, "{instant}");
        assert!(
            instant.ends_with('Z') && instant.as_bytes()[10] == b'T' && instant.as_bytes()[19] == b'.',
            "{instant}"
        );
        (instant.to_owned(), rest.to_owned())
    };
    let (_, first) = shape(lines[0]);
    assert!(first.starts_with(" INFO 3278 --- [vectispire] [ionShutdownHook] "), "{first}");
    assert!(first.ends_with(" : Graceful shutdown complete"), "{first}");
    let (_, second) = shape(lines[1]);
    assert!(second.starts_with(" WARN 3278 --- [vectispire] [ionShutdownHook] "), "{second}");
    assert!(second.ends_with(" : Outbox is behind scans=3"), "{second}");
    let (_, third) = shape(lines[2]);
    assert!(third.starts_with("ERROR 3278 --- [vectispire] [ionShutdownHook] c.a.v.c.audit.internal.FileAuditMirror   : Audit entry could not be mirrored"), "{third}");
    // The logger column is forty wide, whatever the logger.
    let column = |line: &str| {
        line.split_once("] ")
            .and_then(|(_, rest)| rest.split_once("] "))
            .map(|(_, rest)| rest.split_once(" : ").unwrap().0.chars().count())
    };
    assert_eq!(column(&first), Some(40));
    assert_eq!(column(&third), Some(40));
}
