//! A failing task is logged in Java's sentence, so that one log search finds both programs' failures.
//!
//! **Alone in its test binary on purpose.** `tracing` caches whether a call site is enabled the first time any thread
//! reaches it; with the other turn tests running beside this one under no subscriber, the error call site was cached
//! as disabled before this test's thread-local subscriber could see it, and the assertion failed one run in two.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};

use vectispire_cp_maintenance::{Cadence, MaintenanceTask, Sequence, TaskRun, Turns};

struct Failing {
    sequence: Sequence,
    how: How,
}

enum How {
    Error(&'static str),
    Panic(&'static str),
    /// A panic whose payload is a `&'static str`, as `panic!` with a literal and no argument writes it.
    PanicLiterally,
}

impl MaintenanceTask for Failing {
    fn sequence(&self) -> Sequence {
        self.sequence
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            match self.how {
                How::Error(message) => Err(message.into()),
                How::Panic(message) => panic!("{message}"),
                How::PanicLiterally => panic!("a literal"),
            }
        })
    }
}

struct Writer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn a_failure_is_logged_in_java_s_sentence() {
    let tasks: Vec<Arc<dyn MaintenanceTask>> = vec![
        Arc::new(Failing { sequence: Sequence::ScanRetention, how: How::Error("boom") }),
        Arc::new(Failing { sequence: Sequence::SentMessages, how: How::Panic("bang") }),
        Arc::new(Failing { sequence: Sequence::TicketSweep, how: How::PanicLiterally }),
    ];
    let turns = Turns::new(tasks).unwrap();
    let written = Arc::new(Mutex::new(Vec::<u8>::new()));
    let sink = written.clone();
    let subscriber = tracing_subscriber::fmt().with_writer(move || Writer(sink.clone())).with_ansi(false).finish();
    {
        let _guard = tracing::subscriber::set_default(subscriber);
        turns.turn(Cadence::Hourly).await;
    }
    let text = String::from_utf8(written.lock().unwrap().clone()).unwrap();
    assert!(text.contains("ERROR"), "{text}");
    assert!(text.contains("maintenance: ScanRetentionTask failed, the turn goes on: boom"), "{text}");
    assert!(text.contains("maintenance: SentMessagesTask failed, the turn goes on: panicked: bang"), "{text}");
    assert!(text.contains("maintenance: TicketSweepTask failed, the turn goes on: panicked: a literal"), "{text}");
}
