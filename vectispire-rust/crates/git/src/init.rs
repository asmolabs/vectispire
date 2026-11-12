//! libgit2's process-wide state, set once.
//!
//! Both calls are `unsafe` in git2 because libgit2 reads these settings without synchronisation: they
//! must be made before any other thread uses libgit2. [`ensure`] makes them under a `Once`, from the
//! first clone, before that clone touches libgit2 — and no other code in the agent uses libgit2.

use crate::https::Https;
use std::sync::Once;

static REGISTERED: Once = Once::new();

/// How long libgit2 waits to connect, and then on a silent socket — SSH and `git://`; HTTPS has its
/// own client, with the clone's timeout.
const CONNECT_TIMEOUT_MILLISECONDS: i32 = 30_000;
const IO_TIMEOUT_MILLISECONDS: i32 = 5 * 60 * 1000;

/// Registers this crate's HTTPS transport for `https://` — and for `http://`, which the URL checks
/// refuse, so that nothing ever falls through to a transport this crate does not control — and sets
/// the socket timeouts.
pub(crate) fn ensure() {
    REGISTERED.call_once(|| {
        for scheme in ["https", "http"] {
            // SAFETY: called once, under `Once`, before this process's first use of libgit2 — the
            // registry is not synchronised, and nothing else registers into it.
            #[allow(unsafe_code)]
            let registered = unsafe {
                git2::transport::register(scheme, |remote| git2::transport::Transport::smart(remote, true, Https))
            };
            if let Err(error) = registered {
                tracing::error!(scheme, %error, "the clone's HTTPS transport could not be registered");
            }
        }
        // SAFETY: as above — once, before any other libgit2 call of this process.
        #[allow(unsafe_code)]
        let timeouts = unsafe {
            git2::opts::set_server_connect_timeout_in_milliseconds(CONNECT_TIMEOUT_MILLISECONDS)
                .and_then(|()| git2::opts::set_server_timeout_in_milliseconds(IO_TIMEOUT_MILLISECONDS))
        };
        if let Err(error) = timeouts {
            tracing::warn!(%error, "libgit2's socket timeouts could not be set; its defaults apply");
        }
    });
}
