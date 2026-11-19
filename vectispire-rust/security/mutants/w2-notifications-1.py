#!/usr/bin/env python3
"""Mutation check of wave 2, notifications: what a delta selects, who is queued a copy (a channel switched off, a
team without a channel, a team owning through its project), a disabled channel held rather than failed, what keeps a
channel in use and what a save configures, the test button's refusal, the masked destination, the signature and the
chat escaping, the token alert's channels, and the channels in the outbox's registry. See README.md.

Killed by `vectispire-domain`'s notifications unit tests, `cp-notifications`' unit and engine tests
(`notifications_on_both_engines`) and `cp-app`'s `maintenance_composition`. The routes' answers are held by the
golden replay.
"""
import sys

import _runner

SELECTION = "crates/domain/src/notifications/selection.rs"
SIGNATURE = "crates/domain/src/notifications/signature.rs"
CHAT = "crates/domain/src/notifications/chat_text.rs"
ROUTING = "crates/cp-notifications/src/routing.rs"
GATE = "crates/cp-notifications/src/gate.rs"
DESTINATIONS = "crates/cp-notifications/src/destinations.rs"
SERVICE = "crates/cp-notifications/src/service.rs"
ALERTS = "crates/cp-notifications/src/alerts.rs"
MT = "crates/cp-app/src/maintenance.rs"
DOMAIN = ["-p", "vectispire-domain", "--lib", "notifications"]
UNIT = ["-p", "vectispire-cp-notifications", "--lib"]
ENGINES = ["-p", "vectispire-cp-notifications", "--test", "notifications_on_both_engines"]
MAINT = ["-p", "vectispire-cp-app", "--test", "maintenance_composition"]

MUTANTS = [
    ("a quality finding is announced", SELECTION,
     ".filter(|issue| issue.kind != Some(FindingType::Quality))", ".filter(|_| true)", ENGINES),
    ("a switched-off channel is queued a delta", ROUTING,
     "if channel.configured().await? && gate::is_on(&self.integrations, channel.kind()).await? {",
     "if channel.configured().await? {", ENGINES),
    ("a team without a channel is queued a copy", ROUTING,
     "Ok(TeamChannels::with_channel(tx, &owners).await?)", "Ok(owners)", ENGINES),
    ("a team owning through its project is not told", ROUTING,
     "            claims.extend(TeamChannels::teams_granted(tx, KIND_PROJECT, project).await?);\n",
     "            let _ = project;\n", ENGINES),
    ("a switched-off channel fails rather than holds", GATE,
     "Ok(false) => Err(DeliveryError::Held(format!(", "Ok(false) => Err(DeliveryError::Gone(format!(", ENGINES),
    ("a Teams URL without its switch keeps the channel in use", DESTINATIONS,
     'if value(Setting::TeamsEnabled).await? == "true" && set(&value(Setting::TeamsWebhookUrl).await?) {',
     "if set(&value(Setting::TeamsWebhookUrl).await?) {", ENGINES),
    ("a secret is compared with what is stored", DESTINATIONS,
     "&& (setting.is_secret()\n", "&& (false\n", ENGINES),
    ("the test button tests a switched-off channel", SERVICE,
     "        gate::require_enabled(&self.config.integrations, kind).await?;\n", "", ENGINES),
    ("a token alert is queued for a switched-off channel", ALERTS,
     "if !channel.configured().await? || !gate::is_on(&self.integrations, channel.kind()).await? {",
     "if !channel.configured().await? {", ENGINES),
    ("an address is masked as a URL", SERVICE, "if destination.contains('@') {", "if false {", UNIT),
    ("a signature over an empty secret", SIGNATURE, "if crate::java::is_blank(secret) {", "if false {", DOMAIN),
    ("a Slack mention left live", CHAT, '.replace(\'<\', "&lt;")', "", DOMAIN),
    ("the channels not registered with the relay", MT,
     "Registry::new(handlers, notifications.outbox_channels())", "Registry::new(handlers, Vec::new())", MAINT),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900))
