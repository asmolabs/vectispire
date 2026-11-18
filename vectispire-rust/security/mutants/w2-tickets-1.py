#!/usr/bin/env python3
"""Mutation check of wave 2, tickets: the sweep's gate and its closing mark, the token refused while the tracker is
suspended, the token's change announced once, the links' visibility first and the tracker's switch, the webhook's
suspended tracker, a settled decision kept and a tracker's refusal queued for approval, a Jira key held to its
project, and the two maintenance slots in the binary's composition. See README.md.

Killed by `vectispire-domain`'s tickets unit tests, `cp-tickets`' engine test (`tickets_on_both_engines`, against a
GitLab stand-in through the real outbound door) and `cp-app`'s `maintenance_composition`. The routes' answers are held
by the golden replay.
"""
import sys

import _runner

SWEEP = "crates/cp-tickets/src/sweep.rs"
SERVICE = "crates/cp-tickets/src/service.rs"
STATE = "crates/cp-tickets/src/token_state.rs"
LINKS = "crates/cp-tickets/src/links.rs"
WEBHOOK = "crates/cp-tickets/src/webhook.rs"
DOMAIN_TICKETS = "crates/domain/src/tickets.rs"
MT = "crates/cp-app/src/maintenance.rs"
DOMAIN = ["-p", "vectispire-domain", "--lib", "tickets"]
ENGINES = ["-p", "vectispire-cp-tickets", "--test", "tickets_on_both_engines"]
MAINT = ["-p", "vectispire-cp-app", "--test", "maintenance_composition"]

MUTANTS = [
    ("a ticket for what the gate passes", SWEEP, "            .passed\n", "            .passed && false\n", ENGINES),
    ("a closed ticket left unmarked", SWEEP,
     "if self.issues.mark_ticket_closed(issue.id, &reference).await? == 0 {", "if false {", ENGINES),
    ("a suspended tracker's token handed out", SERVICE,
     "            return Err(TicketError::IntegrationDisabled(standing.integration));\n", "", ENGINES),
    ("a token's change announced every pass", STATE, "        if previous == current {", "        if false {", ENGINES),
    ("a hidden issue's window judged first", LINKS,
     "        self.visible_issue(issue_id, visibility).await?;\n", "", ENGINES),
    ("a link onto a suspended tracker", LINKS,
     "            self.integrations.require_enabled(integration).await?;\n", "", ENGINES),
    ("a suspended tracker's delivery applied", WEBHOOK,
     "if !self.integrations.is_enabled(integration).await? {", "if false {", ENGINES),
    ("a settled decision moved by a payload", WEBHOOK,
     ".filter(TriageStatus::is_settled)", ".filter(|_| false)", ENGINES),
    ("a tracker's decision settled on the spot", WEBHOOK,
     "&request, false, &self.independence", "&request, true, &self.independence", ENGINES),
    ("a Jira key of another project", DOMAIN_TICKETS,
     "key.eq_ignore_ascii_case(crate::java::trim(project))", "true", DOMAIN),
    ("the tickets' slots not composed", MT, "    tasks.extend(tickets.tasks());\n", "", MAINT),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900))
