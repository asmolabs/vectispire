#!/usr/bin/env python3
"""Mutation check of wave 1, access administration stage: four-eyes on account administration — a creation applied
alone when nobody else could approve it, the requester refused as its own approver, the approver independence, a
reset that waits for a pending change, a withdrawal named as one, only an administrator deciding — the gestures
recorded with a creation, and the second factor's reset. See README.md.

Killed by `cp-access`' `four_eyes_on_both_engines` (MySQL, Docker required).
"""
import sys

import _runner

ACCOUNTS = "crates/cp-access/src/accounts.rs"
INDEPENDENCE = "crates/cp-access/src/independence.rs"

FOUR = ["-p", "vectispire-cp-access", "--test", "four_eyes_on_both_engines"]

MUTANTS = [
    ("a second administrator always assumed", ACCOUNTS,
     "Ok(self.count_other_admins(acting).await? > 0)", "Ok(true)", FOUR),
    ("the requester approves its own request", ACCOUNTS,
     "if request.requested_by_id == approver.id {", "if false {", FOUR),
    ("a withdrawal reads as a rejection", ACCOUNTS,
     'let verb = if requester == decider.username { "withdrawn" } else { "rejected" };', 'let verb = "rejected";', FOUR),
    ("any active account decides", ACCOUNTS,
     "account.filter(|account| account.is_active && is_administrative(&account.role))",
     "account.filter(|account| account.is_active)", FOUR),
    ("a reset does not wait for the pending change", ACCOUNTS,
     "if password.is_some() && self.store.request_pending_for(id).await? {",
     "if false && self.store.request_pending_for(id).await? {", FOUR),
    ("a creation records no gesture", ACCOUNTS,
     "Recorded { held_role: None, administrators, made: vec![Gesture::Created], at: Some(at) }",
     "Recorded { held_role: None, administrators, made: Vec::new(), at: Some(at) }", FOUR),
    ("the reset keeps the factor's secret", ACCOUNTS, "        user.totp_secret = None;\n", "", FOUR),
    ("the approver's gestures read the wrong way round", INDEPENDENCE,
     "match self.newest(approver_id, requester_id, window, now).await? {",
     "match self.newest(requester_id, approver_id, window, now).await? {", FOUR),
]

# Not listed:
# - the request's status and the account's role read again before the decision: the store reads both again under the
#   locks and answers the same refusal, so a mutant there is equivalent as far as any outcome goes.
# - a team's webhook refused while `notification.webhook` is off, the issuer's target that must exist, the order the
#   revoked keys are audited in: held by the golden replay (NotificationChannelSwitchRoutesTest,
#   ApiKeyIntegrationRoutesTest), which runs too long for a mutation run.

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900, env={"VECTISPIRE_TEST_ENGINES": "mysql"}))
