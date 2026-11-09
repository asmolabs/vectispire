-- The sealing key an agent receives credentials under is now one it proved, not one it announced.
--
-- **`sealing_public_key` changes meaning.** It held whatever the last `hello` carried, overwritten
-- on every one of them, empty included. From this version it holds only a key signed with the
-- result-signing key an administrator pinned for the agent (decision 0031), written by the agent's
-- signed announcement and by nothing else: a `hello` no longer touches it.
--
-- `sealing_key_generation` is the generation that signature covered — when the agent made the
-- pair, in epoch milliseconds. The control plane keeps the newest it accepted and refuses an older
-- one, so a recorded announcement cannot bring back a key the agent no longer holds.
--
-- **The keys already stored are forgotten.** None of them was ever verified, and keeping one would
-- let the control plane go on sealing for a key nobody vouched for. A delegated agent announces a
-- signed key at its next start; until then it is handed no credential.
--
-- Written once, in common: an added nullable column and an update every engine reads alike.

alter table t_agent add column sealing_key_generation bigint;

update t_agent set sealing_public_key = null;
