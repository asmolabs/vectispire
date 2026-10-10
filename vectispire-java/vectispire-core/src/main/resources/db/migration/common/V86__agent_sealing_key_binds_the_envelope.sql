-- The sealing keys accepted so far are forgotten: they were announced by agents that open
-- envelopes bound to nothing but the sender's key.
--
-- Such an envelope carried an HTTPS token while its host travelled beside it in the clear, and a
-- TLS-terminating proxy could rewrite the host and receive the token. Envelopes are now sealed
-- under what the secret is for — a deployment key, or a token for one host and one user name —
-- and an agent vouches, in its signed announcement, that it opens them that way. A key accepted
-- before that vouched for nothing of the kind; keeping one would let the control plane seal for
-- an agent that cannot open what it is sent. A current agent announces again at its next start;
-- an older one is refused, by name, and handed no credential.
--
-- Written once, in common: an update every engine reads alike. V85 is taken by the integrations
-- branch (decision 0040), which merges after 0.11.0.

update t_agent set sealing_public_key = null, sealing_key_generation = null;
