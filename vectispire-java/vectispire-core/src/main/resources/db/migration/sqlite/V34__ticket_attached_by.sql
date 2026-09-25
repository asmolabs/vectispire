-- Who attached a ticket reference by hand; null when Vectispire opened the ticket itself.
--
-- The sweep closed on the tracker every ticket attached to a resolved finding, whoever attached it.
-- A developer could attach somebody else's ticket to a finding they could fix, and have the
-- integration close it with its own token. Only a ticket Vectispire opened is now closed by it;
-- one a person attached is theirs to close.
--
-- Existing rows stay null, so what was closable before the upgrade still is: nothing records which
-- of them were typed by hand, and guessing would stop closing the tickets Vectispire did open.

alter table t_issue add column ticket_attached_by varchar(255);
