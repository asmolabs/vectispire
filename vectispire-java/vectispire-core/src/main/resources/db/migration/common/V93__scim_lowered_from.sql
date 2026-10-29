-- The privileged role the directory lowered an unbound account out of, until an administrator sets
-- the account's role in Vectispire.
--
-- The directory may not bind a subject to a privileged account (a rule of the service, not of the schema), and
-- it may lower a role — taking a privilege away must stay easy. The two made a takeover in two
-- requests: lower a CISO to User, then bind it, now that it held nothing. The binding reads this
-- column, so the role the account held before the directory touched it still decides; an
-- administrator who sets the role in Vectispire has looked at the account, and clears it.
--
-- Null for every account the upgrade finds: a lowering from before the column existed is not known.

alter table t_user add column scim_lowered_from varchar(32);
