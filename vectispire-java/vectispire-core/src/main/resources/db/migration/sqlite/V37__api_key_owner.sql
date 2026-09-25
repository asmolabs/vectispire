-- The account an integration API key acts for (decision 0024).
--
-- Keys issued from the API keys screen authenticated nowhere: the bearer filter accepted only an
-- agent's own key. An integration key now acts for the account that issued it — its role and its
-- visibility, narrowed by the key's target restriction — and stops working with that account.
-- Keys issued before this have no owner and keep authenticating nowhere; they are to be reissued.

alter table t_api_key add column owner_user_id bigint references t_user(id) on delete cascade;
