-- The account an integration API key acts for (decision 0024).
--
-- Keys issued from the API keys screen authenticated nowhere: the bearer filter accepted only an
-- agent's own key. An integration key now acts for the account that issued it — its role and its
-- visibility, narrowed by the key's target restriction — and stops working with that account.
-- Keys issued before this have no owner and keep authenticating nowhere; they are to be reissued.

-- Named and separate: MySQL ignores a column-level REFERENCES (see V19 and V36).
alter table t_api_key add column owner_user_id bigint;
alter table t_api_key add constraint fk_api_key_owner
    foreign key (owner_user_id) references t_user(id) on delete cascade;
