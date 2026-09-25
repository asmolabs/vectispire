-- HTTPS clone tokens, managed like deployment keys and bound to one host (decision 0022).
--
-- A private repository over HTTPS could only be cloned with the token written into its URL, stored
-- in the clear in t_repository.url. The token now lives here, encrypted with its row as context, and
-- names the host it is issued for: the clone presents it to that host and to nothing else.
--
-- A repository references a key or a token, never both; the rule is the service's, the columns only
-- say which. Deleting a token a repository still uses is refused by the service; the foreign key's
-- "set null" is the backstop, as for ssh_key_id.

create table t_git_token (
    id char(36) not null primary key,
    name varchar(255) not null,
    host varchar(255) not null,
    username varchar(255),
    token text not null,
    created_at datetime(6) not null
);

-- Named and separate, as V19 declares the others: MySQL parses a column-level REFERENCES and then
-- ignores it, which is how the baseline's foreign keys existed only on paper there.
alter table t_repository add column https_token_id char(36);
alter table t_repository add constraint fk_repository_https_token
    foreign key (https_token_id) references t_git_token(id) on delete set null;
