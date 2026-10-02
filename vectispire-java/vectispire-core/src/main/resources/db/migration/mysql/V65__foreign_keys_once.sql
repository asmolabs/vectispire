-- Every foreign key exactly once, whichever MySQL.
--
-- **MySQL 8 and MySQL 9 read a column-level `references` differently.** MySQL 8 parses it and drops
-- it without a word — the reason V19 exists. MySQL 9 honours it. So the same history gives two
-- schemas: on MySQL 9, V1's inline keys exist twice, InnoDB's `t_scan_ibfk_1` beside V19's
-- `fk_scan_repo`, twenty-four pairs measured on 9.4 on 2026-10-02, each pair with the same columns,
-- target and rules. Harmless today, and a trap for the next migration that drops or changes a key by
-- its name: the twin stays, unseen, and a cascade or a column change then behaves differently on one
-- engine version only.
--
-- **And one key exists on MySQL 9 only.** V23, written after V19, declared
-- `t_mfa_challenge.user_id` inline again; on MySQL 8 — the engine `docker-compose.yml` ships — that
-- column has had no constraint at all, and a challenge could outlive its account in the table.
--
-- Both are settled by reading the catalogue rather than naming rows: the missing key is added under a
-- name, and an automatically named key is dropped only where a named key with the same columns,
-- target and rules exists. On MySQL 8 the second step finds nothing; run twice, both do nothing.

-- ------------------------------------------------------------------ the key MySQL 8 never had
-- Orphans first, as V19 did: a constraint cannot be added over them, and nothing can read a
-- challenge whose account is gone.
delete from t_mfa_challenge where user_id not in (select id from t_user);

set @missing = (
    select count(*) = 0
    from information_schema.table_constraints
    where constraint_schema = database()
      and table_name = 't_mfa_challenge'
      and constraint_name = 'fk_mfa_challenge_user');
set @statement = if(@missing,
    'alter table t_mfa_challenge add constraint fk_mfa_challenge_user foreign key (user_id) references t_user (id) on delete cascade',
    'do 0');
prepare add_key from @statement;
execute add_key;
deallocate prepare add_key;

-- ------------------------------------------------------------------ the twins MySQL 9 made
-- A procedure only because a loop needs one; it is dropped at the end. The candidates are copied into
-- a temporary table first, so no table is altered while the catalogue is being read.
drop procedure if exists v65_drop_twin_foreign_keys;

DELIMITER //
create procedure v65_drop_twin_foreign_keys()
begin
    declare finished int default 0;
    declare owner varchar(64);
    declare twin varchar(64);
    declare twins cursor for select table_name, constraint_name from v65_twins;
    declare continue handler for not found set finished = 1;

    drop temporary table if exists v65_keys;
    create temporary table v65_keys as
        select k.table_name, k.constraint_name,
               group_concat(k.column_name order by k.ordinal_position) as columns_list,
               max(k.referenced_table_name) as target,
               group_concat(k.referenced_column_name order by k.ordinal_position) as target_columns,
               max(r.delete_rule) as on_delete,
               max(r.update_rule) as on_update
        from information_schema.key_column_usage k
        join information_schema.referential_constraints r
          on r.constraint_schema = k.constraint_schema
         and r.table_name = k.table_name
         and r.constraint_name = k.constraint_name
        where k.constraint_schema = database()
          and k.referenced_table_name is not null
        group by k.table_name, k.constraint_name;

    drop temporary table if exists v65_named;
    create temporary table v65_named as
        select * from v65_keys where constraint_name not like '%\_ibfk\_%';

    drop temporary table if exists v65_twins;
    create temporary table v65_twins as
        select automatic.table_name, automatic.constraint_name
        from v65_keys automatic
        where automatic.constraint_name like '%\_ibfk\_%'
          and exists (
              select 1 from v65_named named
              where named.table_name = automatic.table_name
                and named.columns_list = automatic.columns_list
                and named.target = automatic.target
                and named.target_columns = automatic.target_columns
                and named.on_delete = automatic.on_delete
                and named.on_update = automatic.on_update);

    open twins;
    drop_each: loop
        fetch twins into owner, twin;
        if finished = 1 then
            leave drop_each;
        end if;
        set @drop_twin = concat('alter table `', owner, '` drop foreign key `', twin, '`');
        prepare drop_one from @drop_twin;
        execute drop_one;
        deallocate prepare drop_one;
    end loop;
    close twins;

    drop temporary table v65_twins;
    drop temporary table v65_named;
    drop temporary table v65_keys;
end //
DELIMITER ;

call v65_drop_twin_foreign_keys();
drop procedure v65_drop_twin_foreign_keys;
