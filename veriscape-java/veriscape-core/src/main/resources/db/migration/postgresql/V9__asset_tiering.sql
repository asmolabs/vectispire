alter table t_repository add column tier varchar(32) not null default 'TIER_2_BUSINESS_OPERATIONAL';
alter table t_container add column tier varchar(32) not null default 'TIER_2_BUSINESS_OPERATIONAL';
