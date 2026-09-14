-- Le verdict de la barrière, écrit au moment où il tombe.
--
-- **`GateService` ne persistait que les politiques, jamais les verdicts.** « Cent pour cent des
-- cibles passent la barrière » était donc ambigu entre deux lectures opposées : tout est propre, ou
-- la barrière n'a jamais rien bloqué. Un contrôle dont on ne peut pas exhiber un refus n'est pas un
-- contrôle démontré — c'est la différence entre affirmer qu'une porte est fermée et montrer le
-- registre de ceux qu'elle a arrêtés.
--
-- **Une table plutôt que le journal d'audit, et la raison n'est pas le confort.** Le journal
-- enregistre ce que des personnes font ; un verdict est une décision du système, prise des dizaines
-- de fois par jour par une chaîne d'intégration. Et il doit être agrégeable — combien de refus ce
-- mois-ci, sur quelle cible, pour quelle règle — ce qu'une ligne de journal conçue pour être lue
-- une par une ne permet pas.
--
-- **Les comptes par gravité sont des colonnes, pas un document JSON.** C'est ce qui rend
-- « combien de refus portaient un critique » interrogeable sur les trois moteurs sans qu'aucun
-- n'ait à savoir lire du JSON.
--
-- `evaluated` est le nombre d'issues que la politique a examinées, `violations` celui qu'elle a
-- retenues. Les deux : un verdict qui passe en ayant tout examiné et un verdict qui passe en
-- n'ayant rien vu se ressemblent, et seul le premier compte comme une preuve.
--
-- `on delete cascade` : supprimer une cible emporte ses verdicts, comme elle emporte ses scans.

create table t_gate_verdict (
    id char(36) not null primary key,
    repo_id bigint references t_repository(id) on delete cascade,
    container_id bigint references t_container(id) on delete cascade,
    passed boolean not null,
    evaluated integer not null,
    violations integer not null,
    critical_count bigint not null default 0,
    high_count bigint not null default 0,
    medium_count bigint not null default 0,
    low_count bigint not null default 0,
    fail_on_severity varchar(20),
    policy_source varchar(32) not null,
    policy_version bigint,
    relaxations_ignored boolean not null default false,
    decided_at numeric not null,
    decided_by varchar(255),
    ip_address varchar(64)
);

-- La lecture est « les verdicts récents, d'une cible ou de tout le parc », donc le tri est la
-- requête. Sans cet index elle balaie une table qu'une chaîne d'intégration fait grossir chaque
-- jour.
create index idx_gate_verdict_decided_at on t_gate_verdict (decided_at);
create index idx_gate_verdict_repo on t_gate_verdict (repo_id, decided_at);
create index idx_gate_verdict_container on t_gate_verdict (container_id, decided_at);
