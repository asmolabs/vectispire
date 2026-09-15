-- La note de conformité, mois par mois, avec ce qui l'a produite.
--
-- **Stocké et non recalculé, et c'est toute la conception.** La courbe du backlog ne stocke
-- rien : elle reconstruit le passé à partir des dates que chaque issue transporte. Un verdict de
-- conformité ne se reconstruit pas ainsi — il dépend du backlog du moment, de la fenêtre de
-- fraîcheur, des cibles qui existaient, de ce que l'analyse de code atteignait, de la déclaration
-- d'applicabilité, et du code du moteur lui-même.
--
-- Recalculer le passé, c'est donc une courbe qui bouge quand on modifie un seuil, et un verdict
-- de mars que personne ne sait expliquer en septembre. Montré à un évaluateur, c'est une
-- progression fabriquée par l'outil. Même raison que pour les verdicts de barrière : ce qui ne se
-- reproduit pas doit s'écrire.
--
-- **La forme du parc est enregistrée à côté de la note, et elle est la moitié utile.** La note
-- baisse quand on enregistre un dépôt de plus, et quand on allume un détecteur : dans les deux cas
-- parce qu'on regarde plus large. Une courbe tracée sans ça rapporte « on a régressé » le mois où
-- quelqu'un a commencé à mieux surveiller, et l'équipe qui la lit apprend à surveiller moins.
--
-- **Mensuel et non quotidien.** Un contrôle qui bouge au rythme des scans produit du bruit à une
-- maille plus fine, et le mois est l'unité que lit une évaluation — la même que la continuité
-- mensuelle du registre des verdicts.
--
-- L'unicité porte sur (période, cadre) : une ligne par mois et par cadre. La capture du mois en
-- cours est réécrite à chaque passage, si bien qu'un mois clos porte son état de fin de mois.

create table t_compliance_snapshot (
    id char(36) not null primary key,
    -- **varchar et non char, et PostgreSQL seul le dit.** Un `char(7)` y devient `bpchar`, que
    -- Hibernate refuse face a un String de longueur 7 : la validation de schema echoue et
    -- l'application ne demarre pas du tout. SQLite l'accepte sans broncher, donc la suite unitaire
    -- reste verte — c'est le defaut de portabilite que la campagne a trois moteurs existe pour
    -- attraper, et il a ete attrape.
    period varchar(7) not null,
    framework varchar(32) not null,
    score integer not null,
    status varchar(16) not null,
    targets integer not null,
    observed_targets integer not null,
    fresh_targets integer not null,
    freshness_days integer not null,
    eol_enabled boolean not null default 0,
    code_analysis_reaches boolean not null default 0,
    controls_total integer not null default 0,
    controls_declared integer not null default 0,
    soa_findings integer not null default 0,
    captured_at numeric not null
);

create unique index uq_compliance_snapshot on t_compliance_snapshot (period, framework);

-- « La progression sur la période auditée » se lit par cadre, du plus ancien au plus récent.
create index idx_compliance_snapshot_framework on t_compliance_snapshot (framework, period);
