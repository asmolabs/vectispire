-- La déclaration d'applicabilité : ce qu'un organisme **dit** de chaque contrôle.
--
-- **C'est le document ISO 27001.** La clause 6.1.3 d en exige un : chaque contrôle de l'annexe A
-- traité, applicable ou exclu, et toute exclusion argumentée. Un évaluateur ouvre par là et
-- travaille vers l'extérieur. Un outil qui évalue les contrôles automatiquement et ne détient
-- aucune déclaration répond à une question que personne n'a posée : il dit comment les choses
-- sont, et l'évaluateur est venu vérifier ce qui a été affirmé contre comment les choses sont.
--
-- **L'artefact intéressant n'est ni la déclaration ni la mesure, c'est leur désaccord.** Un
-- contrôle déclaré en place que le parc mesure non conforme est exactement ce qu'un évaluateur
-- relève, et aucune des deux moitiés du produit ne pouvait le voir seule.
--
-- **`evidence_source` n'est pas une formalité.** Vectispire mesure une tranche de chaque contrôle,
-- jamais son entier : A.5.15 est le contrôle d'accès, dont « pas de secret dans le code » est un
-- coin. Sans cette colonne, la confrontation fabriquerait des écarts — elle relèverait qu'un
-- organisme se contredit sur le contrôle d'accès parce qu'un scanner de secrets avait un avis.
-- Une ligne dont la preuve vit ailleurs est rapportée comme telle, ce qui est le refus d'avoir un
-- avis et la raison pour laquelle on peut faire confiance aux lignes où le modèle en a un.
--
-- **Pas de clé étrangère vers un référentiel de contrôles, parce qu'il n'y en a pas :** les
-- contrôles sont une énumération dans le code. Une déclaration nommant un contrôle que le cadre ne
-- porte pas est donc possible, et elle est écartée à la lecture plutôt que refusée à l'écriture —
-- une révision du standard que ce build ne connaît pas encore ne doit pas empêcher d'enregistrer
-- ce que l'organisme a décidé.
--
-- L'unicité porte sur (cadre, contrôle) : une ligne par contrôle et par cadre, et le même contrôle
-- déclaré deux fois est une contradiction plutôt qu'un historique.

create table t_control_declaration (
    id char(36) not null primary key,
    framework varchar(32) not null,
    control_id varchar(64) not null,
    applicability varchar(16) not null,
    justification text,
    implementation varchar(32),
    evidence_source varchar(16) not null,
    external_evidence text,
    control_owner varchar(255),
    decided_by varchar(255),
    decided_at timestamp with time zone not null,
    reviewed_at timestamp with time zone,
    review_due_at timestamp with time zone
);

create unique index uq_control_declaration on t_control_declaration (framework, control_id);

-- « Quelles revues ont expiré » est une question posée sur tout le référentiel, pas cadre par
-- cadre : c'est le tableau de bord de l'ISMS, et il n'a pas de clause de cadre à offrir à l'index
-- composite ci-dessus.
create index idx_control_declaration_review on t_control_declaration (review_due_at);
