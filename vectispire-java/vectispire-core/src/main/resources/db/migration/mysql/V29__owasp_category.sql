-- La catégorie OWASP qu'une règle déclare sur elle-même.
--
-- **Sept catégories du Top 10 restaient « non couvertes », et deux d'entre elles n'avaient
-- aucune raison de l'être.** L'analyse de code peut produire des constats d'injection (A03) et
-- de falsification de requête côté serveur (A10) : les règles amont le déclarent dans leur
-- propre `metadata.owasp`, et ce produit ne lisait pas cette métadonnée. Aucun constat de code
-- ne pouvait donc être placé dans la grille, et la grille annonçait une absence de couverture
-- qui était une absence de lecture.
--
-- **Une colonne, et non une déduction au moment de l'affichage.** La catégorie appartient à la
-- règle qui a produit le constat, au moment où elle l'a produit : la relire plus tard depuis
-- l'ensemble de règles courant donnerait à un constat d'hier la catégorie d'une règle modifiée
-- depuis, et la grille de l'an dernier changerait de forme en silence. C'est une preuve
-- d'évaluation ; elle se conserve avec le constat.
--
-- **Nulle, et pas « A00 ».** La plupart des règles ne déclarent rien, et l'absence de
-- déclaration est précisément ce qui doit empêcher un placement — un défaut quelconque ferait
-- entrer des constats dans une catégorie que personne n'a revendiquée.
--
-- `varchar(3)` et non `char(3)` : sur PostgreSQL, `char` devient `bpchar`, que la validation de
-- schéma Hibernate refuse. Cette leçon a déjà coûté un démarrage entier, en `V25`.

alter table t_issue add column owasp_category varchar(3);
alter table t_finding add column owasp_category varchar(3);
