-- L'appartenance au périmètre certifié.
--
-- **Le produit connaît ses cibles ; un système de management a un périmètre déclaré, et les deux
-- ne coïncident pas.** « Toutes les cibles sont scannées » ne dit rien à un évaluateur tant qu'on
-- ne sait pas ce que le périmètre recouvre : un parc entièrement vert composé de la moitié des
-- actifs certifiés est un constat, pas une conformité.
--
-- **Un drapeau par cible plutôt qu'une table d'adhésion.** Un organisme a un périmètre ISMS, pas
-- une collection ; une table d'association permettrait d'en exprimer plusieurs, ce dont personne
-- n'a besoin, et rendrait obligatoire une jointure sur chaque lecture de couverture.
--
-- **Ce que cette colonne ne peut pas voir.** Un actif du périmètre que Vectispire n'a jamais
-- enregistré est invisible ici : il n'a pas de ligne à marquer. C'est pourquoi le nombre d'actifs
-- que la déclaration de périmètre recouvre est un réglage à part — sans lui, la couverture se
-- mesurerait contre elle-même et serait toujours de cent pour cent.

alter table t_repository add column in_certified_scope boolean not null default 0;
alter table t_container add column in_certified_scope boolean not null default 0;
