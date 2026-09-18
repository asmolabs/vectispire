# 0019 — Le serveur envoie un jeton ; l'écran détient la phrase

**Date :** 2026-09-18 · **Statut :** accepté · **Décideur :** Laurent Boucher

## Contexte

L'interface est bilingue. 1132 clés existent dans les deux bundles, aucun libellé n'est écrit en
dur, et trois cliquets de `check-i18n-keys.mjs` maintiennent cet état.

Quatre fichiers envoyaient des phrases françaises par l'API, que les écrans affichaient telles
quelles :

- `EpssRiskMatrix` — `« P0 - Remédiation sous 24h (Catalogue CISA KEV…) »`, rendu par l'écran EPSS
  **sous un en-tête de colonne qui passe, lui, par le bundle**. L'en-tête changeait de langue, la
  cellule en dessous non.
- `LicenseConflictMatrix` — une explication juridique et un conseil de remédiation par catégorie de
  licence, plus neuf notes de matrice.
- `AttackPathService` — une note sur chaque nœud du graphe, ainsi qu'un titre, un récit et un plan
  en trois étapes par chemin d'attaque, assemblés en concaténant une méthode, un chemin et un nom
  de paquet dans de la prose française.
- `AiVulnerabilityAdvice` — le conseil que ce produit écrit lui-même quand aucun modèle ne répond,
  affiché sur deux écrans, dont un champ part dans l'`impactStatement` des documents VEX exportés.

La règle qui tranche ces quatre cas existait déjà, et seulement dans un javadoc.
`RemediationGap.family` l'énonce : *« un jeton et non une phrase : la phrase qui explique comment on
referme cette famille-là est du texte d'écran, et le texte d'écran est traduit côté client. »* Elle
a été invoquée cinq fois pour modifier un contrat publié, et une règle qui gouverne une API en
vivant dans le javadoc d'une seule classe est une règle que le suivant réimplémente autrement.

## Décision

**Un champ de réponse qu'un écran rend comme de la prose porte un jeton. La phrase vit dans les
bundles de traduction du client.**

Le jeton est une **énumération du domaine**, pas une chaîne libre. springdoc énumère une énum, donc
`openapi.json` publie les valeurs, `openapi-typescript` génère une union exacte, et une constante
renommée fait tomber `ClientContractSpecTest` au lieu d'arriver à l'écran en clé non résolue.
`RemediationSeverityWireTest` existe parce que le seul endroit où cela a été fait avec une liste
`@Schema` recopiée à la main exigeait un test pour tenir la copie honnête ; une énum n'a pas besoin
de ce test.

**Les valeurs qui varient voyagent à côté du jeton, jamais dans la phrase.** Une concaténation est
exactement ce qu'une traduction ne peut pas réordonner : une phrase française bâtie comme
`« …appeler l'endpoint » + method + " " + path + …` ne peut pas devenir anglaise sans être
démontée. `AttackPath` porte donc `Map<String, String> params`, et la phrase du bundle interpole
`{{method}}` et `{{path}}` là où sa langue les place.

**Un écran rend des clés littérales.** `check-i18n-keys.mjs` ne sait lire que celles-là ; une clé
construite depuis un jeton lui est invisible et s'affiche telle quelle le jour où elle manque. Les
gabarits utilisent un `@switch` sur les valeurs du jeton, et là où le même switch se répéterait à
plusieurs endroits il est écrit une fois dans un `ng-template`.

## L'exception, et pourquoi elle n'en est pas une

`AiVulnerabilityAdvice` ne pouvait pas devenir un jeton. Quand un modèle est configuré, **c'est lui
qui remplit ces champs, avec sa prose, dans la langue qu'il a choisie** : ils doivent donc rester du
texte libre.

Ce que le serveur peut dire à la place, c'est *qui a écrit la phrase*. Un enregistrement
`Deterministic` optionnel voyage à côté, portant le paquet, les deux versions, ce que la corrélation
d'atteignabilité a pu dire, et si la CVE est activement exploitée. Présent, l'écran reconstruit la
phrase depuis les bundles ; absent, il affiche les mots du modèle sans y toucher. Réécrire la phrase
d'un modèle dans les mots de ce produit reviendrait à lui prêter des propos, sur un écran dont
l'objet même est de montrer ce qu'il a dit.

**Les phrases anglaises restent en place comme repli**, pour tout consommateur qui ne traduit pas —
le document VEX exporté en fait partie. C'est l'arrangement que `Setting` utilise déjà : le serveur
porte l'anglais, une clé de bundle le remplace quand le lecteur en a une.

## Ce que cette décision ne fait pas, dit plutôt que sous-entendu

**Elle ne rend pas bilingues les messages d'erreur d'API.** Les 32 messages levés dans le plan de
contrôle sont en anglais, délibérément et uniformément ; deux étaient français et ont été alignés,
non transformés en jetons. Un détail d'erreur est lu par un développeur tenant un corps de réponse
plus souvent que par un utilisateur devant un écran, et transformer chaque `throw` serait une autre
décision, avec un autre coût.

**Elle ne traduit ni les logs, ni les invites, ni les données stockées.** Les logs d'exploitation
sont en anglais. L'invite envoyée à un modèle est une instruction au modèle. Un commentaire écrit
dans la piste d'audit est le compte rendu de ce qui s'est passé, dans les mots où cela s'est passé.

**Elle ne ferme pas à elle seule l'angle mort du garde.** `check-i18n-keys.mjs` ne sait pas lire une
clé construite à l'exécution, et jusqu'à ce travail il ne savait pas lire `[label]="…"` non plus —
32 libellés en dur occupaient cet écart, dont 25 `aria-label` anglais qu'un lecteur francophone
entendait au lecteur d'écran. Un troisième cliquet lit désormais à l'intérieur des liaisons. Il ne
sait toujours pas distinguer un libellé d'un seul mot en minuscules d'une valeur de comparaison, et
cette limite est écrite dans le fichier.

## Conséquences

Cinq formes de réponse ont changé : `EpssPrioritizedIssue`, `LicenseConflict`, `CompatibilityCell`,
`AttackPathNode`, `AttackPath` et `AiVulnerabilityAdvice`. Chaque changement a régénéré
`openapi.json`, et les types clients avec lui.

Deux tests du domaine qui épinglaient une formulation française portent désormais sur le verdict —
`contains("EXPOSITION INDÉTERMINÉE")` est devenu `isEqualTo(Exposure.NOT_MENTIONED)`. C'est la
meilleure assertion indépendamment de la langue : un verdict survit à une reformulation, une phrase
non.

Un nouvel écran qui rend de la prose venue du serveur doit ajouter une énumération, pas une phrase.
Le coût est d'une énum et de deux entrées de bundle ; le coût de s'en passer est un îlot d'une seule
langue au milieu d'une interface qui suit son lecteur.
