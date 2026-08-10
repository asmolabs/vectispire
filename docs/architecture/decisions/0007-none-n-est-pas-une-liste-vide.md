# 0007 — Un analyseur qui échoue renvoie `None`, jamais `[]`

**Date :** 2026-08-07 · **Statut :** acceptée

## Contexte

Un analyseur peut échouer : image absente, délai dépassé, sortie illisible, mémoire
épuisée. La question est ce qu'il renvoie alors.

`scan_iac` renvoyait `[]`. C'est-à-dire que **le plantage de checkov déclarait le dépôt
conforme** : la liste vide était lue comme « analysé, rien trouvé », donc tous les
problèmes IaC ouverts étaient résolus. Sur toutes les cibles concernées, en silence.

Le défaut n'a pas été trouvé par une relecture. Il a été trouvé en cassant délibérément une
image pendant un scan réel.

## Décision

`None` et `[]` disent deux choses différentes, partout, et le code doit les distinguer :

- **`[]`** — l'étape a tourné, elle n'a rien trouvé. Les problèmes de ce type sont
  résolus.
- **`None`** — l'étape n'a pas tourné. On ne touche pas au backlog.

En conséquence, `ScanArtifacts.iac` et `.sast` sont `Optional`, et
`issue_service.scanned_types_for(...)` n'inclut un type que s'il a **réellement été
cherché**.

Et l'échec ne se lit pas seulement au code de retour : un scan Semgrep où la plupart des
fichiers ont expiré sort en 0 avec une liste courte, ce qui se lirait « analysé, presque
rien trouvé ». `errors[]` et `paths.scanned` sont inspectés, et au-delà d'un seuil
d'erreurs le résultat est `None`.

## Ce qu'on a écarté

**Un booléen `sast_ran` à côté de la liste.** Un booléen peut mentir sur sa charge : rien
ne garantit qu'il soit cohérent avec ce qui l'accompagne. `None` ne peut pas.

Et il y a mieux : un agent d'une version antérieure laisse le champ vide, donc `None`, donc
le bon comportement gratuitement. Si l'on oubliait la délégation dans un moteur, le pire
serait une fonctionnalité manquante — avec un booléen calculé côté serveur, ce serait la
**résolution silencieuse de tout le backlog** du type concerné.

## Conséquences

C'est la même distinction que `ScanIngestor` appliquait déjà pour les données de fin de
vie ; elle est maintenant la règle.

La classe de défaut à surveiller est nommable : **toute valeur par défaut qui ressemble à
un succès**. Une liste vide, un zéro, un `False` — chacun se lit comme un résultat alors
qu'il signifie une absence. Dans une application dont le métier est de dire ce qui va mal,
l'absence par défaut est toujours du côté rassurant.

Un scan dont un analyseur a échoué **se termine quand même**, avec les résultats des
autres. Refuser le scan entier pour un analyseur en panne serait la réaction opposée et
aussi mauvaise.
