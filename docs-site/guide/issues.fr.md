# Constats et triage

Une issue est un problème, suivi d'un scan à l'autre. C'est là que le travail se fait
réellement.

## Ce qui identifie une issue

L'empreinte **ignore délibérément la version du paquet**. Une dépendance qui reste vulnérable
sur trois correctifs successifs est une issue avec un historique et une décision, pas trois
issues qu'il faut chacune décider à nouveau.

Chaque issue porte : sa première apparition, le nombre de fois qu'elle a été vue, l'existence
d'une version correctrice, le caractère direct ou transitif du paquet, son score EPSS, son
statut KEV, et son historique de triage.

## Les deux axes

| | Écrit par | Valeurs |
|---|---|---|
| **État** | le pipeline, depuis ce que les scanners ont observé | `open`, `resolved` |
| **Statut de triage** | une personne | `affected`, `not affected`, `fixed`, `under review` |

Ils ne s'écrivent jamais l'un l'autre. Supprimer une issue ne la résout pas, et un scan qui
résout une issue n'efface pas ce que quelqu'un a décidé à son sujet.

## Trier

Ouvrez une issue et consignez une décision dans le vocabulaire VEX, avec une
**justification** et éventuellement un **commentaire**. La justification est la partie qui doit
vous survivre : « non atteignable dans notre configuration », « non livré en production »,
« code vendu que nous n'exécutons pas ».

### Dates de réexamen {#review-dates}

Une suppression est une affirmation sur un contexte, et les contextes changent. Posez une
**date de réexamen** sur la décision : l'issue revient à *en cours d'examen* à cette date, avec
sa justification et son commentaire intacts.

C'est le mécanisme qui empêche un backlog de triage de se dégrader en silence permanent. « Non
atteignable dans notre configuration » était vrai quand la configuration était ce qu'elle était.

Les issues dont l'échéance est passée sont signalées comme telles dans la liste.

### Triage en masse

Une CVE présente dans quarante dépôts est **un jugement sur un contexte**, pas quarante — et la
décider quarante fois est la façon dont le triage cesse d'avoir lieu.

Restreignez la liste avec les filtres, sélectionnez, décidez une fois. La transaction est
tout-ou-rien, et chaque issue enregistre malgré tout sa propre transition dans son propre
historique : une décision en masse qui réécrirait silencieusement quarante lignes serait
indiscernable de quarante lignes éditées à la main, et le registre doit pouvoir faire la
différence.

## Filtres à connaître

- **Corrigeables seulement** — masque tout ce dont aucune version correctrice n'est publiée.
- **Dépendances directes** — masque ce qu'une publication en amont, et non vous, doit corriger.
- **Activement exploitées (KEV)** — la liste la plus courte, et celle à lire en premier.
- **Triées / non triées** — ce qui a été décidé face à ce qui ne l'a pas été.
- **Échéance dépassée** — les suppressions dont la date de réexamen est arrivée.

## Un ordre qui fonctionne

1. Les entrées KEV, quel que soit leur CVSS.
2. EPSS élevé.
3. Directes et corrigeables.
4. Tout le reste, par gravité.

Un classement par gravité d'abord place une critique inexploitable dans une dépendance
transitive devant une élevée activement exploitée dans un paquet que vous avez déclaré. Ce
n'est pas le bon après-midi de travail.

## Historique

Chaque transition est conservée : de quel statut vers quel statut, par qui, avec quelle
justification, contre quelle version du projet. Une issue que personne n'a triée est imprimée
dans l'historique exporté en le disant — sinon, le silence passerait pour une décision qui n'a
simplement jamais été écrite.

Voir [Historique et preuves](history.md).
