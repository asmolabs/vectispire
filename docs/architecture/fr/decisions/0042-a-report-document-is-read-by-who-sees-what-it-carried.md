# 0042 — Un document de rapport est lu par qui voit ce qu'il contient, pas seulement par qui voit le projet aujourd'hui

**Date :** 2026-10-10 · **Statut :** acceptée · **Amende :** [0035](0035-report-plugins.md) §4 · **S'appuie sur :** [0007](0007-none-is-not-an-empty-list.md) · **Décideur :** Laurent Boucher

## Contexte

Une exécution de rapport construit l'export du projet au moment où elle est prise en charge, pour son
demandeur, sur toutes les cibles rangées dans le projet — dépôts et images ([0035](0035-report-plugins.md) §2).
Le document qu'elle produit est gardé pendant la fenêtre des preuves et téléchargé par « quiconque peut lire
l'exécution » : un appelant qui voit le projet **entier**, tel qu'il est **au moment du téléchargement** (§4). La
route de statut (`GET /api/v1/report-documents/{sha256}`) répondait selon la même règle.

Ces deux instants ne désignent pas le même projet. Un dépôt retiré du projet après l'exécution laissait ses
constats dans le document, et un lecteur qui voit le projet tel qu'il est — chacune des cibles qu'il contient
aujourd'hui — sans avoir jamais eu accès à ce dépôt, les téléchargeait. Un droit qui nomme le projet se résout
en ses cibles actuelles : un lecteur à qui le projet est accordé est exactement ce lecteur-là. L'audit du
10 octobre 2026 l'a relevé ; rien n'enregistrait quelles cibles un export avait contenues, si bien qu'aucune
règle ne pouvait s'y opposer.

## Décision

### 1. L'exécution enregistre les cibles que son export a contenues

`ProjectExportService` lit déjà les cibles du projet pour refuser un appelant qui ne les voit pas toutes.
L'export remis à une exécution (`RunExport`) porte désormais cette liste, et la ligne de l'exécution la garde dans
`export_targets` (V87), chaque cible écrite comme l'empreinte d'un constat la nomme — `repo:12 container:4` —, à
la fin de l'exécution, dans la transaction qui écrit le reste de son enregistrement. Ce n'est pas une nouvelle
table : la liste est lue avec l'exécution, par elle, et s'en va avec elle.

### 2. Un document est lu par un appelant qui voit le projet entier **et** chacune des cibles qu'il a contenues

Le téléchargement et la route de statut gardent la règle du projet et y ajoutent celle de l'exécution : chaque
cible enregistrée doit être visible de l'appelant (`ReportRunTargets.seenBy`). Un appelant qui échoue à la
seconde reçoit la réponse d'une exécution qui n'existe pas — le 404 de l'exécution au téléchargement, `unknown`
sur la route de statut —, jamais 403 : une réponse différente confirmerait ce que contient le document.

Les deux règles, pas la seconde seule. Ne lire que les cibles enregistrées serait plus précis — un lecteur qui
ne voit pas une cible ajoutée *après* l'exécution garderait ses documents antérieurs —, mais cela assouplirait la
règle « projet entier » que 0035 applique à l'export, à la demande et aux exécutions, et cet assouplissement
mérite sa propre décision plutôt que la marge d'un correctif.

### 3. Non enregistré n'est pas vide

Une exécution antérieure à V87 a `export_targets` à null : personne n'a noté ce que son export contenait.
Remplir la colonne à partir des cibles actuelles des projets écrirait précisément l'hypothèse que cette décision
supprime. Un tel document est lu par un appelant dont la visibilité est **totale** — un administrateur, ou tout
compte tant que le déploiement laisse la visibilité ouverte — et par personne d'autre
([0007](0007-none-is-not-an-empty-list.md)). Un texte qui ne se lit pas est traité de même, jamais comme moins de
cibles. Une colonne vide est un export d'un projet sans cible, et ne demande rien au-delà de la règle du projet.

Une cible supprimée depuis l'exécution n'est visible d'aucun lecteur restreint ; son document est donc lu par
ceux qui voient tout — la même réponse prudente.

### 4. Les exécutions elles-mêmes restent sous la règle du projet

La liste des exécutions et la fiche d'une exécution (plugin, état, instants, empreintes, comptes) ne sont pas le
document et gardent la règle de 0035. Cacher une exécution qui existe à quelqu'un qui voit le projet mettrait
l'écran en désaccord avec lui-même pour peu de chose : le contenu est dans le document.

## Conséquences

- Un lecteur qui voit le projet entier mais pas une cible qu'il contenait au moment de l'exécution ne télécharge
  plus le document de cette exécution et n'en apprend pas le statut. Un administrateur, si.
- Un lecteur qui ne voit pas une cible ajoutée depuis au projet continue de perdre les documents du projet, comme
  avant : la règle 2 garde la condition du projet.
- Sur une installation mise à jour avec des documents déjà produits, ceux-ci sont lus par les administrateurs
  seuls (et par tous tant que la visibilité est ouverte). Une nouvelle production démarre sans aucun.
- `ReportRunsRoutesTest` vérifie le téléchargement et la route de statut après qu'un dépôt a quitté le projet, et
  une exécution dont les cibles n'ont pas été enregistrées ; `ReportRunTargetsTest` le texte de la colonne, une
  liste vide et un texte qui ne se lit pas.

## Rejeté

- **Ne rien enregistrer et vérifier les cibles que le projet contient aujourd'hui.** C'est la règle qui a failli.
- **Une table `t_report_run_target`.** Interrogeable, mais rien ne l'interroge : la liste est lue avec son
  exécution. Une colonne suit la ligne qu'elle décrit et n'a besoin d'aucun écouteur à la suppression d'un projet.
- **Remplir la colonne à partir des projets actuels lors de la migration.** Cela écrit l'hypothèse qu'on corrige.
- **Les seules cibles enregistrées.** Voir §2 : un assouplissement de 0035, pour sa propre décision.
