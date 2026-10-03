# Checklists de sécurité

La **checklist de sécurité** d'un projet est la checklist propre à votre organisation — un
[modèle de checklist](../administration/checklist-templates.fr.md) que votre fonction sécurité a
importé et publié — remplie pour un projet, ligne par ligne, par ceux qui le construisent, puis
approuvée par un approbateur. Chaque réponse garde son auteur et son instant, chaque preuve sa date,
et une révision approuvée n'est plus jamais modifiée.

Ouvrez-la depuis **Solutions et projets** : chaque projet que vous voyez en entier porte un lien
**Checklist de sécurité**. La décision
[0032](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0032-security-checklists.md)
consigne pourquoi elle fonctionne ainsi.

!!! info "Le projet entier, ou rien"
    Une checklist parle pour chaque dépôt de son projet. Elle est montrée à un compte dont la
    visibilité est totale, à un compte à qui le projet est accordé comme tel, et à un compte qui voit
    chacun des dépôts du projet — et il y en a au moins un. À tout autre, il est dit que le projet
    *n'existe pas ou ne lui est pas visible*, les mêmes mots pour les deux : un lecteur qui voit une
    partie d'un projet lirait sinon, en une ligne, l'état de dépôts qui lui sont cachés. Un projet
    que vous ne voyez qu'en partie n'a pas de lien de checklist dans l'arbre.

## Qui peut faire quoi

| | Administrateur, RSSI, security champion | Utilisateur | Auditeur | Gouverneur de la plateforme |
|---|---|---|---|---|
| Lire la checklist, ses lignes, son historique et ses révisions antérieures | oui | oui | oui | oui |
| L'ouvrir, répondre, joindre et retirer des preuves, soumettre, renvoyer, rouvrir, passer à une autre version | oui | oui | non | non |
| L'approuver | oui — [double validation](../administration/four-eyes.fr.md) active, **pas un auteur de la révision** | non | non | non |

L'auditeur lit tout et ne change rien. Le gouverneur de la plateforme décide des règles — il peut
écrire les modèles — et ne prend aucune décision sous elles : il ne répond ni n'approuve. Un compte
qui ne peut pas écrire voit la checklist sans un seul contrôle qui la modifie.

## 1. Ouvrir la checklist

La page porte le nom du projet, même avant qu'il ait une checklist. Un projet sans checklist propose
les versions **publiées** des modèles. Choisissez-en une et **Ouvrir la checklist** : la révision 1
s'ouvre en **brouillon**, vous comme auteur, chaque ligne sans réponse. Une version en brouillon ou
retirée n'est jamais proposée.

Une version publiée avant que Vectispire ne contrôle les modèles, dont aucune approbation ne pourrait
remplir le classeur, est listée mais **ne peut pas être choisie** : elle porte la mention *ne peut pas
être approuvée*, et une note sous la liste nomme les cellules en cause. Elle reste listée plutôt que
masquée, pour qu'un projet dont la checklist s'y trouve voie où elle est passée et quoi signaler ;
demandez à qui gère les modèles une
[version corrigée](../administration/checklist-templates.fr.md#une-formule-dans-une-cellule-que-vectispire-ecrit).
La liste **Passer à une autre version** la signale de la même façon.

Un projet a **une seule révision ouverte à la fois**. Si quelqu'un en a ouvert une après que vous avez
chargé la page, votre ouverture est refusée et l'écran propose de recharger — vous voyez la sienne
plutôt que d'en ouvrir une seconde.

## 2. Répondre aux lignes

Les lignes sont groupées comme le modèle les groupe : par domaine, puis par objectif, dans l'ordre de
la feuille. Chacune montre son contrôle, son contact et son KPI dans les mots du modèle, la preuve
qu'un « oui » demande, et ce qui l'empêche encore d'être soumise :

| Affiché sur la ligne | Que faire |
|---|---|
| Pas encore de réponse | Y répondre. |
| En attente de confirmation | Une réponse reportée sur une ligne qui a changé : y répondre de nouveau, ou **Confirmer la réponse**. |
| Commentaire requis | Un *non* ou *non applicable* sans sa raison : répondre de nouveau avec un commentaire. |
| Preuve requise | Un *oui* sur une ligne qui demande une preuve, sans aucune jointe (ou seulement un lien là où un fichier est demandé). |
| Preuve périmée | Toutes les preuves jointes ont dépassé leur validité : en joindre une plus récente. |

**Répondre** à une ligne par *oui*, *non* ou — seulement sur une version dont l'importateur y a associé
un mot — *non applicable* ; le mot du modèle est montré à côté de chacun. **Un *non* ou un *non
applicable* demande un commentaire** (4 000 caractères au plus) : le lecteur de la checklist a besoin
de la raison précisément sur ces lignes-là. L'écran refuse une réponse sans commentaire avant de rien
envoyer.

Répondre ne réécrit jamais une réponse : cela ajoute une ligne à l'**historique** de la ligne, sous
votre nom — le compte connecté, jamais un nom saisi quelque part — et la plus récente est la réponse
de la ligne. **Historique** sur une ligne liste chaque réponse donnée dans cette révision, de la plus
ancienne à la plus récente, avec qui et quand, et chaque preuve, retirées comprises.

Une équipe remplit une checklist ensemble. Votre réponse n'est refusée que lorsque **cette ligne-là** a
changé depuis que vous l'avez chargée — quelqu'un d'autre y a répondu ou y a joint une preuve —
jamais parce qu'une autre ligne a changé ; l'écran le dit sur la ligne et propose de recharger.

## 3. Joindre des preuves

**Ajouter une preuve** sur une ligne joint une preuve, avec **le jour où le travail a été fait** — un
jour, et pas dans le futur :

- **un lien** — une adresse `https:` ou `http:` avec un hôte, 2 000 caractères au plus ;
- **un fichier** — **25 Mo** au plus. L'écran refuse un fichier plus gros avant d'envoyer un octet,
  avec la phrase que le serveur répondrait ; joignez un document plus gros par un lien.

Un fichier n'est rendu **qu'en téléchargement**, comme des octets opaques, quel que soit le type qu'il
déclare : un fichier HTML ou SVG téléversé puis ouvert dans la page serait un script exécuté sur
l'origine du plan de contrôle. Son nom, sa taille et son SHA-256 sont montrés sur la ligne.

Quand une ligne dit combien de temps une preuve vaut, chaque preuve est **valable jusqu'au** jour
où le travail a été fait plus ce nombre de mois, et la ligne affiche *Preuve périmée* dès qu'aucune ne
vaut plus. Une preuve n'est demandée qu'à un *oui* — un *non* dit que le contrôle n'est pas en place,
et son commentaire dit pourquoi. Une ligne qui demande un fichier n'est pas satisfaite par un lien.

Quelles lignes demandent une preuve, de quelle sorte et pour combien de temps, relève du **modèle**,
défini sur son brouillon avant sa publication — voir [modèles de checklists](../administration/checklist-templates.fr.md#4-dire-quelle-preuve-chaque-ligne-demande).
Une ligne montre ce qu'elle demande ; une ligne qui n'en demande aucune n'a besoin d'aucune preuve,
quelle que soit sa réponse.

**Retirer** une preuve tant que la révision est un brouillon. Elle n'est jamais supprimée : elle cesse
de compter, et elle reste dans la liste, barrée, avec qui l'a retirée et quand.

## 4. Soumettre, renvoyer

**Soumettre pour approbation** est grisé, les lignes nommées, tant que chaque ligne n'est pas prête :
répondue, chaque *non* et *non applicable* commenté, chaque preuve qu'un *oui* demande jointe et
valable, et aucune réponse reportée en attente de confirmation. Une révision soumise n'est plus
répondue.

Quiconque peut écrire peut la **Renvoyer à ses auteurs** avec une raison, conservée sur la révision et
montrée dans son en-tête : elle redevient un brouillon, à remplir.

Une soumission, un renvoi, une approbation, une réouverture et un passage de version sont refusés
quand **quoi que ce soit** a changé dans la révision depuis que vous l'avez chargée — ce qui est soumis
ou approuvé est ce que vous avez relu, ligne pour ligne. L'écran explique le refus et propose de
recharger.

## 5. Approuver

Un administrateur, un RSSI ou un security champion **approuve** une révision soumise : l'attestation
de mise en production. [Double validation](../administration/four-eyes.fr.md) active, l'approbateur
ne doit être **aucun des auteurs de la révision** — quiconque a ouvert une checklist neuve, donné une
réponse qu'elle contient (une réponse reportée reste à son auteur), confirmé une ligne reportée, joint
ou retiré une preuve, ou l'a soumise. Reporter des réponses n'est pas écrire : rouvrir ou changer de
version ne fait pas de vous un auteur. L'en-tête liste ces auteurs, et le
bouton **Approuver** est grisé pour l'un d'eux avec la raison : *une deuxième personne doit
l'approuver*. Le serveur décide — le refus est inscrit au journal d'audit et envoyé au SIEM
(`VECTI-SEC-026`). Double validation éteinte, un approbateur peut approuver ce qu'il a écrit.

Une approbation est aussi refusée quand une preuve a cessé de valoir depuis la soumission — sa validité
a expiré entre-temps. Les lignes refusées sont marquées en rouge, chacune avec ce que le serveur y a
trouvé manquant — *Preuve périmée*, par exemple. Renvoyez la révision à ses auteurs, qui joignent une
preuve plus récente et soumettent de nouveau.

Une révision approuvée indique dans son en-tête qui l'a soumise, qui l'a approuvée et quand, et si la
double validation exigeait que les deux diffèrent.

## 6. Rouvrir

Une révision approuvée n'est jamais modifiée. **Rouvrir en nouvelle révision** ouvre la révision
suivante sur la **même version**, chaque réponse et chaque preuve reportées comme actuelles — rien à
confirmer, puisqu'aucune ligne n'a changé. La révision approuvée reste telle qu'elle a été approuvée,
listée plus bas.

Rouvrir ou changer de version ne fait **pas** de vous un auteur de la nouvelle révision : les réponses
reportées restent à leurs auteurs, et vous ne vous êtes prononcé sur aucune ligne. Un approbateur qui
rouvre une checklist peut l'approuver, tant qu'il n'y confirme, ne répond ni ne joint rien ; qui
confirme une ligne reportée en devient auteur, puisque confirmer, c'est s'en porter garant à nouveau.

## 7. Passer à une version plus récente

Quand une version plus récente du modèle est publiée, **Passer à une autre version** ouvre une nouvelle
révision dessus et **reporte** les réponses de la plus récente :

| La ligne dans la nouvelle version | Sa réponse |
|---|---|
| Inchangée | Reportée comme actuelle. |
| Modifiée — son libellé, son KPI, son exigence de preuve ou sa règle liée a bougé, ou elle a été appariée à la main avec une ligne reformulée | Reportée **en attente de confirmation** : y répondre de nouveau ou la confirmer avant que la révision puisse être soumise. |
| Ajoutée | Commence sans réponse. |
| Supprimée | Sa réponse reste dans la révision où elle a été donnée. |

Un *non applicable* reporté sur une version qui ne le propose pas attend lui aussi une nouvelle
réponse. Chaque réponse reportée garde le nom et l'instant de qui l'a donnée, et nomme qui l'a
reportée et quand ; les preuves d'une ligne inchangée ou modifiée la suivent, les retirées exceptées,
redatées selon la validité de la nouvelle ligne. **Passer à un autre modèle ne reporte rien** : les
mêmes mots dans une autre checklist sont une autre question.

La révision quittée devient *remplacée* si elle était un brouillon ou soumise ; une révision approuvée
reste approuvée. Dans les deux cas elle reste lisible.

La version d'arrivée est d'abord essayée, comme l'approbation la remplirait : une version publiée avant
la version qui suit la 0.10.0 dont aucune approbation ne pourrait remplir le classeur est refusée, ses
cellules nommées ([quand le serveur refuse](#quand-le-serveur-refuse)). La version quittée n'est jamais
essayée : une checklist bloquée sur une telle version peut toujours la quitter.

## Lignes mesurées

Une ligne que le modèle lie à une règle — voir
[modèles de checklists](../administration/checklist-templates.fr.md#lignes-mesurees-la-regle-liee-a-une-ligne)
— est **mesurée** : Vectispire lit ce que ses analyses, les plugins, les imports de votre CI et le
passif ont enregistré pour chaque dépôt du projet, et dit ce qu'il a trouvé à côté de la réponse.
La mesure est une preuve à côté de la réponse — et, sauf si votre gouverneur de plateforme l'a
désactivé, Vectispire **répond aussi lui-même à la ligne** à partir d'elle : voir
[réponses automatiques](#reponses-automatiques).

Chaque ligne liée montre, sous ses mots, **Mesurée par** et la règle en mots, puis sa mesure :
**Atteint**, **Non atteint** ou **Pas de données** — jamais un succès par défaut — avec la raison en une
phrase quand il n'y a pas de données, l'instant auquel elle vaut (sa preuve la plus ancienne), les
chiffres par périmètre et sévérité, et **Afficher les preuves** : pour chaque dépôt l'analyse (liée à
sa page) ou l'import lu, sa date, l'empreinte du document qu'un import a accepté, s'il est atteint, et
le détail du serveur. Un script lit la même chose à
`GET /api/v1/projects/{id}/checklists/{revision}/measurements`.

La page dit quelles mesures elle montre. Celles d'un brouillon et d'une révision soumise sont **en
direct** : calculées pour votre lecture, conservées nulle part, relues après chaque changement que vous
faites, et calculées à nouveau par la soumission et par la validation. Celles d'une révision validée
sont **figées par sa validation**. Des badges à côté du résultat disent ce que la réponse et la mesure
disent ensemble, et ce que la mesure retient encore d'une soumission.

**L'absence de données dit pourquoi.** Un seul dépôt sans données rend la ligne *no data*, et un
seuil n'est jamais jugé sur une partie du passif d'un projet :

| Raison | Sens |
|---|---|
| `no_repository` | Le projet n'a aucun dépôt : « chacun des zéro dépôts passe » n'est pas un succès. |
| `never_examined` | Un dépôt n'a aucune analyse ni aucun import où le périmètre a produit. |
| `forge_unlinked` | Une [ligne `change_review`](../administration/checklist-templates.fr.md#revue-des-changements-comment-ils-arrivent-sur-une-branche), sur un dépôt qu'aucune connexion de forge n'a importé et dont aucune découverte n'a listé l'URL : il n'y a pas de projet de forge à interroger. |
| `forge_unreadable` | La même, et la forge a refusé au jeton de la connexion le projet, ses merge requests ou ses pull requests — sur GitHub, un jeton *fine-grained* sans *Pull requests: read*. Les preuves donnent la réponse de la forge. |
| `step_absent` | Chaque analyse dans l'âge maximal s'est faite sans l'étape ou le plugin — n'a pas regardé, n'a pas « rien trouvé » ; aussi un rapport de couverture qui n'a compté aucune branche, pour une règle sur les branches. |
| `plugin_unsigned` | Le plugin a été refusé, et n'a pas produit depuis dans l'âge : son manifeste ne déclare aucun signataire, l'exécuteur en exige un, et le gouverneur n'a accordé aucune [dérogation](../administration/plugins.md#faire-tourner-un-plugin-non-signe). Personne n'a lancé l'outil — signez son image, ou enregistrez la dérogation. |
| `plugin_signature_unverified` | De même, refusé parce que le signataire que déclare son manifeste n'a pas vérifié l'image (autre signataire, pas de signature, ou un registre que cosign n'a pas pu joindre). |
| `plugin_registry_authentication_required` | De même, refusé parce que le registre de l'image n'a pas laissé lire la signature : l'exécuteur n'a pas d'identifiants pour lui, ou ceux qu'il a ont été refusés. On ignore si l'image est signée — donnez à la configuration Docker de l'exécuteur un compte en lecture seule pour ce registre ([Identifiants de registre](containers.md#identifiants-de-registre)). |
| `language_not_analysed` | L'analyse statique a produit sur un arbre qu'elle ne savait pas lire : un langage source du dépôt qu'aucune des règles SAST de l'analyse ne lit, ou un plugin qui a produit sur un arbre ne contenant aucun de ses langages. Les preuves nomment les langages. Installez des règles pour eux — un jeu de règles du catalogue — et relancez l'analyse. |
| `examination_unrecorded` | Les analyses dans l'âge maximal datent d'avant que Vectispire enregistre quelles étapes ont tourné, ou un import d'avant qu'il enregistre quels outils il portait : relancez l'analyse, ou renvoyez le rapport. |
| `languages_unrecorded` | L'analyse où l'examen a produit n'a pas enregistré les langages de son arbre, ou ceux que lisent ses règles : toute analyse d'avant cette version, un arbre trop grand pour être compté en entier, un agent plus ancien que le recensement. Relancez l'analyse avec un exécuteur à jour. |
| `version_unrecorded` | Un paquet déclaré d'une ligne `component_versions` figure dans le SBOM, et aucune de ses occurrences n'en indique la version — Syft écrit `UNKNOWN` pour une version Maven héritée d'un parent ou d'un BOM qu'il ne résout pas. Le paquet est présent ; sa version n'a pas été enregistrée, elle n'est donc pas jugée, et la preuve dit que la version est gérée hors du SBOM — importez un SBOM produit par le build, qui l'indique, ou liez [`component_present`](../administration/checklist-templates.md#composants-presence-versions-et-plages) quand la ligne demande seulement si la bibliothèque est utilisée. Quand certaines occurrences indiquent une version, ce sont elles qui jugent, les autres nommées dans la preuve ; une version indiquée non admise, ou un paquet absent du SBOM, échoue toujours. |
| `inventory_absent` | Une ligne `component_present` ou `component_versions`, sur un dépôt dont la dernière analyse ne conserve plus son SBOM — la rétention des charges l'a purgé — et dont l'inventaire ne liste aucun composant : la présence des paquets n'a pas été enregistrée, et « non utilisée » — ou « pas à une version autorisée » — serait une réponse que personne n'a pu voir. Un inventaire que la rétention a laissé est toujours lu. Analysez à nouveau le dépôt. |
| `packages_unrecorded` | Une ligne de couverture [limitée à un périmètre de paquets](../administration/checklist-templates.fr.md#couverture-sur-un-perimetre-de-paquets), et l'import de couverture le plus récent a été accepté avant que les imports ne conservent leurs paquets : seuls ses totaux sont connus, et ce ne sont pas ceux du périmètre. Le prochain envoi du pipeline le mesure. |
| `packages_not_kept` | De même, et l'import le plus récent a conservé ses totaux et pas ses paquets — plus de 10 000, un chemin trop long pour être stocké entier, ou des comptes qui ne s'additionnent pas aux totaux. La preuve dit lequel. |
| `scope_matches_nothing` | De même, et aucun paquet du rapport n'entre dans le périmètre : rien n'y a été compté, ce qui n'est ni 0 % ni 100 %. La preuve donne le nombre de paquets du rapport ; comparer les motifs à ses chemins. |
| `review_incomplete` | Une ligne `change_review`, et la lecture de la forge ne couvre pas la fenêtre : plus de 500 changements fusionnés, ou une lecture plus étroite qu'une fenêtre tout juste élargie — la lecture suivante la couvre. |
| `no_change_merged` | Une ligne `change_review`, et rien n'a été fusionné dans la branche pendant la fenêtre : chacun de zéro n'est pas tous. |
| `stale` | Le regard le plus récent est plus ancien que l'âge maximal de la règle. |
| `not_applicable_anywhere` | Un plugin ne s'applique à aucun dépôt du projet : il n'a rien regardé. Un dépôt où il ne s'applique pas est exclu des chiffres quand un autre est mesuré. |
| `suite_not_found`, `no_test_ran` | Aucune suite du rapport de tests le plus récent ne correspond, ou celles qui correspondent n'ont rien exécuté. |

**L'analyse statique ne compte que ce qu'elle a lu.** Une ligne sur `builtin:sast` ou
`builtin:quality` — tous deux Semgrep et ses règles — ou sur un plugin est jugée sur les langages
qu'a enregistrés l'analyse qui la fonde : ceux que son recensement a trouvés dans l'arbre du dépôt, et
ceux que lit son examen. Zéro constat de règles qui ne lisent rien du code n'est pas un résultat
propre, et Vectispire y répondrait sinon *oui* dans un document que quelqu'un signe.

- **SAST et qualité intégrés :** chaque langage *source* de l'arbre doit être lu par une des règles
  avec lesquelles l'analyse a tourné — les règles embarquées (un motif Python) plus le jeu de règles
  actif **quand la tâche de l'analyse a été construite**, chaque règle comptée pour son répertoire du
  catalogue (`java/…`, `javascript/…`). Un jeu activé plus tard ne remonte pas aux analyses plus
  anciennes ; relancez l'analyse. Java lu et TypeScript non, c'est `language_not_analysed`, pas un
  succès sur la moitié Java. Les règles qu'un exécuteur lit dans son propre
  `VECTISPIRE_SEMGREP_RULES_DIR` sont sur le disque de cet exécuteur et ne sont pas comptées.
- **Les langages source** sont ceux dans lesquels s'écrit le comportement d'un programme : tous les
  langages du vocabulaire sauf `json`, `yaml` (données), `html` (balisage), `dockerfile` et
  `terraform` (infrastructure — celle de l'étape IaC). `bash` compte : un script shell s'exécute, et
  l'injection de commande est un constat SAST. Un arbre sans aucun langage source que le recensement
  connaît — du code dans un langage hors du vocabulaire, par exemple — n'est pas un arbre dont le code
  a été analysé : `language_not_analysed`.
- **Un plugin** doit avoir lu un des langages de l'arbre, d'après le manifeste avec lequel l'analyse
  l'a lancé (pas le manifeste actuel du plugin). Les preuves nomment les langages source qu'il ne lit
  pas, sans retenir la ligne pour autant : un plugin est choisi pour ce qu'il déclare.
- Une ligne sur un périmètre de secrets, d'IaC, de dépendances, de licences ou de fin de vie, ou sur
  un outil importé, n'est pas jugée par langage.

Après une mise à jour vers cette version, chaque ligne sur ces périmètres lit `languages_unrecorded`
jusqu'à ce que chaque dépôt du projet soit analysé à nouveau — aucune analyse antérieure n'a
enregistré les langages de ses règles — et un *oui* automatique que Vectispire y avait donné est
retiré à la mesure suivante.

Les chiffres du passif excluent le **triage réglé** des deux côtés — *non affecté*, *corrigé* — et
comptent tout autre statut, y compris un statut que cette version ne connaît pas.

**La réponse à côté de la mesure :**

| Réponse | Mesure | La ligne est | À la soumission |
|---|---|---|---|
| *oui* | pass | cohérente | passe |
| *oui* | fail | **contredite** | **refusée** — répondez *non* avec la raison, ou réglez les constats par le triage, que les chiffres excluent alors |
| *oui* | no data | déclarée, non mesurée | passe **avec un commentaire et une preuve** en cours de validité, quoi que la ligne demande elle-même |
| *non* | pass | sous-déclarée | passe ; le commentaire dit pourquoi |
| *non* | fail | cohérente | passe |
| *non applicable* | toute | exclue | passe, commentée |

Une réponse peut **reposer sur la mesure** que la personne a lue : la réponse nomme l'`evidenceDigest`
de cette mesure (`measurementDigest`), la règle est appliquée à nouveau, et la réponse est conservée
en désignant la mesure conservée avec elle. Une mesure qui a bougé depuis — une nouvelle analyse, un
nouveau constat — est refusée plutôt qu'acceptée sans avoir été vue.

À l'écran, c'est **un clic** : sur une ligne mesurée *atteint*, **Répondre oui, comme mesuré** envoie
votre oui reposant sur la mesure affichée ; sur une ligne *non atteint*, **Répondre non, comme mesuré**
ouvre le formulaire sur un non, qui demande son commentaire. Une ligne sans données n'offre rien sur
quoi reposer : répondez vous-même, et un oui y demande alors un commentaire et une preuve. Choisir une
autre réponse que celle mesurée l'envoie sans mesure. Si la mesure a changé entre votre lecture et
votre clic, la page la relit et le dit sur la ligne : lisez-la, puis répondez.

**Toutes les lignes mesurées d'un coup.** `POST /api/v1/projects/{id}/checklists/{revision}/answers/as-measured`,
avec l'`edition` que vous avez lue et, dans `lines`, chaque ligne que la page vous a montrée comme
répondable avec le `measurementDigest` lu, donne ce clic pour chacune d'elles où il n'attend rien de
vous : chaque ligne désignée, sans réponse, toujours sur la preuve que vous avez lue et *atteinte*,
reçoit un *oui*, en votre nom, reposant sur cette mesure — une ligne de son historique comme toute autre
réponse, et une entrée d'audit chacune. Seul ce qui vous a été montré est répondu : une ligne désignée
dont la preuve a bougé depuis votre lecture — une nouvelle analyse, un nouveau constat — est laissée
telle quelle comme **mesure changée**, avec ce qu'elle est maintenant, et une ligne atteinte qui ne vous
a pas été montrée comme **non montrée**. Il laisse aussi telles quelles, et les nomme avec la raison :
une ligne **déjà répondue** — quelle que soit
la réponse, même en attente de confirmation ou égale à la mesure : une réponse donnée par quelqu'un
n'est jamais remplacée par un geste qui ne l'a pas regardée ; une ligne **sans données** ; et une ligne
*non atteinte*, dont le non **demande un commentaire** — le clic unique ouvre le formulaire pour que
vous l'écriviez, et un commentaire écrit par le produit sous votre nom serait une affirmation que vous n'avez pas faite :
répondez-y une à une. Si quoi que ce soit a été écrit sur la révision depuis l'édition lue, rien n'est
répondu (`checklist-changed`) : relisez-la.

Sur la page, cet acte est le bouton **Répondre comme mesuré pour les lignes mesurées**, en tête des
lignes, sous la note qui dit que les mesures sont calculées en direct. Il est proposé à qui écrit, sur
le brouillon le plus récent, une fois les mesures lues, et seulement tant qu'au moins une ligne sans
réponse montre son propre bouton en un clic : il envoie exactement ces lignes, chacune avec la mesure
sur laquelle son bouton reposerait. Un récapitulatif reste ensuite au-dessus des lignes jusqu'à ce que
vous le fermiez ou lisiez une autre révision : combien de lignes ont reçu un oui comme mesuré, puis ce
qui a été laissé tel quel, par raison — les lignes *non atteintes* qui attendent votre non, chacune avec
un bouton **Ligne N : répondre non** qui ouvre son formulaire sur non, reposant sur la mesure, le champ
de commentaire prêt ; les lignes dont la mesure a changé depuis votre lecture, à vérifier à nouveau ;
les lignes sans données, auxquelles répondre vous-même ; une ligne atteinte qui ne vous avait pas été
montrée ; et une ligne envoyée à laquelle quelqu'un a répondu entre-temps. Une ligne quitte le
récapitulatif dès qu'elle a sa réponse. Un refus s'explique comme toute autre écriture de la page —
`checklist-changed` avec l'offre de recharger.

**Soumettre** n'est proposé qu'une fois les mesures lues et quand aucune ne retient la révision — un oui
contredit, ou un oui sans données auquel manque son commentaire ou sa preuve — ce que l'état de chaque
ligne seul ne sait pas ; la page nomme les lignes. Une révision soumise dont une mesure n'est plus
celle de la soumission grise la **validation** avec la raison. Si le serveur refuse quand même
(`checklist-measurement-contradicted`, `checklist-measurement-changed`), les lignes qu'il nomme sont
mises en évidence avec la réponse, ce qui est mesuré maintenant et, à la validation, ce que la
soumission avait trouvé.

**La fraîcheur est rejugée à chaque étape.** La soumission mesure à nouveau chaque ligne liée et
conserve ce qu'elle a trouvé, chacune avec la réponse à laquelle elle a été rapprochée. L'approbation
mesure à nouveau, et **est refusée quand le résultat ou la raison d'une ligne n'est plus celui que la
soumission a conservé** — une signature ne doit pas attester une preuve qui a cessé d'être vraie
entre-temps (et une ligne devenue satisfaite est un tableau que l'auteur de la soumission n'a pas
attesté non plus). Le refus est consigné et signalé comme toute approbation refusée ; renvoyez la
révision, et soumettez-la à nouveau. Une approbation acceptée conserve ses mesures : une révision
approuvée lit ses mesures telles qu'elles ont été signées, quoi que fasse le passif ensuite.

## Réponses automatiques

Avec le paramètre de plateforme [**Répondre automatiquement aux lignes mesurées des checklists**](../administration/settings.fr.md#checklists-de-securite)
activé — c'est le défaut — **Vectispire répond lui-même aux lignes mesurées d'un brouillon**, à partir
de leur mesure, pour qu'une checklist arrive remplie de tout ce que les analyses peuvent affirmer :

| La mesure | La réponse de Vectispire |
|---|---|
| Atteint | *oui* |
| Non atteint | *non*, avec un commentaire rédigé à partir de la mesure — la règle et ce qui l'a fait échouer, commençant par *Measured by Vectispire* |
| Pas de données | rien |

Le commentaire est écrit **en anglais**, comme la feuille *Evidence* : la plateforme ne déclare pas de
langue de document, et les mots de votre organisation sont ceux du modèle (oui, non), pas les phrases
du produit.

**Quand.** Quand une analyse se termine sur un dépôt du projet, quand un rapport SARIF, de couverture
ou de tests est accepté pour l'un d'eux, et quand la checklist est ouverte, passée à une autre version
ou rouverte — la page où vous arrivez montre déjà les réponses. Après une analyse ou un rapport, les
réponses arrivent **en moins d'une minute** plutôt qu'aussitôt : l'analyse ou l'import les met en file
avec ses propres résultats, et le prochain passage du relais du planificateur les donne, en réessayant
si la réponse échoue — un serveur qui s'arrête au mauvais moment répond donc quand même à son redémarrage. Jamais sur une révision soumise ou
approuvée, et jamais parce que quelqu'un a lu la page.

**Qui.** L'auteur est **Vectispire** : aucun compte, aucun rôle. Chacune de ces réponses porte la
mention *automatique* à côté de son auteur, repose sur la mesure qui l'a produite, est une ligne de
l'historique comme une autre, et est inscrite au journal d'audit en `CHECKLIST_ANSWERED` **sans
utilisateur** — personne ne l'a demandée — avec une description qui nomme Vectispire. Ce qui distingue
une réponse automatique de celle d'une personne est sa **nature**, `answeredByKind: system`, jamais le
nom : un compte peut s'appeler *Vectispire*, et ses réponses sont celles d'une personne.

**Les personnes d'abord.**

- **La réponse d'une personne n'est jamais remplacée** par Vectispire — toute réponse donnée par
  quelqu'un, y compris une réponse reportée d'une révision antérieure et en attente de confirmation.
- **Répondez vous-même à une ligne et elle est à vous** : votre réponse remplace celle de Vectispire,
  et les analyses la laissent ensuite en paix — même si la mesure la contredit, ce que la soumission
  nommera.
- **Vectispire ne remplace sa propre réponse que si ce qu'elle affirme change** — sa valeur, ou son
  commentaire généré, qui porte les chiffres : un *non* dont « 5 open » devient « 3 open » reçoit une
  nouvelle réponse. Une nouvelle analyse qui mesure la même chose n'écrit rien, aussi souvent que la
  checklist soit ouverte ou analysée : l'édition de la révision ne bouge pas sous les personnes qui la
  remplissent. L'historique garde chaque réponse.
- **Quand la mesure n'a plus de données** — l'analyse la plus récente a dépassé l'âge maximal de la
  règle, une étape a cessé de produire — Vectispire **retire** sa propre réponse : la ligne redevient
  sans réponse, et son historique montre la réponse et son retrait. Un *oui* laissé debout sur des
  données qui ne sont plus là serait une affirmation que plus personne ne fait.

**Ce qui demande toujours une personne.** La soumission et l'approbation sont inchangées — des
personnes, sous [double validation](../administration/four-eyes.fr.md). L'auteur de la soumission
atteste de toute la révision, réponses automatiques comprises. Vectispire n'est **aucun des auteurs de
la révision** : la double validation compare les personnes qui l'ont écrite. Les règles de la soumission
s'appliquent aux réponses automatiques comme aux autres : un *non* porte son commentaire généré, il
passe donc ; un *oui* automatique sur une ligne qui demande **un fichier ou un lien exige toujours
cette preuve** — joignez-la, sinon la ligne retient la révision en *preuve requise*.

**Sur la page.** Une réponse automatique porte le badge **Automatique — mesuré par Vectispire** à
côté d'elle, est *répondue par Vectispire*, et son commentaire généré s'affiche comme commentaire de la
ligne. L'en-tête les compte — **N réponse(s) automatique(s)** — pour que vous voyiez d'un coup d'œil ce
que les analyses ont rempli, et ce qui vous reste. La ligne reste à vous : **Changer la réponse** ouvre
le formulaire avec la réponse et le commentaire de Vectispire, et dit **Répondre remplace la réponse
automatique : la ligne devient la vôtre.** Dans l'**historique** de la ligne, les entrées de Vectispire
sont marquées *automatique*, et un retrait se lit **Réponse automatique retirée (plus de données)**.
**Répondre comme mesuré pour les lignes mesurées** reste là, proposé seulement pour les lignes encore sans
réponse — le réglage activé, il n'y en a le plus souvent aucune.

**Désactivé**, plus rien n'est répondu automatiquement ; les réponses déjà écrites restent, chacune
marquée comme étant de Vectispire, jusqu'à ce que quelqu'un y réponde par-dessus. La réponse « comme
mesuré » en un clic demeure.

## Le document

`GET /api/v1/projects/{id}/checklists/{revision}/document` renvoie la révision comme un document à
remettre : un zip, toujours servi en téléchargement.

| Entrée | Ce que c'est |
|---|---|
| `checklist.xlsx` | **Le classeur de votre propre modèle, rempli.** Chaque partie du fichier est celle du modèle, octet pour octet, sauf les cellules écrites : la réponse de chaque ligne — dans le mot du modèle — et son commentaire, et, dans l'en-tête, le produit, l'auteur et la date. Les listes de validation, les extensions, les commentaires et les styles sont intacts. La date est une **valeur, l'instant de l'approbation** — une formule comme `AUJOURDHUI()` est remplacée, puisqu'elle daterait chaque copie du jour de sa dernière ouverture. Une feuille est ajoutée, **Evidence** : une ligne par ligne de la checklist avec sa réponse, qui l'a donnée — *Vectispire (automatic, from its measurement)* pour une réponse automatique — et quand, le résultat de la mesure, l'instant dont elle date, le résumé et le SHA-256 de ses preuves, ce que disent ensemble la réponse et la mesure (*declared, not measured* pour un oui sans données), les liens et les empreintes des fichiers de preuve ; puis qui a soumis, qui a approuvé, et si la double validation s'appliquait. Les instants sont en UTC. |
| `checklist.json` | La même déclaration, lisible par une machine : projet, révision, identifiant du modèle, version et SHA-256 du fichier source, chaque ligne avec sa réponse courante et son historique — chaque réponse avec son `answeredByKind`, `person` ou `system`, et un retrait par Vectispire marqué `withdrawn` (déclaration de `form` 2) —, sa mesure (la règle et les preuves en textes exacts, ceux que couvrent leurs empreintes) et ses preuves — les fichiers nommés par leur SHA-256, jamais inclus —, l'auteur de la soumission, l'approbateur et la version de Vectispire. |
| `checklist.xlsx.sig`, `checklist.json.sig` | Signatures détachées par la clé de signature de la plateforme — **seulement pour une révision approuvée**. |

**Le document d'une révision approuvée est produit et signé avec son approbation**, puis conservé :
chaque téléchargement renvoie ces mêmes octets, quoi qui ait changé depuis. Un brouillon, une révision
soumise ou remplacée est rendu pour la requête, **sans signature**, ses lignes mesurées mesurées pour
lui, sa cellule de date laissée vide et sa feuille Evidence ouverte par *Draft — not signed off*.
Une révision approuvée **avant que les documents soient signés** n'a pas de paquet conservé : elle est
rendue de la même façon, sans signature, et sa feuille Evidence s'ouvre en disant qu'elle a été
approuvée mais qu'aucun document signé n'a été produit alors. La page propose tout de même son
téléchargement comme un *paquet signé* — elle ne voit que le statut —, si bien qu'un zip sans
entrées `.sig` relève de ce cas, et non d'une panne.

Sur la page de la checklist, **Document** télécharge la révision affichée — *Télécharger le paquet
signé* pour une révision approuvée, *Télécharger un rendu non signé* sinon — et **Révisions** propose
de même celui de chaque révision antérieure. Une révision approuvée montre aussi les commandes
ci-dessous, prêtes à copier, et un lien vers la clé publique.

Quiconque peut lire la checklist peut la télécharger ; une [clé d'intégration](../administration/api-keys.fr.md)
ayant la portée `export` aussi — mais une clé restreinte à un dépôt ne voit jamais un projet en entier,
et reçoit la réponse d'un projet qui n'existe pas.

**Vérifiez-le avec une clé obtenue séparément**, jamais une clé remise avec le document :

```bash
curl -fsS -H "Authorization: Bearer $VECTISPIRE_TOKEN" -o checklist.zip \
  "$VECTISPIRE_URL/api/v1/projects/12/checklists/3/document"
curl -fsS -o vectispire-signing-key.pub "$VECTISPIRE_URL/api/v1/crypto/public-key.pub"
unzip checklist.zip
cosign verify-blob --key vectispire-signing-key.pub --insecure-ignore-tlog=true \
  --signature checklist.xlsx.sig checklist.xlsx
cosign verify-blob --key vectispire-signing-key.pub --insecure-ignore-tlog=true \
  --signature checklist.json.sig checklist.json
```

`--insecure-ignore-tlog=true` dit seulement que la signature n'a jamais été publiée dans le journal
de transparence public de Sigstore — Vectispire signe avec sa propre clé et ne publie rien — et il est
nécessaire, sans quoi cosign cherche une entrée qui n'existe pas. C'est la clé qui est vérifiée.

## Révisions antérieures

**Révisions** liste chaque révision de la checklist du projet, de la plus récente à la plus ancienne,
avec son statut, sa version, qui l'a ouverte et qui l'a approuvée. **Lire** en montre une telle
qu'elle est, en lecture seule : seule la révision la plus récente fait l'objet d'actions.

## Quand le serveur refuse

Chaque refus est nommé par sa cause, et l'écran le dit en une phrase :

| L'écran dit | Ce qui s'est passé |
|---|---|
| La checklist a changé depuis que vous l'avez lue | Quelqu'un d'autre a modifié la révision après que vous l'avez chargée. Rechargez, regardez, réessayez. |
| Quelqu'un d'autre a écrit sur cette ligne | Une autre réponse ou preuve est arrivée sur la même ligne. Rechargez pour la voir. |
| Cette révision n'est plus un brouillon / n'attend plus d'approbation | Elle a été soumise, approuvée, renvoyée ou mise de côté entre-temps. |
| Seule une révision approuvée se rouvre / une révision plus récente existe | Agissez sur la révision la plus récente. |
| Toutes les lignes ne sont pas prêtes | Des lignes demandent encore de l'attention : elles sont nommées, et chacune est marquée *Refusé pour cette ligne* avec ses problèmes — pas de réponse, commentaire requis, preuve requise ou périmée, en attente de confirmation — tels que le serveur les a trouvés, ce qu'une preuve expirée depuis le chargement de la page peut faire différer de ce que la ligne montrait. |
| Principe des quatre yeux : une deuxième personne doit l'approuver | Vous avez écrit une partie de cette révision. |
| Une ligne répond oui là où sa mesure échoue (`checklist-measurement-contradicted`) | La soumission est refusée ; les lignes sont nommées. Voir [lignes mesurées](#lignes-mesurees). |
| Une mesure a changé (`checklist-measurement-changed`) | À l'approbation : la mesure d'une ligne n'est plus celle que la soumission a conservée — renvoyez la révision. Sur une réponse qui repose sur une mesure : ce n'est pas celle que vous avez lue — rechargez. |
| Cette version n'est plus publiée / déjà sur cette version | Choisissez une autre version ; après une approbation, rouvrez plutôt. |
| Aucune approbation ne pourrait remplir le classeur de la version choisie (`checklist-version-unrenderable`) | La version a été publiée avant que Vectispire ne contrôle les modèles pour cela, et une cellule que l'approbation écrit dans son classeur porte une formule dont d'autres cellules dépendent : les cellules sont nommées. Rien n'a été ouvert ni changé de version. Voir ci-dessous. |
| Plus de réponse reportée en attente / preuve déjà retirée | Quelqu'un l'a fait avant vous. |

Une approbation refusée parce qu'**une cellule du classeur du modèle porte une formule dont d'autres
cellules dépendent** — la phrase nomme les cellules — ne peut pas réussir sur cette version : le
classeur est celui du modèle, et une version publiée ne change jamais. Depuis la version qui suit la 0.10.0,
une version est contrôlée avant sa publication, et une checklist n'est plus **ouverte sur une version
publiée plus tôt qui échoue au même contrôle, ni passée à celle-ci** : l'écran en nomme les cellules, et
rien n'est ouvert, changé de version ni consigné — une checklist qui ne pourrait jamais être approuvée
n'est pas commencée. Demandez à qui gère les modèles une
[version corrigée](../administration/checklist-templates.fr.md#une-formule-dans-une-cellule-que-vectispire-ecrit),
puis ouvrez la checklist sur celle-ci, ou [passez-y](#7-passer-a-une-version-plus-recente) : vos réponses
sont reportées. **Quitter** une telle version n'est jamais refusé — c'est la sortie pour une checklist
qui s'y trouve déjà.

## Ce qui est consigné

L'ouverture, le passage de version, la réouverture, chaque réponse et chaque confirmation — les
réponses automatiques de Vectispire et leurs retraits compris, sans utilisateur et avec une
description qui nomme Vectispire —, chaque
preuve jointe ou retirée, la soumission, le renvoi, l'approbation et une approbation refusée sont
inscrits au [journal d'audit](../administration/audit-log.fr.md), de même que chaque téléchargement
du document, avec son SHA-256. Une approbation est signalée au SIEM
comme `VECTI-SEC-025` ; une approbation refusée et un renvoi comme `VECTI-SEC-026`.

## À lire aussi

- [Modèles de checklists](../administration/checklist-templates.fr.md) — où un modèle est importé,
  apparié avec sa version précédente et publié.
- [Double validation](../administration/four-eyes.fr.md) — le réglage qui décide qui peut approuver.
- [Solutions et projets](../administration/solutions-and-projects.fr.md) — les projets auxquels une
  checklist appartient, et les droits qui décident qui en voit un en entier.
