# Modèles de checklists

Un modèle de checklist est **la checklist de sécurité de votre organisation**, importée depuis le
classeur que vous utilisez déjà : ses domaines, objectifs, contrôles, contacts et KPI, dans ses
propres mots et sa propre langue. Les projets y répondent ligne par ligne — voir
[checklists de sécurité](../guide/security-checklists.fr.md) ; cette page est celle où le modèle
lui-même est importé, vérifié et publié.

Ouvrez-la depuis **Administration → Modèles de checklists**. La décision
[0032](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0032-security-checklists.md)
consigne pourquoi il fonctionne ainsi.

!!! info "Jamais publié en une étape"
    Un classeur devient un **brouillon**. Quelqu'un confirme où se trouve la checklist dans le
    classeur et ce que veulent dire ses mots de réponse, ses lignes sont appariées avec la version
    précédente, et c'est seulement ensuite qu'il est publié. Une version publiée ne change jamais :
    un nouveau mot, une nouvelle disposition ou une nouvelle liaison fait une nouvelle version.

## Qui peut faire quoi

| | Gouverneur de la plateforme, administrateur, CISO | Auditeur | Tous les autres |
|---|---|---|---|
| Voir les modèles, leurs versions, la feuille, la disposition, les items et l'appariement | oui | oui | non — l'entrée n'est pas dans leur menu |
| Importer un classeur, confirmer une disposition, apparier des items, dériver une version | oui | non | non |
| Publier un brouillon, retirer une version publiée | oui et, [double validation](four-eyes.fr.md) active, **pas la personne qui l'a écrit** | non | non |
| Écarter un brouillon | oui, son auteur compris | non | non |

L'auditeur voit chaque écran décrit ci-dessous sans une seule commande qui modifie quoi que ce soit.

## 1. Importer un classeur

Donnez au modèle un **identifiant** — de 1 à 64 minuscules, chiffres et tirets intérieurs, comme
`checklist-livraison`. Un nouvel identifiant crée le modèle, nommé par **Nom du modèle** ; un
identifiant existant reçoit sa version suivante et le nom n'est pas demandé. Le **libellé de la
version** est facultatif (`Édition 2026`).

Le `.xlsx` est envoyé tel quel. L'écran refuse un fichier de plus de **10 Mo** avant d'envoyer quoi
que ce soit, avec la phrase que le serveur répondrait. Le serveur refuse un classeur à macros
(`.xlsm`), le format binaire, et un fichier qui échoue à l'un de ses gardes — plus de 200 entrées zip,
plus de 50 Mo décompressés, une entrée compressée plus de 100 pour un, une DTD dans une partie
quelconque, une cible de relation externe. Un modèle a **au plus un brouillon à la fois** : tant qu'il
en existe un, l'import est refusé jusqu'à ce qu'il soit publié ou écarté.

Le fichier source est conservé avec son SHA-256, affiché sur la version : les documents signés d'un
lot ultérieur s'écrivent dedans, et un auditeur peut comparer un document livré avec le modèle qu'il
dit suivre.

## 2. Confirmer la disposition, sur la feuille elle-même

Ouvrir une version montre sa feuille sous forme de grille — numéros de ligne sur le côté, lettres de
colonne en haut — avec un sélecteur pour les autres feuilles du classeur. Le lecteur a **proposé** une
disposition à partir de la structure du classeur : ses plages de validation, ses cellules fusionnées,
et la ligne suivie d'une suite de lignes remplies. Il ne cherche jamais de mots attendus, qui seraient
le vocabulaire d'une seule organisation inscrit dans le produit. La grille dessine la disposition à
l'écran par-dessus les cellules :

- l'en-tête d'une colonne nomme le champ qu'elle porte — `C · Contrôle` ;
- les lignes d'items des colonnes nommées sont surlignées en bleu ;
- les cellules d'en-tête sont surlignées en ambre ;
- la ligne d'en-têtes de colonnes trouvée par le lecteur est en gras ; `ƒ` signale une formule.

Corrigez ce qui est faux ; la grille suit la saisie.

| Partie | Ce qu'il faut donner |
|---|---|
| Colonnes | Les lettres de chaque champ. **Contrôle, réponse et commentaire sont obligatoires** ; identifiant, domaine, objectif, contact et KPI quand le modèle les a. Une colonne identifiant fait de ses valeurs les clés des items ; sans elle, une clé est tirée du texte du contrôle. |
| Lignes d'items | La première et la dernière ligne qui portent des items, 5 000 lignes au plus. |
| Cellules d'en-tête | Pour la date, le produit et l'auteur, chacun seulement si le modèle l'a : la cellule du libellé, laissée telle quelle, et la cellule de la valeur, où l'on écrit. Les deux ou aucune ; jamais parmi les lignes d'items, et deux entrées ne partagent jamais une cellule de valeur. |
| Mots de réponse | Les mots du modèle lui-même pour **oui** et **non**, quelle que soit sa langue. La liste de réponses trouvée par le lecteur dans la validation de la colonne réponse est affichée à côté ; l'écran ne l'associe jamais à votre place — quel mot veut dire oui, c'est à vous de le dire. |
| Non applicable | Proposé seulement si vous le cochez et nommez son mot. Quand la liste du modèle n'a pas ce mot, saisissez-en un : le document le porte, et la liste du modèle reste telle quelle. Une réponse « non applicable » exige toujours sa justification. |

**Confirmer la disposition** lit les items : les cellules de domaine et d'objectif vides sont remplies
vers le bas, comme la feuille les entend, et une ligne dont la cellule contrôle est vide n'est pas un
item. Les items lus apparaissent sous la grille. Confirmer à nouveau plus tard les relit et **efface
les appariements faits à la main**, puisqu'ils nommaient les items tels que la disposition précédente
les lisait.

## 3. Apparier les items avec la version précédente

Une fois la disposition confirmée, chaque item est comparé avec la version publiée précédente :

| Changement | Ce qu'il signifie pour la réponse d'un projet, quand le projet passe à la nouvelle version |
|---|---|
| Inchangé | Même clé, même contenu : reportée telle quelle. |
| Modifié | Même clé, contenu différent — la formulation, le KPI ou la liaison ont bougé : reportée, à confirmer. |
| Ajouté | Aucune clé dans la version précédente : commence sans réponse. |
| Supprimé | Absent de cette version : sa réponse reste là où elle a été donnée. |

Un contrôle seulement reformulé apparaît comme un item supprimé et un item ajouté. **Appariez-les à
la main** : choisissez l'item ajouté et l'item supprimé qu'il est, puis **Les apparier**. Le nouvel
item prend l'ancienne clé et devient *modifié*, *apparié à la main*, afin que la réponse d'un projet
le suive, à confirmer. **Désapparier** défait un appariement. Une première version n'a rien avec quoi
s'apparier : chaque item est nouveau.

Confirmer une disposition et apparier des items sont envoyés sur la **révision affichée**, comme la
publication : quand un autre responsable a modifié le brouillon après que vous l'avez ouvert, votre
modification est refusée, les deux révisions nommées, plutôt que de remplacer la sienne sans qu'il le
voie. Rechargez le brouillon et refaites-la.

## 4. Publier

Publier fait de la version celle sur laquelle les projets ouvrent leurs checklists. Le bouton nomme la
**révision** affichée — le compteur de modifications du brouillon — et c'est cette révision qui est
envoyée : une modification faite par quelqu'un d'autre après l'ouverture de la page refuse la
publication plutôt que de publier ce que personne ici n'a lu.

Quand le serveur refuse, l'écran dit pourquoi :

- **Vous avez écrit ce brouillon** — vous l'avez importé ou dérivé, avez confirmé sa disposition ou
  apparié ses items — et la double validation est active : **une deuxième personne doit le publier**,
  un autre gouverneur de la plateforme, administrateur ou CISO qui n'en a rien écrit. Chaque compte
  qui a façonné le brouillon en est l'auteur, pas seulement celui qui l'a importé. L'écran vous
  prévient aussi avant le clic.
- **Le brouillon a changé depuis que vous l'avez lu** : la révision relue et la révision actuelle sont
  toutes deux nommées. Rechargez-le, relisez-le, puis publiez.
- **Il n'a pas de disposition confirmée**, ou **ce n'est plus un brouillon** parce que quelqu'un l'a
  publié ou écarté entre-temps.

Double validation active, la plateforme refuse de se retrouver avec un seul compte capable de
publier — voir [double validation](four-eyes.fr.md#lactiver-demande-quune-seconde-personne-existe).

## 5. Dériver, retirer, écarter

- **Dériver un nouveau brouillon** d'une version publiée pour changer ce qu'une version publiée ne peut
  jamais changer en place : le même classeur, la même disposition et les mêmes items, apparié avec la
  version dont il vient, et un libellé à lui si vous en donnez un.
- **Retirer** une version publiée : aucune nouvelle checklist ne s'ouvre dessus, et chaque checklist
  qui l'utilise déjà reste lisible et exportable. Double validation active, elle est retirée par
  quelqu'un qui ne l'a pas écrite.
- **Écarter le brouillon** quand il ne doit jamais être publié. Cela ne change rien à ce qu'un projet
  atteste, donc cela ne demande personne d'autre, et la version s'affiche comme *retirée*.

## Refus, pour les scripts et les intégrations

Chaque refus d'une route de modèle qui tient à l'état de la version répond **409**, et nomme sa cause
dans le `type` du problème, `urn:vectispire:problem:` suivi du jeton ci-dessous — pour qu'un script
distingue « relisez » de « quelqu'un d'autre doit le faire » sans lire la phrase, écrite pour une
personne et susceptible de changer.

| `type` se termine par | Signification | Que faire |
|---|---|---|
| `checklist-template-changed` | Le brouillon a changé depuis la `revision` nommée | Le relire |
| `checklist-template-not-draft` | La version est publiée ou retirée | Dériver un nouveau brouillon de la version publiée |
| `checklist-template-no-layout` | La disposition du brouillon n'est pas confirmée | La confirmer d'abord |
| `checklist-template-has-draft` | Le modèle a déjà un brouillon | Le publier ou l'écarter d'abord |
| `checklist-template-not-published` | Dériver d'un brouillon ou d'une version retirée | Dériver d'une version publiée |
| `checklist-template-retired` | La version est déjà retirée | — |
| `checklist-template-nothing-to-pair` | Une première version : aucune précédente avec laquelle apparier | — |
| `checklist-four-eyes` | Le double contrôle est activé et vous avez écrit ce brouillon | Quelqu'un d'autre le publie ou le retire |

`checklist-four-eyes` est aussi le jeton de l'approbation d'une checklist de projet : il y signifie la
même chose.

## Ce qui est consigné

Chaque import, confirmation de disposition, appariement, dérivation, publication et retrait est inscrit
au [journal d'audit](audit-log.fr.md). Publier une version, et retirer une version publiée, est aussi
signalé au SIEM comme `VECTI-SEC-024`.

## À lire aussi

- [Checklists de sécurité](../guide/security-checklists.fr.md) — la checklist d'un projet, remplie sur une version
  publiée, et ce que le passage à une nouvelle version reporte.
- [Double validation](four-eyes.fr.md) — le réglage qui décide qui peut publier.
- [Utilisateurs et équipes](users-and-teams.fr.md) — les rôles et ce que chacun peut faire.
- [Journal d'audit](audit-log.fr.md) — où chaque changement d'un modèle est inscrit.
