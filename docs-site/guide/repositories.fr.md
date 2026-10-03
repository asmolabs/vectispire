# Dépôts

Un dépôt est une cible de scan : une URL de clonage, une branche, éventuellement un
sous-chemin, et une récurrence.

![La liste des dépôts : deux cibles avec leur branche, leur palier de criticité, leurs constats ouverts et l'état de leur dernier scan.](../assets/screens/fr/repositories.png)

## En enregistrer un

**Dépôts → ajouter.**

| Champ | Notes |
|---|---|
| **URL du dépôt** | HTTPS pour un dépôt public, SSH là où une clé de déploiement est nécessaire. Donnez l'adresse que la forge sert réellement : un clonage **ne suit aucune redirection HTTP**, vers aucun hôte, parce que l'hôte qu'elle ferait atteindre n'a jamais été vérifié. Un projet déplacé ou renommé échoue avec *« answered with a redirect … to &lt;hôte&gt; »* — enregistrez la nouvelle adresse. |
| **Nom affiché** | Le nom sous lequel tous les autres écrans le désignent. |
| **Branche** | La branche analysée à chaque exécution. |
| **Sous-chemin** | Pour un monodépôt. Enregistrez un monodépôt **une fois par projet**, pas une fois pour l'arbre entier — sinon un seul SBOM confond les dépendances de plusieurs applications et aucun verdict ne veut plus rien dire. Relatif à la racine du dépôt — `services/billing` — sans segment `..` ni `/` initial ; un répertoire qui est un lien hors du dépôt fait échouer l'analyse plutôt qu'analyser autre chose. |
| **Niveau de criticité métier** | Niveau 1 · critique pour la mission, niveau 2 · opérationnel, niveau 3 · interne. |
| **Agent requis** | Épingle le scan à un agent. Laissez vide, sauf si le dépôt n'est routable que depuis un segment réseau particulier. |

## Identifiants {#credentials}

Les dépôts privés s'authentifient avec une clé de déploiement enregistrée sous
[Clés SSH](../administration/ssh-keys.md). Donnez-lui un accès **en lecture seule** chez votre
hébergeur — Vectispire ne fait jamais que cloner.

La moitié privée est chiffrée au repos avec votre `ENCRYPTION_KEY`. Le stockage d'une clé est
refusé net tant que cette variable n'est pas posée.

### En SSH : la clé d'hôte de la forge {#ssh-host-keys}

Un clone avec une clé de déploiement vérifie la **clé d'hôte** du serveur contre un fichier
`known_hosts` tenu par l'exécutant qui mène le scan — le worker intégré du plan de contrôle ou un
agent :

- **Premier contact :** la clé est acceptée et inscrite dans ce fichier.
- **Chaque clone suivant :** la clé doit correspondre. Sinon le scan échoue avec *« The host key of
  … has changed since the last clone. Check it is the same server before running again. »* et rien
  n'est récupéré. Après une vraie rotation chez la forge, supprimez la ligne de cet hôte dans le
  fichier ; le scan suivant inscrit la nouvelle clé.
- **Épinglée plutôt qu'apprise :** écrivez vous-même les clés de la forge dans le fichier (issues de
  `ssh-keyscan`, comparées aux empreintes que publie votre forge) et rendez le fichier **en lecture
  seule** pour l'exécutant. Il n'est alors que comparé : un hôte qu'il ne liste pas est refusé, et
  rien n'y est jamais ajouté.

Le fichier est `<home>/.ssh/known_hosts` du processus de l'exécutant. Dans le `docker-compose.yml`
livré, c'est `$VECTISPIRE_WORK_DIR/home/.ssh/known_hosts` pour le plan de contrôle et
`$VECTISPIRE_AGENT_WORK_DIR/home/.ssh/known_hosts` pour l'agent — voir
[Installation](../getting-started/installation.md). Rien d'autre de ce répertoire n'est lu pour un
clone avec clé : ni identité, ni agent, ni `config` — un alias `Host`, un `Port`, un `ProxyJump` ou
un `StrictHostKeyChecking` y sont sans effet. Mettez l'hôte et le port réels dans l'URL du dépôt.

#### Un agent `local` : remplir `known_hosts` avant son premier clone {#ssh-known-hosts-local-agent}

Un agent en mode `local` ne reçoit aucune clé et clone avec l'accès SSH de sa propre machine —
l'identité, la `config` et le `known_hosts` du `.ssh` de son home, utilisés tels quels. C'est le
comportement de ssh lui-même, et il **refuse un hôte que son `known_hosts` ne liste pas** :
personne n'est là pour répondre « êtes-vous sûr ? ». La première analyse échoue alors avec *« The
host key of … was refused by this machine's own known_hosts: the host is not listed there, or its
key has changed. »* C'est voulu — un premier contact inscrit sans vérification est le moment où
une interception serait crue — et le fichier est donc rempli une fois, par vous, après avoir
vérifié la clé.

Le fichier est `<home>/.ssh/known_hosts` du processus de l'agent : dans le profil `with-agent`,
`$VECTISPIRE_AGENT_WORK_DIR/home/.ssh/known_hosts` ; pour l'image de l'agent lancée seule,
`/home/vectispire/.ssh/known_hosts` sauf si vous réglez `-Duser.home`. Sur l'hôte de l'agent :

```bash
# 1. Récupérer les clés d'hôte de la forge (ajoutez -p <port> pour un port non standard).
ssh-keyscan -t ed25519,ecdsa,rsa gitlab.example.com > known_hosts.new

# 2. Afficher leurs empreintes et comparer CHACUNE à celles que publie la forge — GitHub et
#    GitLab.com listent les leurs dans leur documentation ; pour votre propre serveur, demandez à
#    son administrateur la sortie de `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.
#    Une différence : arrêtez-vous.
ssh-keygen -lf known_hosts.new

# 3. Installer le fichier pour l'utilisateur de l'agent (1000:1000 dans les images).
home="${VECTISPIRE_AGENT_WORK_DIR:-/var/lib/vectispire/agent-work}/home"
sudo install -d -m 0700 -o 1000 -g 1000 "$home/.ssh"
sudo install -m 0644 -o 1000 -g 1000 known_hosts.new "$home/.ssh/known_hosts"
```

`ssh-keyscan` récupère les clés par le même réseau que celui où se tiendrait une interception :
l'étape 2, contre une empreinte obtenue par un autre chemin, est la vérification, et la sauter
inscrit ce qui a répondu. L'identité avec laquelle l'agent clone se place à côté
(`$home/.ssh/id_ed25519`, mode 0600, propriété de 1000) — une clé dédiée à cet agent, jamais la
vôtre. Ne mettez pas `StrictHostKeyChecking no` dans une `config` de ce répertoire pour passer
outre le refus : il accepterait n'importe quel serveur, clé changée comprise.

### En HTTPS, avec un jeton

Un dépôt joignable seulement en HTTPS se clone avec un **jeton HTTPS** — un jeton personnel, de
projet ou de déploiement délivré par la forge, avec un accès en lecture au dépôt. Enregistrez-le
sous **Jetons HTTPS**, à côté de [Clés SSH](../administration/ssh-keys.fr.md) dans le menu, avec :

- **l'hôte** pour lequel il est émis (`gitlab.example.com`, sans schéma ni port). Le jeton est
  présenté à cet hôte et à **aucun autre** : un dépôt dont l'URL nomme un autre serveur ne peut pas
  l'utiliser, et une redirection vers un autre hôte ne reçoit rien — c'est mesuré, pas supposé ;
- un **nom d'utilisateur** si votre forge en veut un à côté du jeton ; laissé vide, une valeur fixe
  est envoyée, que GitLab, GitHub et Gitea acceptent.

Un dépôt utilise une clé SSH **ou** un jeton HTTPS, du type que son URL appelle. Le jeton est chiffré
comme une clé, jamais réaffiché, et ne rejoint un agent qu'en mode `delegated`, scellé ; un agent
`local` n'en reçoit aucun.

**Un jeton écrit dans l'URL n'est plus accepté** (`https://utilisateur:jeton@hôte/…`) : il était
conservé en clair dans la ligne du dépôt et envoyé à chaque agent. Les dépôts déjà enregistrés ainsi
continuent de fonctionner ; pour en migrer un, retirez l'identifiant de son URL et rattachez un
jeton.

## Récurrence {#recurrence}

Posez soit un **intervalle de scan**, soit une **expression cron**. L'expression l'emporte
quand les deux sont présents.

Préférez cron. Un intervalle dérive de quelques minutes à chaque exécution, si bien qu'un scan
configuré pour 03:00 migre dans la journée de travail en quelques semaines — et un scan qui
concurrence la journée de travail est le scan que quelqu'un finit par désactiver.

La récurrence est la raison d'être du produit plutôt qu'une commodité : de nouvelles
vulnérabilités sont publiées contre du code qui n'a pas changé, donc un dépôt analysé une fois
est un dépôt dont la posture est connue à une date passée.

## Niveaux de criticité métier {#business-criticality-tiers}

Trois niveaux, et ils existent pour que le classement tienne compte de ce qu'une cible *est*
plutôt que seulement de ce qu'on y a trouvé :

- **Niveau 1 · critique pour la mission**
- **Niveau 2 · opérationnel**
- **Niveau 3 · interne**

La même CVE critique n'est pas le même problème dans un chemin de paiement et dans un outil
interne jetable. Sans niveau, le backlog affirme qu'ils sont identiques.

## Projet {#project}

Chaque dépôt indique le projet où il est rangé, avec un lien vers ce projet dans
[Solutions et projets](../administration/solutions-and-projects.md), ou « — » s'il n'est dans
aucun. Le rangement se fait depuis cet écran, par un administrateur — et il change des accès : une
attribution sur un projet couvre les dépôts qui y sont rangés.

## La pastille README

Chaque dépôt peut exposer une pastille dynamique pour son propre README, montrant la note de
posture de sécurité. Elle met le chiffre sous les yeux des gens qui commitent, c'est-à-dire là
où il change les comportements.

## Comment la note du scorecard est calculée

La note de la **fiche scorecard** d'un dépôt et celle de sa pastille sont le même nombre. Elle
est calculée à la demande, sur le backlog du dépôt tel qu'il est — rien n'est stocké.

**Ce qui compte.** Les problèmes ouverts de ce dépôt seulement. Les problèmes résolus sont
écartés, ainsi que ceux triés **non affecté** ou **corrigé** — les deux décisions qui empêchent
déjà un problème de faire échouer la barrière. Un problème dont l'exclusion est **en attente
d'approbation** compte toujours : une demande n'est pas une décision. Un statut de triage que
Vectispire ne reconnaît pas compte aussi, plutôt que d'être lu comme réglé.

**Le score** part de 100 :

| Élément | Points | Par |
|---|---|---|
| Vulnérabilité activement exploitée (CISA KEV) | −25 | problème |
| Critique | −8 | problème |
| Haute | −4 | problème |
| Licence non autorisée par la politique de licences | −5 | composant |
| Au moins un scan terminé | +5 | une fois |

**L'atteignabilité n'est pas un terme.** Vectispire n'exécute aucune analyse de graphe d'appels,
si bien que rien n'établit si le code vulnérable d'un composant est appelé. La note facturait un
critique « atteignable » −15 au lieu de −8, sur une valeur jamais enregistrée ; tout critique coûte
désormais −8, ce que toutes les notes valaient déjà.

Les pénalités s'additionnent : un critique activement exploité coûte 33. Les
sévérités moyenne et basse ne coûtent rien. Le résultat est borné entre 0 et 100.

**La note :**

| Score | Note |
|---|---|
| 95 et plus | A+ |
| 85 – 94 | A |
| 70 – 84 | B |
| 55 – 69 | C |
| 40 – 54 | D |
| moins de 40 | F |

Par exemple, un dépôt scanné avec deux critiques, une haute, une moyenne activement exploitée et
une licence non autorisée obtient 100 − 8 − 8 − 4 − 25 − 5 + 5 = **55, note C**.

**Pas de scan, pas de note.** Un dépôt ou une image sans scan terminé n'a rien à noter : sa fiche
porte la note **`NO_DATA`** sans score (`score` vaut `null`), et sa pastille affiche *no data* en gris.
Elle affichait 100, A+ — le score retranche de cent ce qu'il trouve, et personne n'avait regardé. Les
compteurs restent, puisqu'ils sont vrais de ce qui a été lu ; un import SARIF seul ne fait pas d'une
cible une cible analysée. Un scan en cours, ou un scan échoué après un scan terminé, n'enlève pas la
note : le backlog noté est celui qu'a laissé le dernier scan terminé.

**Un portefeuille, un projet ou une solution** — la fiche globale et celle qui accompagne
[la conformité d'un projet](compliance.fr.md#par-projet-et-par-solution) — se calcule de même sur les
cibles que vous voyez, avec deux règles propres. Aucune analysée, c'est `NO_DATA`. Une partie analysée
plafonne le score à la part analysée, arrondie, et ajoute la recommandation *Scan the N target(s) never
scanned* : dix cibles dont une analysée propre valent 10, pas 100 — le plafond de couverture des
contrôles de conformité, lu sur les mêmes cibles. `totalTargets` et `observedTargets` disent ce que la
fiche couvre. La fenêtre de fraîcheur de la conformité ne la plafonne pas : cette fenêtre est un
réglage de chaque installation, et une note ne doit pas différer entre deux installations qui tiennent
le même parc.

**Ce qui ne change pas la note.** Les problèmes en retard sur leur délai de remédiation sont
comptés sur la fiche et produisent une recommandation, mais ne coûtent aucun point : les délais
sont un réglage propre à chaque installation (voir [Délais de correction](remediation-delays.md#dou-viennent-les-delais)),
et une pastille ne doit pas changer de note parce que quelqu'un a modifié une fenêtre.

**Les recommandations** listent, quand elles s'appliquent : les licences non autorisées,
l'absence de scan terminé — une attestation in-toto est délivrée à partir d'un scan terminé, il
n'y en a donc aucune avant —, les vulnérabilités activement exploitées, les critiques, les
hautes et les problèmes en retard.

Les pénalités n'ont pas de plafond, l'échelle sature donc par le bas : cinq critiques
exploités suffisent pour un F, et cinq cents donnent le même F. Lisez les
compteurs de la fiche, pas seulement la lettre.

Cette note est aussi celle du classement de maturité du tableau de bord : une cible y lit le même
score et la même lettre — voir [Tableau de bord](dashboard.md#note-de-posture-de-securite).

### Une formule candidate, pour comparer (expérimental) {#score-simulation}

**Expérimental — rien ne change sur une fiche, une pastille ni le classement.** Pour décider s'il faut
remplacer la formule ci-dessus, un administrateur peut voir chaque cible notée des deux façons sur le
backlog réel du parc : `GET /api/v1/scorecards/simulation`. Rien n'est enregistré ni consigné.

La candidate est **100 × exp(−Σ poids × nombre / k)**, sur les problèmes ouverts et les licences
interdites : chacun retire une part de ce qui reste au lieu d'un nombre fixe de points, le score
continue donc de baisser avec le backlog sans jamais atteindre 0, et cinquante moyennes ne se lisent
plus comme cinq cents. Les valeurs par défaut sont la calibration validée par le responsable produit le
2026-10-03 : 25 pour un problème activement exploité (CISA KEV, quelle que soit sa sévérité — compté
dans cette classe seulement), 10 pour un critique, 4 pour un haut, 0,5 pour un moyen, 0,125 pour un bas
et **4 pour une licence interdite** (le poids d'un haut, comptée comme la fiche compte ses violations de
licence), avec **k = 55**. Tout problème exploité plafonne la note à **D** (score 54 au plus). Il n'y a
**pas de bonus pour un scan terminé** : en avoir un est ce qui fait qu'une cible est notée. Les seuils
de note sont ceux du tableau ci-dessus, inchangés. Les mêmes problèmes comptent que pour le score
actuel — ouverts, triage non réglé — et une cible sans scan terminé est `NO_DATA` dans les deux.

À côté du score, chaque ligne porte ses **points de risque**, le total pondéré Σ poids × nombre dont le
score est calculé. Le score est maintenu à 1 au bas de F ; les points de risque continuent de bouger, et
une équipe loin dans F voit encore ce qu'elle a corrigé.

Avec ces valeurs, un critique donne 83 (B), un critique exploité 54 (D, plafonné), cinquante moyennes 63
(C), une licence interdite 93 (A), un critique et une licence interdite 78 (B), dix licences interdites
48 (D), cinq cents moyennes 1 (F) et vingt-sept hautes 14 (F). Avec les moyennes à 1, aucun `k` ne donne
à la fois B pour un critique et C pour cinquante moyennes — d'où le poids de 0,5 du moyen. Passer la
formule de production à celle-ci est la [décision 0036](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0036-the-posture-score-formula.md),
proposée.

Chacun de `exploited`, `critical`, `high`, `medium`, `low`, `licence` et `k` peut être passé en
paramètre de requête pour essayer d'autres valeurs ; un paramètre absent prend la valeur validée. La
réponse liste pour chaque cible le score et la note actuels et candidats, ses points de risque et ses
compteurs, et combien de cibles lisent chaque note sous chaque formule.

**Les projets et les solutions sont listés aussi** (`scopes`), chacun de ceux que
l'[arbre des solutions](../administration/solutions-and-projects.fr.md) montre à l'administrateur : le score que donne aujourd'hui le
scorecard du projet ou de la solution à côté de la candidate sur le backlog entier de la portée, avec
le même plafond quand une partie de la portée n'a jamais été scannée et le même `NO_DATA` quand aucune
ne l'a été. Une portée cumule les backlogs de ses cibles, et peut donc se lire plus bas que chacune
d'elles. Chaque ligne de portée porte aussi deux nombres de licences : `licences`, celui de la
candidate, chaque entrée interdite comptée une fois ; et `currentLicences`, ce que compte aujourd'hui
la fiche du projet ou de la solution. Ils diffèrent — `currentDoubleCounted` vaut alors `true` — là
où un scan a nommé à la fois une image et un dépôt de la portée : la fiche actuelle compte les
composants et les constats de licence de ce scan une fois pour le dépôt et une fois de plus pour
l'image. La fiche propre de chaque cible les compte une fois, sur le dépôt ; la candidate s'accorde
avec elle, et la bascule de formule corrige la fiche de portée.

## Langages {#languages}

Chaque dépôt montre, sous ses détails, les langages recensés par son **scan terminé le plus récent**,
en petites étiquettes dans le vocabulaire même des manifestes de plugin (`java`, `typescript`…).
**« pas encore connus »** signifie que rien n'a été recensé — aucun scan terminé depuis que le
recensement existe, ou un arbre trop grand pour être compté — et n'est pas **« aucun langage
détecté »**, qui signifie que le recensement a eu lieu et n'en a trouvé aucun. Voir
[plugins](../administration/plugins.md#les-langages-detectes-dans-un-depot) pour ce que les langages
décident.

## Ce qui est lu de l'arbre, et ce qui ne l'est pas

Les scanners tournent dans des conteneurs. Deux lectures ont lieu dans le processus de Vectispire
lui-même — le manifeste du projet (`pom.xml`, `package.json`, `pyproject.toml`…) et la découverte
d'API — et elles **ignorent tout lien symbolique et tout fichier de plus de 2 Mo**. Le contenu d'un
dépôt appartient à son auteur : un lien commité vers `/dev/zero` ou vers un fichier de l'hôte, ou un
fichier source d'un gigaoctet, faisait tomber le processus ou lisait l'hôte. Un point d'accès
déclaré seulement dans un tel fichier n'est pas découvert.

## Supprimer un dépôt

Retirer un dépôt retire ses scans et son historique d'issues avec lui. Là où vous devez garder
la trace, exportez d'abord
[l'historique de détection et de triage](history.md) — ce document est écrit pour être lu
après coup par quelqu'un qui n'était pas là.
