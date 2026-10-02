# Notes de version

## Prochaine version (après 0.10.0)

### Changements visibles d'une intégration

- **Les réponses automatiques d'une checklist arrivent en moins d'une minute après une analyse ou un
  rapport, et non plus aussitôt.** Une analyse terminée, ou un rapport SARIF, de couverture ou de tests
  accepté, les met en file avec ses propres résultats, et le prochain passage du relais du planificateur
  les donne, en réessayant si la réponse échoue. Elles étaient données juste après la validation, et un
  serveur arrêté entre les deux laissait les lignes sans réponse jusqu'à l'analyse suivante. Un script qui
  lit une checklist juste après avoir déposé un rapport doit attendre le relais — ouvrir, passer à une
  autre version ou rouvrir une révision répond toujours aussitôt.
- **Un événement SIEM signalé par une entrée d'audit, et `SECURITY_GATE_FAILED`, sont mis en file avec ce
  qui les cause.** Ils l'étaient juste après, dans une transaction à eux, et un arrêt entre les deux les
  perdait. Si les deux ne peuvent pas être écrits ensemble, l'entrée ou le verdict est quand même écrit et
  l'événement mis en file juste après, comme avant ; le serveur journalise alors un avertissement.
- **L'entrée d'audit `AGENT_RESULT_SUBMITTED` d'un agent est écrite jusqu'à une minute après le
  résultat**, depuis l'outbox, au lieu de juste après — et ne se perd plus si le serveur s'arrête entre
  les deux. Son horodatage est celui de l'écriture ; le moment où le résultat a été accepté est dans sa
  description (« … at 2026-… »), avec l'identifiant de la livraison.
- **L'historique de triage d'une issue reçoit des entrées d'origine `reopen`**, dans
  `GET /api/v1/issues/{id}` (`decisions`) et dans l'historique d'une cible
  (`GET /api/v1/history/repositories/{id}`), avec un nouveau champ, `previousResolvedAt` — `null` sur
  toute autre entrée. Leur `actor` est `null`, comme sur une `expiry`. Le CSV de l'historique reçoit une
  dernière colonne, `decision_previous_resolved_at` ; le compte `decisions` d'une cible n'inclut pas les
  réouvertures.

### Nouveautés

- **Un relevé hebdomadaire de la couverture OWASP Top 10 commence maintenant.** Toutes les six heures au
  plus, le passage de maintenance enregistre, pour chaque dépôt et chaque image — analysés ou non — et pour
  chacune des dix catégories, l'état qu'affiche la grille OWASP (constats, non mesuré, non couvert, rien
  trouvé), les constats ouverts qu'elle compte, et à part les constats ouverts dont le triage est réglé,
  pour que les risques acceptés puissent être montrés comme tels — pour une cible jamais analysée, ses
  constats tels que la grille les compte dès qu'une cible à côté d'elle est analysée, pour que la semaine
  d'un projet ou d'un parc lise ce que lit la grille en direct. La semaine en cours (lundi 00:00 UTC) est
  réécrite jusqu'à sa clôture ; une semaine close garde son dernier relevé. **Les semaines antérieures à la
  mise à jour n'ont pas d'état enregistré** — qu'une catégorie ait alors été couverte ou mesurée dépendait
  de réglages et de règles qui ont changé depuis, et la vue hebdomadaire ci-dessous dit « non enregistré »
  pour elles plutôt que de le deviner. Les lignes d'une cible supprimée partent avec elle (migration V67).
- **Le Top 10 OWASP, semaine par semaine : `GET /api/v1/owasp/coverage/weekly`.** Jusqu'à 52 semaines
  ISO (les 12 dernières par défaut), sur le parc de l'appelant ou sur un projet ou une solution, pour les
  cibles qu'il peut voir (un périmètre dont il ne voit rien répond 404, comme un périmètre absent). Chaque
  semaine donne, par catégorie, l'état, les constats ouverts et réglés tels que le relevé hebdomadaire les
  a capturés, et les issues ouvertes et résolues dans la semaine. **Une semaine antérieure au relevé est
  reconstituée à partir des dates des issues** et le dit : son état et son chiffre de constats réglés valent
  `null` plutôt que d'être devinés, et son chiffre d'ouverts compte toute issue ouverte à la fin de la
  semaine, quel que soit son triage — le triage d'une date passée n'est pas connu. La résolution
  antérieure d'une issue rouverte compte — pas ouverte de cette résolution à la réouverture, et une
  résolution de sa semaine — d'après les entrées de réouverture de l'historique de triage ; une
  réouverture antérieure à cette version n'en a laissé aucune, et une telle issue compte encore comme
  ouverte entre cette résolution antérieure et sa réouverture.
- **De nouveaux filtres du backlog pour les chiffres de cette vue** : `owasp_category` (`A01`…`A10`,
  rangée comme la grille range les issues — une vulnérabilité est `A06`), `open_at` (ouverte à la fin de
  ce jour, UTC) et `first_seen_from` / `first_seen_to` / `resolved_from` / `resolved_to` — `open_at` et
  l'intervalle de résolution lisent de même les résolutions antérieures d'une issue rouverte. **Avec une date
  et sans `state`, `GET /api/v1/issues` liste tous les états**, puisque les issues ouvertes un jour passé
  sont pour la plupart résolues depuis ; le défaut reste `open` sinon.

### Corrigé

- **Une issue rouverte ne laissait aucune trace dans son historique de triage.** Quand une analyse ou un
  import retrouvait une issue résolue, il la rouvrait et effaçait une décision `fixed` sans aucune
  entrée : l'historique montrait `fixed` comme dernier mot d'une issue de nouveau ouverte et en revue, et
  la résolution qu'elle avait eue — de quand à quand — était perdue. La réouverture est désormais une
  entrée à part entière : le triage qu'elle quitte (ou qu'elle garde, pour un jugement qui survit au
  retour), le jour où la résolution qu'elle clôt avait commencé, et l'analyse qui a retrouvé l'issue ;
  personne n'est nommé, puisque personne n'a décidé (migration V68). Une réouverture antérieure à la mise
  à jour reste sans entrée.
- **Des écritures d'audit simultanées pouvaient casser la chaîne d'audit, et déclencher une fausse
  alerte de falsification.** Deux entrées écrites au même instant — deux requêtes sur un serveur, ou deux
  serveurs — pouvaient se chaîner toutes deux sur le même prédécesseur ; la vérification déclarait alors
  la chaîne rompue, et le SIEM recevait `AUDIT_CHAIN_BROKEN`, sans que rien ait été modifié. Les entrées
  sont désormais écrites une à une, entre serveurs aussi (migration V66). Une installation qui a vu une
  rupture inexpliquée doit relancer la vérification après la mise à jour : les entrées écrites ensuite se
  chaînent correctement ; une rupture déjà enregistrée reste où elle est, puisque réécrire un journal
  d'intégrité est précisément ce qu'il doit révéler.
- **Le premier coffre de preuves d'une installation sans `vectispire.signing.key` répondait 500.** La clé
  de signature créée à la première utilisation rejoignait la transaction en lecture seule du coffre, dans
  laquelle MySQL et PostgreSQL refusent d'écrire. Elle est désormais créée hors de celle-ci.

## 0.10.0 — 1er octobre 2026

Lisez d'abord **Avant la mise à jour** : cinq de ses points arrêtent
quelque chose tant qu'un opérateur n'a pas agi, et c'est voulu.

### Avant la mise à jour

**Les identifiants de signature SIEM passent de `ZAN-SEC-nnn` à `VECTI-SEC-nnn`, d'un coup.** Le numéro
et le sens de chaque événement restent les mêmes ; seul le préfixe change, et plus aucun événement ne
porte l'ancien — pas même ceux encore en file au moment de la mise à jour, puisque l'identifiant est
écrit au départ de l'événement. **Une règle de corrélation, une alerte ou un tableau de bord qui filtre
sur `ZAN-SEC-` cesse de correspondre, sans aucune erreur.** Avant la mise à jour, passez chacun au
nouveau préfixe, ou faites-lui accepter les deux le temps du déploiement. Le `signatureId` CEF, le
`MSGID` syslog et le JSON du webhook le portent tous. Voir [SIEM](../integrations/siem.md#catalogue-des-evenements).

| Avant | À partir de cette version | Événement |
|---|---|---|
| `ZAN-SEC-002` | `VECTI-SEC-002` | Actively exploited vulnerability (KEV) detected |
| `ZAN-SEC-003` | `VECTI-SEC-003` | Security gate refused a build |
| `ZAN-SEC-005` | `VECTI-SEC-005` | Finding settled by triage |
| `ZAN-SEC-006` | `VECTI-SEC-006` | MFA backup code consumed |
| `ZAN-SEC-007` | `VECTI-SEC-007` | Sign-in failure ceiling reached |
| `ZAN-SEC-008` | `VECTI-SEC-008` | MFA failure ceiling reached |
| `ZAN-SEC-009` | `VECTI-SEC-009` | Bearer token failure ceiling reached |
| `ZAN-SEC-010` | `VECTI-SEC-010` | Account privileges or credentials changed |
| `ZAN-SEC-011` | `VECTI-SEC-011` | Team access grant changed |
| `ZAN-SEC-012` | `VECTI-SEC-012` | API key issued |
| `ZAN-SEC-013` | `VECTI-SEC-013` | API key revoked |
| `ZAN-SEC-014` | `VECTI-SEC-014` | Agent declared or its credentials changed |
| `ZAN-SEC-015` | `VECTI-SEC-015` | Agent result refused: attestation did not verify |
| `ZAN-SEC-016` | `VECTI-SEC-016` | Four-eyes triage request approved |
| `ZAN-SEC-017` | `VECTI-SEC-017` | Four-eyes triage request refused |
| `ZAN-SEC-018` | `VECTI-SEC-018` | Audit log integrity verification failed |
| `ZAN-SEC-019` | `VECTI-SEC-019` | Security-relevant setting changed |
| `ZAN-SEC-020` | `VECTI-SEC-020` | Agent sealing key refused: signature or generation did not verify |
| `ZAN-SEC-021` | `VECTI-SEC-021` | Analysis plugin registered, changed or activated |
| `ZAN-SEC-022` | `VECTI-SEC-022` | SARIF import source declared or changed |
| `ZAN-SEC-023` | `VECTI-SEC-023` | SARIF import refused: undeclared source, scope or tool |
| `ZAN-SEC-024` | `VECTI-SEC-024` | Checklist template version published or retired |
| `ZAN-SEC-027` | `VECTI-SEC-027` | Report import refused: undeclared source, kind or scope |
| `ZAN-SEC-999` | `VECTI-SEC-999` | SIEM connector health check |

**Les scans délégués s'arrêtent tant que chaque agent délégué n'est pas mis à jour et n'a pas de
clé de signature épinglée.** Un agent en mode d'identifiants `delegated` reçoit la clé SSH ou le
jeton HTTPS d'un dépôt scellé pour sa clé de scellement. Cette clé n'est désormais acceptée que si
l'agent la signe avec la clé Ed25519 qu'un administrateur a épinglée
([décision 0031](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0031-a-sealing-key-is-believed-only-on-the-pinned-key.md)),
et aucun identifiant n'est plus jamais envoyé en clair, TLS ou pas. Tant qu'un agent n'est pas mis
à jour **et** que sa clé de signature n'est pas épinglée, il ne réclame aucun scan qui a besoin
d'un identifiant : ces scans attendent, en file et sans consommer de tentative, un exécuteur qui
peut les prendre. Les agents en mode `local`, les scans d'images et les dépôts sans identifiant ne
sont pas concernés. Avant la mise à jour : épinglez la clé de signature de chaque agent délégué
sur l'écran **Agents**, puis mettez les agents à jour. Voir [Agents](../administration/agents.md).

**Les tentatives comptées par les réclamations retenues sont rendues une fois, au premier
démarrage.** Avant cette version, chaque interrogation d'un tel agent prenait un scan qui avait
besoin d'un identifiant — une tentative — et le remettait en file : un scan que rien n'avait essayé
pouvait échouer en « bail épuisé » à sa première vraie reprise. Sur une base qui déclare un agent
`delegated`, les scans en attente de dépôts portant un identifiant qu'aucun agent n'a jamais reçu
(pas d'`AGENT_CREDENTIAL_SENT`) voient leurs tentatives remises à 0, consigné une fois — par une seule instance, quand plusieurs démarrent ensemble — sous
`SCAN_ATTEMPTS_REPAIRED`. Ne sont pas touchés : un scan livré au moins une fois, en cours, terminé ou
déjà en échec — relancez à la main un scan en échec —, les scans d'images et les dépôts sans
identifiant.

**Les secrets arrivent dans les conteneurs sous forme de fichiers, plus de variables
d'environnement.** Le `docker-compose.yml` livré remet désormais `ENCRYPTION_KEY`, les mots de
passe de la base, le mot de passe d'amorçage, `VECTISPIRE_SIGNING_KEY` et le secret du client OIDC
comme secrets Compose sous `/run/secrets/` : l'environnement d'un conteneur est lisible par tout ce
qui peut l'inspecter à travers le démon Docker. Si vous utilisez votre propre composition ou vos
propres manifestes, passez-les en fichiers de la même façon (`ENCRYPTION_KEY_FILE`,
`spring.config.import: optional:configtree:/run/secrets/`). Votre `.env` doit déclarer
`VECTISPIRE_SIGNING_KEY` et `VECTISPIRE_OIDC_CLIENT_SECRET`, vides s'ils ne servent pas : Compose
s'arrête en nommant la variable plutôt que de perdre une clé de signature qu'une installation
utilisait, parce qu'une clé remplacée rend invérifiable tout document déjà signé.

**La base n'est plus publiée sur l'hôte.** La publication du port `127.0.0.1:3306` a disparu et la
base est sur un réseau interne. Un outil qui s'y connectait depuis l'hôte passe par
`docker compose exec` ou par un réseau à lui.

**Tout corps de requête a un plafond.** 1 Mo par défaut (`VECTISPIRE_MAX_BODY_DEFAULT`) ; les
routes qui ont le leur le gardent : VEX 16 Mo, imports SARIF 32 Mo, envoi de jeux de règles
64 Mo, résultats d'agent 256 Mo. Un client qui envoie un corps plus gros à une route ordinaire
reçoit désormais un 413.

**Le flux KEV est le catalogue de la CISA, lu sur le réseau.** C'était une liste de dix
enregistrements écrits dans le code ; le plan de contrôle lit désormais
`known_exploited_vulnerabilities.json` toutes les six heures et depuis l'onglet **Threat
Intelligence** des paramètres, et un scan interroge la copie stockée au lieu de la télécharger. Le
plan de contrôle doit joindre `www.cisa.gov` — ou `VECTISPIRE_KEV_URL` doit désigner un miroir (et
`VECTISPIRE_KEV_ALLOW_PRIVATE=true` s'il est sur un réseau privé), voir
[Configuration](configuration.md#threat-intelligence). La mise à jour vide l'ancien flux : jusqu'à la
première synchronisation, le statut indique *jamais synchronisé* et un scan ne marque rien comme
activement exploité. Cette première synchronisation **retire** aussi le marquage des constats
ouverts dont la CVE ne figure pas au catalogue, y compris ceux que la liste écrite en dur avait
marqués.

**Les analyses demandent un répertoire de l'hôte monté au même chemin — la composition livrée en
crée un désormais.** Les analyseurs sont des conteneurs que lance le démon Docker, et il résout ce
qu'il y monte sur son propre hôte ; la composition gardait les espaces de travail dans le `/tmp` du
plan de contrôle, si bien que chaque analyseur recevait un répertoire vide et **qu'aucune analyse du
`docker-compose.yml` livré n'a jamais abouti**. Elle monte maintenant `VECTISPIRE_WORK_DIR` (par
défaut `/var/lib/vectispire/work`, quelque 3 Go pour la base de vulnérabilités) au même chemin et le
prépare par un service ponctuel `work-dir` ; `docker compose up` s'en charge, il suffit d'avoir le
disque. Si vous utilisez **votre propre composition ou vos propres manifestes**, montez un
répertoire de l'hôte au même chemin absolu et réglez `JDK_JAVA_OPTIONS=-Djava.io.tmpdir=<chemin>` —
voir [Installation](../getting-started/installation.md) et
[Configuration](configuration.md#espaces-de-travail-des-analyses). Les analyseurs tournent
désormais sous le propriétaire de l'espace de travail et non plus sous root, qui ne pouvait pas le
lire.

**Les images construites depuis le `Dockerfile` tournent en 1000:1000**, comme les images publiées.
Si vous avez construit la vôtre et que son volume du miroir d'audit existe déjà, remettez-le une
fois : `docker run --rm -v vectispire_audit:/a alpine chown -R 1000:1000 /a`.

**Les clones SSH avec clé de déploiement fonctionnent à travers la composition — et elle ne monte
plus votre `~/.ssh`.** À travers le `docker-compose.yml` livré, aucun de ces clones n'avait jamais
réussi : les images n'ont pas de compte pour leur utilisateur, le home était `/`, et le fichier
known-hosts ne pouvait pas être créé (*« The known-hosts file could not be prepared: /.ssh »*,
affiché *« The clone of … failed. »*). Derrière cela, la vérification de clé d'hôte refusait tout
hôte jamais rencontré (*« Server key did not validate »*) — hors de la composition aussi, sauf si
l'hôte figurait déjà dans le `~/.ssh/known_hosts` de l'utilisateur qui fait tourner le processus.
Désormais un premier contact est inscrit et une clé changée refusée, le home du processus est
`$VECTISPIRE_WORK_DIR/home` (celui de l'agent sous `$VECTISPIRE_AGENT_WORK_DIR`), et le montage de
`${HOME}/.ssh` a disparu, `VECTISPIRE_HOST_SSH` valant désormais `false` dans la composition. Ce
qu'il faut faire :

- Rien, si vos dépôts privés portent une clé de déploiement : `docker compose up` crée le home.
- Si vous comptiez sur le montage — seules les images construites depuis le `Dockerfile` l'ont
  jamais lu — attachez une clé de déploiement à chacun de ces dépôts dans l'écran **Clés SSH**. Un
  agent `local` du profil `with-agent` clone avec `$VECTISPIRE_AGENT_WORK_DIR/home/.ssh`, vide sauf
  si vous y placez une clé dédiée.
- **Votre propre composition ou vos manifestes :** ajoutez `-Duser.home=<répertoire de travail>/home`
  à `JDK_JAVA_OPTIONS`. Sans cela, les images se rabattent désormais sur `HOME=/home/vectispire`,
  qu'un simple `docker run` peut écrire mais qui disparaît avec le conteneur — les hôtes qui y
  sont inscrits sont rencontrés à nouveau comme nouveaux.
- **Hors conteneur,** un clone avec clé ne lit plus le `~/.ssh/config` de l'utilisateur : un alias
  `Host`, un `Port` ou un `ProxyJump` qui s'y trouve cesse de s'y appliquer. Mettez l'hôte et le
  port réels dans l'URL du dépôt. Les hôtes déjà présents dans `~/.ssh/known_hosts` restent
  vérifiés contre lui.

Voir [En SSH : la clé d'hôte de la forge](../guide/repositories.md#ssh-host-keys) pour épingler les
clés à l'avance.

**Les scores EPSS viennent du fichier quotidien du FIRST, et les scans n'appellent plus
`api.first.org`.** Chaque scan envoyait les CVE trouvées à l'API du FIRST — ce qui apprenait à un
tiers à quoi chaque dépôt était vulnérable — et, sur un parc sans accès sortant, tous les scores
restaient inconnus. Le plan de contrôle télécharge désormais `epss_scores-current.csv.gz` une fois
par jour et depuis l'onglet **Threat Intelligence**, le stocke (quelque 380 000 lignes, quelques
secondes sur MySQL et PostgreSQL), en rafraîchit les scores des constats ouverts, et les scans lisent
la copie stockée. Il doit joindre `epss.empiricalsecurity.com` — ou `VECTISPIRE_EPSS_URL` doit
désigner un miroir (et `VECTISPIRE_EPSS_ALLOW_PRIVATE=true` sur un réseau privé), voir
[Configuration](configuration.md#threat-intelligence) ; une liste d'autorisation qui ouvrait
`api.first.org` aux scans peut le refermer. Jusqu'à la première synchronisation, que la première
tâche de maintenance lance une demi-minute après le démarrage, un nouveau constat n'a pas de score
EPSS — inconnu, et non zéro — et les scores déjà portés par les constats restent jusqu'à ce que le
fichier les remplace.

**Un échec permanent n'est plus retenté ; un échec transitoire attend 1, puis 5, puis 15 minutes.**
Une analyse qui n'a pas pu s'exécuter — sur un agent ou sur le worker intégré — échoue aussitôt, dès sa
première tentative et avec la raison, quand une autre tentative rencontrerait le même refus : une clé
d'hôte qui a changé, une authentification refusée, un dépôt, une branche ou un sous-chemin qui
n'existe pas, un identifiant qui ne s'ouvre pas, une URL que le clonage refuse. Tout le reste — le
réseau, un délai dépassé, un démon qui ne répond pas, un bail expiré — revient dans la file avec la
tentative comptée et ne peut être réclamé de nouveau qu'une minute après la première tentative, cinq
après la deuxième, quinze après toute tentative suivante (`VECTISPIRE_SCAN_RETRY_DELAYS`, voir
[Configuration](configuration.md#scan-queue)), puis échoue à la troisième. Auparavant, un agent seul
reprenait à son interrogation suivante l'analyse qu'il venait de signaler et consommait les trois
tentatives en quelques secondes ; le worker intégré faisait échouer une analyse pour de bon à sa
première erreur, avec le message brut. Un sous-chemin absent du clone fait désormais échouer l'analyse
avant tout analyseur, là où chacun le signalait.

**Signer une checklist demande la clé de signature.** La signature d'une checklist rend et signe
désormais son document dans la même transaction. Une installation sans `ENCRYPTION_KEY` ni
`vectispire.signing.key` configurée y répond 412, comme tout autre export signé — et une signature qui ne
peut pas être signée n'est pas enregistrée. Voir [Checklists de sécurité](../guide/security-checklists.fr.md).

**Une ligne de checklist sur l'analyse statique lit « pas de données » jusqu'à la prochaine analyse de
chaque dépôt.** Une ligne sur `builtin:sast`, `builtin:quality` ou un plugin ne compte désormais un
dépôt comme examiné que là où l'analyse a lu les langages de l'arbre, jugé sur ce que l'analyse a
enregistré : son recensement et, depuis V58, les langages des règles SAST que portait sa tâche. Aucune
analyse antérieure n'a enregistré ces derniers : chacune de ces lignes mesure `languages_unrecorded`
jusqu'à la prochaine analyse de chaque dépôt, et un *oui* automatique que Vectispire y avait donné est
retiré à la mesure suivante. Ensuite, sur une installation qui n'a que les règles embarquées — un motif
Python —, un dépôt Java ou JavaScript mesure `language_not_analysed` : installez un jeu de règles
couvrant ses langages (Jeux de règles, *importer depuis le catalogue*) et relancez l'analyse. Une ligne
qui passait avant parce que ses règles ne trouvaient rien dans du code qu'elles ne savaient pas lire ne
mesurait rien. Voir [Checklists de sécurité](../guide/security-checklists.md#lignes-mesurees).

**Développement sécurisé, IaC et secrets lisent désormais la couverture, comme les vulnérabilités —
les scores baissent sur un parc analysé en partie.** ISO 27001 A.8.28, A.8.9 et A.5.15, et les contrôles
de mêmes catégories de NIS 2, DORA, PCI DSS et SOC 2, étaient notés sur le seul zéro de constats : dix
cibles dont une analysée sans constat les lisaient *conformes*, à côté d'un A.8.8 *non conforme* sur le
même parc. Ils portent maintenant le plafond de couverture d'A.8.8 — une cible jamais analysée rend le
contrôle non conforme, une cible analysée hors de la fenêtre de fraîcheur le limite à partiel, le score
vaut au plus la part des cibles observées, et le détail le dit. **Un parc entièrement analysé dans la
fenêtre se lit comme avant.** Sur un parc analysé en partie, ces contrôles et le score de leurs
référentiels baissent dès le premier affichage après la mise à jour, et une déclaration qui dit un tel
contrôle en place se lit *contredite* dans la déclaration d'applicabilité. La progression de conformité
réécrit le point du mois en cours à sa prochaine capture et montre la baisse comme *même parc, mêmes
règles, N points de moins* : rien n'a changé dans le parc — l'ancien score comptait comme propres des
cibles que personne n'avait regardées, et les mois déjà capturés gardent ce score. Analysez le reste du
parc, ou prévenez ceux qui lisent la courbe avant qu'ils ne la lisent. Voir
[Conformité](../guide/compliance.md#sans-donnee-nest-pas-conforme).

**Une cible jamais analysée n'a plus de note de sécurité, et un portefeuille, un projet ou une
solution analysés en partie voient leur score plafonné — des notes baissent, et des pastilles publiées
peuvent afficher *no data*.** La fiche de score retranche de cent ce qu'elle trouve : un dépôt
enregistré et jamais analysé lisait 100, A+, sur sa fiche et sur la pastille de son README, et un
projet dont la seule cible n'avait jamais été analysée lisait de même. Une telle fiche porte maintenant
la note `NO_DATA`, sans score, et la pastille affiche *no data* en gris. Là où une partie seulement des
cibles est analysée — la fiche globale, celle d'un projet, d'une solution — le score est plafonné à la
part analysée : dix cibles dont une analysée propre valent 10, F, là où elles lisaient A+. Un dépôt ou
une image qui a un scan terminé garde sa note. Rien n'est enregistré, le changement se voit donc à la
première lecture ; analysez les cibles que nomme la nouvelle recommandation. Voir
[Comment la note du scorecard est calculée](../guide/repositories.md#comment-la-note-du-scorecard-est-calculee).

**Un plugin dont l'image n'est pas signée ne tourne plus, sauf dérogation du gouverneur de la
plateforme.** `VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED` vaut désormais `true` par défaut, sur le worker
intégré du plan de contrôle et sur chaque agent. Les plugins n'existaient pas en 0.9.0, aucune
installation publiée ne perd donc rien ; une **version de développement** qui a enregistré un plugin
sans `signature` dans son manifeste le voit **refusé** dès le premier scan après la mise à jour — la
carte **Plugins** du scan dit *refusé — non signé*, le scan liste l'échec sous `plugin <id>`, ses issues
restent telles quelles, et une ligne de checklist qui le mesure est *sans données* (`plugin_unsigned`).
Avant la mise à jour, déclarez le signataire de l'image de chacun de ces plugins, ou — tant qu'elle ne
peut pas être signée — faites enregistrer par le gouverneur une dérogation avec sa justification sur la
page du plugin (`PUT /api/v1/plugins/{id}/unsigned-waiver`). Positionner la variable à `false` lance
encore tout plugin non signé sur cet exécuteur, sans trace de pourquoi ; la dérogation est la voie
documentée. Pourquoi le défaut change : un registre, un miroir ou un tag compromis en amont fait tourner
du code sur le source de chaque projet pour lequel le plugin est activé, et l'absence de réseau ne
l'empêche pas d'inventer ou de taire des constats. Voir
[Plugins](../administration/plugins.md#faire-tourner-un-plugin-non-signe) et la
[décision 0017](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0017-custom-checks-as-container-images.md).

**Les migrations V32 à V64 s'exécutent au démarrage**, sur MySQL et PostgreSQL. Sauvegardez la
base avant, comme pour toute mise à jour — [sauvegarde et restauration](https://github.com/asmolabs/vectispire/blob/main/docs/fr/BACKUP_AND_RESTORE.fr.md).

### Changements visibles d'une intégration

- **Trois nouveaux événements SIEM, et l'export dit quand il s'arrête.** `VECTI-SEC-028` est envoyé
  au collecteur quitté quand l'export est coupé ou dirigé ailleurs — le silence était jusqu'ici le
  seul signal. `VECTI-SEC-029` annonce un nouveau secret de sévérité élevée ou critique, une fois par
  constat ; `VECTI-SEC-030` un constat qui dépasse son délai de remédiation, une fois par constat,
  depuis le tour horaire (transmis à partir d'une sévérité minimale Moyenne). Une règle de corrélation
  écrite pour les `001` et `004` retirés ne les capte pas : ils ont pris de nouveaux numéros. `GET` et
  `PUT /api/v1/siem/config` portent `tlsCaPem`, `tlsCaSubject` et `tlsCaNotAfter`, et `POST
  /api/v1/siem/test` accepte `tlsCaPem` — [Export SIEM](../integrations/siem.md#catalogue-des-evenements).
- **Le modèle de barrière GitLab fait désormais échouer le pipeline sur un verdict rouge.**
  `ci/gitlab/vectispire-gate.gitlab-ci.yml` livrait `allow_failure: true`, si bien qu'une barrière
  échouée s'affichait en avertissement et que le pipeline passait ; il n'accepte plus que la sortie
  `3`, que `VECTISPIRE_GATE_MODE: advisory` produit pour un verdict rouge. Un pipeline qui comptait
  sur l'ancien comportement pose cette variable. Le modèle demande aussi `VECTISPIRE_GATE_VERSION`,
  le tag auquel il a été inclus : il télécharge le `vectispire-gate.sh` de cette version et ne le
  lance qu'au SHA-256 qu'il épingle — il lançait `ci/vectispire-gate.sh` depuis le checkout du
  consommateur, où ce fichier n'existe pas. Il ne déclare plus `VECTISPIRE_REPOSITORY_ID` ni
  `VECTISPIRE_CONTAINER_ID` sur son job, si bien qu'une valeur posée globalement atteint la barrière.
  Voir [Exemples CI](../integrations/ci-examples.md#gitlab-ci).
- **La version porte `vectispire-gate.sh` et son bundle Sigstore**, signés par la même identité de
  workflow que le jar.
- **`vectispire-cli` sort en `2` avec le `detail` du serveur sur un refus**, là où il sortait avec le
  `22` de curl sans rien afficher. La sortie `1` n'est plus qu'un verdict rouge ; un scan échoué ou
  hors délai donne `2`. `scan` suit le scan déjà en attente sur un `409` ; `sbom --repo-id` prend le
  dernier scan *terminé*, là où il prenait le dernier, qui pouvait être en attente ; `status`,
  annoncé et absent, existe.
- **Une fiche de score peut porter la note `NO_DATA`, avec un score `null`, et porte `totalTargets` et
  `observedTargets`.** `GET /api/v1/scorecards/repositories/{id}`, `/containers/{id}`, `/global` et le
  `scorecard` de `GET /api/v1/projects/{id}/compliance` et `/solutions/{id}/compliance` répondent la note
  `NO_DATA` et `score: null` quand aucune des cibles de la fiche n'a de scan terminé — ils répondaient
  100 et `A_PLUS`. `score` n'est plus toujours présent comme nombre : un client qui le lit comme tel doit
  tester `grade` d'abord. `observedTargets` inférieur à `totalTargets` signifie que le score est
  plafonné à cette part. `SecurityGrade` gagne `NO_DATA` ; un client qui associe les notes qu'il connaît
  doit traiter une note inconnue comme une absence de note.
- **Le classement de maturité du tableau de bord peut porter la note `NO_DATA`, avec un
  `securityScore` `null`.** Dans `targetScoreboard` de `GET /api/v1/dashboard/posture-analytics`, une
  cible sans scan terminé — ses constats viennent d'un seul import SARIF — est classée en dernier comme
  `NO_DATA` ; elle pouvait lire 100, A, en tête du classement. Ses comptes restent. Une cible jamais
  analysée ne porte aucune issue et n'est pas listée, comme avant.
- **Le classement de maturité du tableau de bord note chaque cible comme son scorecard : ses scores et
  ses notes changent.** Dans `targetScoreboard` de `GET /api/v1/dashboard/posture-analytics`,
  `securityScore` et `maturityGrade` sont désormais le `score` et la `grade` du scorecard de la cible —
  ceux que répondent `GET /api/v1/scorecards/repositories/{id}` et `/containers/{id}` et la pastille. Le
  classement avait sa propre règle (100 moins 25, 10, 3 et 1 par critique, haute, moyenne et autre
  ouverte ; A dès 90, B dès 75, C dès 50, D dès 30), qui lisait 0, F pour dix hautes ouvertes comme pour
  cinq cents. Les mêmes lignes lisent d'autres nombres : dix hautes sur une cible scannée lisent 65, C,
  là où elles lisaient 0, F. `maturityGrade` prend les valeurs du scorecard, `A_PLUS`, `A`, `B`, `C`,
  `D`, `F`, `NO_DATA`, avec ses seuils (A+ dès 95, A dès 85, B dès 70, C dès 55, D dès 40) ; `A_PLUS`
  est nouveau dans ce champ, et le document le type comme cette énumération. Une cible scannée sans
  constat est désormais listée, à 100, `A_PLUS` ; elle était omise, faute de problème. Les lignes gardent
  leur forme ; `openCritical` et `openHigh` sont les comptes de la fiche, `openMedium` et `openLow` sont
  affichés et non notés, et `totalResolved` et `targetMttrDays` sont inchangés.
- **Une ligne `component_versions` lit `no_data` (`version_unrecorded`) quand le SBOM n'indique
  aucune version d'un paquet déclaré.** Syft écrit `UNKNOWN` pour une dépendance Maven dont la version
  est gérée par un parent ou un BOM qu'il ne résout pas ; c'était jugé « pas une version admise », la
  ligne lisait `fail`, et la réponse automatique de Vectispire écrivait *non* pour un module présent.
  Désormais un paquet dont aucune occurrence n'indique de version met son dépôt en *pas de données*,
  le paquet nommé dans la preuve, et un *non* automatique qui en dépendait est retiré. Quand certaines
  occurrences indiquent une version, ce sont elles qui jugent, les autres nommées à côté ; une version
  indiquée non admise et un paquet absent du SBOM échouent toujours. `NoDataReason` gagne
  `version_unrecorded` : un client qui traduit les raisons qu'il connaît doit lire une raison inconnue
  comme une absence de données.
- **`GET /api/v1/solutions` accepte une clé d'API `read`**, comme les listes de dépôts et d'images
  qu'il regroupe le faisaient déjà — il répondait 403. Une clé restreinte à un dépôt ou à une image lit
  les projets qui le contiennent, partiels, et aucun projet par les attributions de son compte.
- **Les chiffres et les filtres d'un projet incluent les images de conteneur qui y sont rangées.** Dès
  qu'une image est rangée dans un projet, `GET /api/v1/issues?project_id=…` et `?solution_id=…`
  répondent ses issues à côté de celles des dépôts, et les `openIssues` de `GET /api/v1/solutions` les
  comptent ; chaque nœud de projet, de solution et le groupe `unfiled` gagnent `containerCount` (et les
  projets et `unfiled` une liste `containers`), `repositoryCount` restant un compte de dépôts. Rien ne
  change tant qu'aucun administrateur n'a rangé d'image : toutes les images existantes démarrent sans
  projet.

- **Un changement de jeu de règles qui résoudrait des issues ouvertes répond 409 tant que leur nombre
  n'est pas accepté.** `POST /api/v1/rule-sets/{id}/activate` et `POST /api/v1/rule-sets/deactivate`
  refusent, avec le type `urn:vectispire:problem:rule-set-activation-loses-issues` et les membres
  `affectedIssues` et `losingIssues`, un changement dont les règles laissent derrière elles des issues
  ouvertes que la prochaine analyse résoudrait avec leur triage — sauf si le corps porte `acceptLosing`
  égal à `affectedIssues`, relu à la requête ; un nombre périmé, inférieur ou supérieur est refusé avec
  le nombre courant. Un changement qui ne résout rien n'a besoin d'aucun champ.
  `GET /api/v1/rule-sets/deactivate/impact` prévisualise une désactivation comme `/{id}/impact` une
  activation, et aucun des deux ne compte plus les issues des règles fournies, qui ne se résolvent
  jamais. Les jeux de règles n'existaient pas en 0.9.0 : aucune intégration construite sur cette
  version n'appelle ces routes ; une intégration écrite depuis contre une version de développement le
  fait, et doit désormais envoyer le nombre — [Jeux de règles](../administration/rule-sets.md).
- **Deux nouvelles raisons pour une mesure sans données**, `language_not_analysed` et
  `languages_unrecorded`, dans le `reason` d'une mesure et le `status` d'un dépôt dans ses preuves — un
  script qui compare les raisons qu'il connaît doit lire une raison inconnue comme une absence de
  données, ce qu'elle est.

- **Un nom déjà pris est un 409 typé, quel que soit le geste.** Créer une solution, ou en renommer
  une, avec le nom d'une autre (casse ignorée) répondait `400` ; cela répond `409` de type
  `urn:vectispire:problem:solution-name-taken`. Créer un projet, ou le renommer dans sa solution, avec
  un nom que la solution contient déjà répondait `400` ; cela répond `409` de type
  `urn:vectispire:problem:project-name-taken`, comme le faisait déjà un déplacement vers une telle
  solution. Le `detail` ne change pas. Décidez sur le `type`, pas sur le statut — un `400` de ces routes
  ne signale plus qu'un nom mal formé (vide, trop long) —
  [Solutions et projets](../administration/solutions-and-projects.md).
- **Un verdict de conformité peut être `NO_DATA`.** Tant qu'aucune cible n'a été analysée avec succès,
  chaque contrôle qui lit le parc — et chaque référentiel — vaut `NO_DATA` avec un score de zéro, qui
  n'est pas une mesure, sur `GET /api/v1/compliance/summary`, le détail d'un référentiel, le
  `01_compliance_frameworks.json` du bundle de preuves et le `measured` de la déclaration
  d'applicabilité ; une cible jamais analysée vaut `NO_DATA` dans la matrice, sans `frameworkScores`.
  Il valait *conforme* sur zéro constat que personne n'avait cherché, et l'A.8.8 de l'ISO 27001 *non
  conforme* sur « 1 target(s) have never been scanned » sans aucune cible enregistrée. Le `divergence`
  de la déclaration gagne `UNEVIDENCED`, entre `OVERSTATED` et `UNDERSTATED`, pour une ligne prouvée ici
  sans rien de mesuré — elle valait `CONSISTENT`. Aucune capture mensuelle n'est écrite pour un
  référentiel sans rien de mesuré.
- **Une réponse de checklist nomme la nature de son auteur.** Chaque réponse d'une vue de checklist,
  de l'historique d'une ligne et de `checklist.json` porte `answeredByKind` — `person`, ou `system` pour
  une réponse donnée par Vectispire à partir de la mesure de la ligne — et `withdrawn`, vrai seulement
  sur la ligne d'historique par laquelle Vectispire a retiré sa propre réponse. Reconnaissez une réponse
  automatique à `answeredByKind`, jamais à `answeredBy` : il vaut `Vectispire`, un nom qu'un compte peut
  aussi porter. `checklist.json` passe pour cela à la déclaration de `form` 2.
- **Chaque erreur est un problème RFC 9457** (`application/problem+json`) avec un `detail` fait
  pour être affiché — voir [Erreurs de l'API](errors.md). Les refus qui ne portaient aucune phrase
  en portent une : une route inconnue, 405, 406, 415, un corps illisible, les refus de connexion,
  le 401 d'un identifiant absent ou invalide (qui n'avait pas de corps) et le 403 d'un rôle (qui
  portait le `{timestamp, status, error, path}` du conteneur). Les trois limiteurs de débit
  répondaient `{"message": …}` : la phrase est désormais `detail`, et un nouveau
  `retryAfterSeconds` répète l'en-tête `Retry-After`. Un client qui lit `message` doit lire
  `detail`. Une URL refusée avant l'application — par le pare-feu de sécurité (`//`, un `..`
  encodé) ou par le conteneur de servlets (un `%` isolé), qui répondait sa propre page HTML — est
  elle aussi un problème 400.
- **Un 500 ne cite plus la défaillance.** Une erreur pour laquelle personne n'a écrit de message —
  y compris celles qui répondaient 400 ou 404 avec les mots d'une bibliothèque (« For input
  string », « No value present », « No enum constant … ») — est un 500 dont le `detail` donne un
  `correlationId`, journalisé avec l'erreur. Les refus que Vectispire écrit gardent leur statut et
  leur phrase.
- Accorder un dépôt ou une image qui n'existe pas, ou que l'administrateur qui accorde ne voit
  pas, est refusé par un **404** ; un droit qui nomme un projet absent était un 400 et devient un
  404.
- Une **clé API restreinte à une cible** n'agit que sur cette cible ; une restriction qu'aucune
  route n'appliquerait est refusée à l'émission. Une clé restreinte à une cible supprimée est
  révoquée avec elle, et chaque révocation est auditée sous l'identifiant de la clé.
- Les clés d'intégration agissent pour le compte auquel elles appartiennent ; la clé d'un agent
  est cantonnée aux routes d'agent (403 ailleurs).
- La synchronisation threat-intel est auditée sous `THREAT_INTEL_SYNCED`, plus sous
  `SETTING_UPDATED` ; un changement de périmètre certifié l'est sous `CERTIFIED_SCOPE_CHANGED`. Un
  filtre sur l'ancienne opération ne trouve plus les synchronisations.
- Enregistrer un verdict de barrière est une écriture : l'auditeur et le gouverneur de la
  plateforme sont refusés.
- `GET /api/v1/threat-intel/status` et les deux routes de synchronisation renvoient la version du
  catalogue, sa date de publication, la dernière tentative et son erreur ; `status` vaut
  `NEVER_SYNCED`, `SYNCED` ou `FAILED`. Une synchronisation qui ne peut pas lire le catalogue répond
  **200** avec `FAILED` et la raison, conserve le catalogue en usage, et est auditée comme un
  `THREAT_INTEL_SYNCED` en échec. `GET /api/v1/epss/cve/{id}` ne répond plus que depuis le catalogue
  et le fichier EPSS stockés — un **404** pour une CVE qu'aucun des deux ne contient.
- Les mêmes routes renvoient l'état du fichier EPSS sous `epss` : son statut, la version du modèle,
  la date des scores, les CVE notées, la dernière tentative et son erreur, et `inProgress` pendant
  qu'une synchronisation tourne. Les deux routes de synchronisation lisent le catalogue et le fichier
  EPSS, et écrivent une entrée `THREAT_INTEL_SYNCED` pour chacun. `epss_score` et
  `epss_percentile` quittent `t_threat_intel_feed` (V45).
- Une revue OWASP est enregistrée avant que le modèle soit interrogé : `GET …/owasp-review` peut
  répondre `status: running` pendant qu'une autre demande attend, et se lit `failed` une fois le
  délai du modèle dépassé sans personne pour la clore.
- Nouveaux types de résultats `plugin` et `imported`, et nouveaux champs sur les problèmes et les
  scans (`tool`, `toolName`, `toolVersion`, `importSource`, les `plugins[]` d'un scan). Le
  document OpenAPI du dépôt fait foi.
- **L'atteignabilité n'est pas calculée, et le dit.** Les champs `reachability` et
  `reachableSymbols` d'un problème restent dans `GET /api/v1/issues` et `GET /api/v1/issues/{id}`,
  marqués dépréciés dans le document OpenAPI : toujours `UNKNOWN` et null, puisque rien n'analyse
  le graphe d'appels. Retirés là où seule l'interface les lisait : `reachableEpssCount` et la
  `reachability` de chaque problème classé de `GET /api/v1/epss/priorities`, la `reachability` de
  chaque cible du rayon d'impact, la clé `reachability` des `metadata` d'un nœud de chemin
  d'attaque, et `deterministic.exposure` de la réponse du conseiller IA.
  `POST /api/v1/ai-advisor/explain/cve/{id}` ignore un paramètre `reachability`. En OpenVEX, un
  constat en attente de triage indique « Awaiting contextual triage. » au lieu de « Awaiting
  reachability confirmation and contextual triage. »
- **Le `deterministic.activelyExploited` du conseiller IA devient `deterministic.kev`** :
  `LISTED`, `NOT_LISTED` ou `UNKNOWN`, lu dans le catalogue CISA enregistré — le booléen valait
  faux avant toute lecture du catalogue. `deterministic.packageName`, `currentVersion`,
  `targetVersion` et `remediation.suggestedVersion` valent null quand rien n'est enregistré, au lieu
  de « the component », « current » ou « the fixed version », et l'avis d'un modèle ne porte plus
  de justification VEX.
- **`POST /api/v1/ai-advisor/explain/cve/{id}` ne lit plus `packageName`, `currentVersion` ni
  `fixVersion`** : ils étaient imprimés comme les faits de l'avis sur la seule parole de l'appelant.
  Un client qui les envoie encore reçoit la réponse qu'il aurait eue sans eux ; la route n'accepte
  aucune clé d'intégration. Une CVE qu'aucun problème visible ne porte est expliquée à partir des
  seuls flux enregistrés, et sa suggestion VEX est `under_investigation` même quand la CISA la liste
  — elle disait `affected`, à propos d'un parc que rien ne montrait concerné. La mise à niveau
  suggérée pour un problème est une seule commande, pour l'écosystème que nomme son purl (Maven,
  npm, PyPI, Cargo, NuGet, Composer, Go), avec un `<dependency>` Maven pour Maven seulement, et
  aucune quand le purl manque ou nomme un autre écosystème — elle proposait `mvn` et `npm` ensemble
  quel que soit le composant. Les deux routes d'explication prennent `language` (`en`, `fr` ;
  anglais en son absence, toute autre valeur un 400) : le modèle répond dans la langue de l'écran,
  là où il répondait en français à tout le monde.
- **La génération EPSS qu'un fichier remplace est conservée jusqu'à l'application du suivant**
  (V47, `epss_previous_generation`) : une analyse enrichie pendant une bascule ne trouve plus ses
  scores disparus ; `t_epss_score` contient les lignes de deux fichiers entre deux synchronisations,
  quelque 760 000.
- **Le protocole des agents a un septième appel**, `POST /api/v1/agent/jobs/{id}/failure` : une analyse
  que l'agent a prise et n'a pas pu exécuter est signalée aussitôt avec sa raison — remise en file avec
  la tentative comptée, ou en échec à la dernière — au lieu d'attendre vingt minutes l'expiration de
  son bail. La réponse à la prise porte l'`attempt` que le rapport nomme ; un agent plus ancien l'ignore.
  Signé comme un résultat quand la clé de l'agent est épinglée, audité sous `AGENT_SCAN_FAILED`. Un
  agent de cette version revient à l'expiration face à un plan de contrôle plus ancien (404). Voir
  [Agents](../administration/agents.md#quand-une-analyse-ne-peut-pas-sexecuter-sur-un-agent).
- **Le rapport d'échec prend un `kind`**, `permanent` ou `transient` (V48 ajoute `t_scan.not_before`) :
  un échec permanent fait échouer l'analyse aussitôt, un échec transitoire attend avant la prise
  suivante. Absent — un agent plus ancien — ou inconnu, il vaut transitoire. La réponse ajoute
  `permanent` et `retryAt`, l'instant à partir duquel l'analyse peut être reprise. Le résumé d'une
  analyse (`GET /api/v1/scans`, `GET /api/v1/scans/{id}`) ajoute `notBefore`, renseigné sur une analyse
  en attente dont la dernière tentative n'a pas pu s'exécuter.
- **Le détail d'une analyse ajoute `examinedTypes`** (V49 ajoute `t_scan.examined_types`) : les types
  de constat intégrés dont l'étape a produit dans cette analyse, par leur nom de fil —
  `vulnerability`, `secret`, `iac`, `sast`, `quality`, `eol`, `license`. Un type absent de la liste
  n'a pas été examiné, et ses issues sont restées en l'état. `null` signifie *non enregistré* — une
  analyse antérieure à cette version, ou qui ne s'est jamais exécutée — et jamais *rien examiné*, qui
  est `[]`. Les plugins restent dans `plugins`, dans leurs trois états.
- **Une source déclarée énonce ses `kinds`** (V50 ajoute `t_sarif_source.kinds`) : `sarif`, `coverage`,
  `test_report`. Une déclaration sans eux vaut `sarif` seul, et toute source déclarée avant cette
  version reste une source SARIF. `tools` est obligatoire avec `sarif` et refusé sans lui.
- **Activer les quatre yeux demande deux comptes capables de publier un modèle de checklist** — le
  gouverneur de la plateforme, un administrateur ou un CISO — en plus d'un compte capable d'approuver
  un triage : sous les quatre yeux, l'auteur d'un modèle ne peut pas le publier. Le réglage est refusé
  par une phrase qui le dit ; un déploiement où il est déjà actif n'est pas modifié. Voir
  [Quatre yeux](../administration/four-eyes.md).
- **Activer les quatre yeux demande aussi deux comptes capables d'approuver** — un administrateur, un
  CISO ou un référent sécurité : sous les quatre yeux, la checklist d'un projet est approuvée par un
  approbateur qui n'en a rien écrit, et celui qui l'a remplie ne peut pas l'approuver. Refusé par une
  phrase qui le dit ; un déploiement où le réglage est déjà actif n'est pas modifié. Voir
  [Quatre yeux](../administration/four-eyes.fr.md#approuver-une-checklist).
- **Un 409 peut nommer sa cause** dans le `type` du problème, `urn:vectispire:problem:<cause>`, là où une
  route refuse pour plusieurs raisons qui appellent des gestes différents — celles des checklists de
  projet le font (`checklist-changed`, `checklist-line-changed`, `checklist-four-eyes`,
  `checklist-incomplete`, …), et celles des modèles de checklist aussi (`checklist-template-changed`,
  `checklist-template-not-draft`, `checklist-template-has-draft`, … et `checklist-four-eyes`, qui y
  signifie la même chose — voir [Modèles de checklists](../administration/checklist-templates.fr.md#refus-pour-les-scripts-et-les-integrations)).
  Un problème sans cause garde `about:blank` ; le `detail` ne change pas. Un problème
  `checklist-incomplete` nomme aussi ses lignes comme données, dans un membre `lines` — l'`itemId`, la
  `position` et les `problems` de chaque ligne (`unanswered`, `evidence_required`, …) — pour qu'un
  client les désigne dans sa propre langue plutôt que d'analyser la phrase anglaise.
- **Les lignes mesurées d'une checklist ajoutent deux causes de 409 et changent trois routes.** Une
  soumission répond `checklist-measurement-contradicted` quand une ligne répond *oui* là où sa mesure
  échoue, et une approbation `checklist-measurement-changed` quand la mesure d'une ligne n'est plus
  celle que la soumission a conservée — chacune nommant ses lignes dans le membre `lines` du problème
  (`itemId`, `position`, `answer`, `outcome`, `reason`, et pour l'approbation `submittedOutcome`,
  `submittedReason`). Un *oui* là où une mesure n'a pas de données demande un commentaire et une preuve
  à la soumission : `checklist-incomplete` les nomme `comment_required` et `evidence_required`, les
  jetons qu'il avait déjà. La route de réponse accepte un `measurementDigest` facultatif ; la vue d'une
  ligne de checklist gagne `rule`, et les lignes d'une version de modèle comme chaque mesure portent leur
  `boundRule`, structurée comme la route des règles la reçoit. Sur un brouillon, les `problems` d'une
  ligne et le `readyToSubmit` de la checklist comptent ce que sa mesure empêche à la soumission —
  `measurement_contradicted` pour un *oui* face à un échec, le commentaire et la preuve qu'un *oui* sans
  données demande — jugé comme la soumission le juge : un client n'a plus besoin d'une seconde requête
  pour savoir si elle passera. Les preuves d'une mesure nomment chaque dépôt, `repositoryName` à côté de
  `repositoryId` (null pour un dépôt qui n'est plus dans le projet). Les vocabulaires fermés des vues de
  checklist sont énumérés dans le document OpenAPI, et le membre `lines` des deux problèmes a son schéma
  (`ChecklistIncompleteProblem`, `ChecklistMeasurementProblem`). La vue d'un import SARIF gagne `toolKeys` (V53) : les clés d'outil dont les
  exécutions ont été acceptées, une liste triée, `null` pour un import accepté avant.
- **Les `tools` d'un import SARIF sont une liste de chaînes**, un `nom version` par exécution, dans
  l'ordre du rapport — c'était une seule chaîne jointe par des virgules, dans la réponse de l'envoi comme
  dans `GET /api/v1/repositories/{id}/sarif-imports`. Une virgule dans la version d'un outil est écrite
  en point-virgule, si bien qu'une virgule sépare toujours deux outils. Les imports SARIF sont nouveaux
  dans cette version : aucune intégration de la 0.9.0 ne lisait la chaîne ; un script écrit contre une
  version de développement qui la découpait doit lire la liste. **`toolKeys` est une liste aussi**, triée
  — c'étaient les clés jointes par des virgules — et reste `null`, jamais une liste vide, pour un import
  accepté avant la V53. Sur les mêmes listes, une activation de
  plugin nomme son projet — `projectName`, `solutionId`, `solutionName` à côté de `projectId` — et une
  source déclarée sa clé, `apiKeyName` à côté de `apiKeyId` (`null` une fois la clé révoquée) ; le
  `plugins[].state` d'une analyse est énuméré dans le document OpenAPI : `produced`, `not_applicable`,
  `absent`, `refused` — ce dernier avec `refusal` (`unsigned`, `signature_unverified`) ; un plugin
  produit porte `signature` (`verified`, `waived`, `not_required`). Un plugin porte `unsignedWaiver`
  (`null` sans dérogation), posée et retirée par `PUT` / `DELETE /api/v1/plugins/{id}/unsigned-waiver` ;
  la tâche d'un scan porte `runsUnsigned` avec chaque plugin. Deux raisons rejoignent le `no_data` d'une
  mesure de checklist : `plugin_unsigned`, `plugin_signature_unverified`. Deux opérations d'audit,
  `PLUGIN_SIGNATURE_WAIVED` et `PLUGIN_SIGNATURE_WAIVER_REVOKED`, signalées toutes deux en `VECTI-SEC-021`.
- **Une nouvelle portée de clé, `report_import`**, jamais accordée par défaut : celle des envois de
  couverture et de rapports de tests, distincte de `sarif_import` pour qu'une clé qui envoie un chiffre
  de couverture ne dépose jamais de constats.

### Nouveautés

- **Un collecteur syslog TLS peut épingler sa propre autorité.** Collée en PEM sur la carte SIEM, elle
  remplace le magasin de confiance de l'environnement Java pour cette connexion seule — plus de
  `cacerts` monté par-dessus celui de la JVM, qui faisait reconnaître l'autorité privée par toutes les
  connexions TLS sortantes. Seul un certificat d'autorité en cours de validité est accepté ; la
  vérification du nom d'hôte reste active — [Export SIEM](../integrations/siem.md#tls).
- **Un projet seul : sa lecture, sa conformité et son score, son SBOM consolidé.**
  `GET /api/v1/projects/{id}` lit un projet tel que le décrit son nœud dans l'arbre, sa solution
  nommée. `GET /api/v1/projects/{id}/compliance` et `GET /api/v1/solutions/{id}/compliance` exécutent
  l'évaluation du parc sur les seules cibles du périmètre — mêmes contrôles, mêmes plafonds, `NO_DATA`
  quand aucune n'a été analysée — avec la fiche de score du portefeuille calculée de même. `GET
  /api/v1/projects/{id}/components` fusionne les composants de la dernière analyse terminée de chaque
  dépôt et de chaque image par package URL et version, en nommant les cibles qui portent chacun et ce
  qui a été lu de chaque cible (`listed`, `empty`, `absent`, `never_scanned`, et `complete`), et `GET
  /api/v1/cyclonedx/projects/{id}/cyclonedx-vex.json` le rend en CycloneDX 1.5 avec le VEX du projet,
  `compositions` disant s'il est complet. Les trois premières acceptent une clé `read`, le document une
  clé `export`. Chacune suit la règle de l'arbre : un projet vu en partie est calculé sur cette partie
  et le dit par `partial` ; un projet que l'on ne voit pas du tout répond `404` comme un projet
  inexistant — [Solutions et projets](../administration/solutions-and-projects.fr.md#un-projet-seul-ses-chiffres-sa-conformite-et-ses-composants).

- **Les images de conteneur peuvent être rangées dans des projets** (V59 ajoute
  `t_container.project_id`), comme les dépôts : un projet au plus chacune, rangée, déplacée et retirée
  par un administrateur via `PUT` / `DELETE /api/v1/projects/{id}/containers/{containerId}`,
  journalisé sous `PROJECT_CONTAINERS_CHANGED`. **Une attribution de projet couvre désormais aussi ses
  images**, résolue à chaque requête : une image rangée dans le projet est visible de ses titulaires
  aussitôt, et cesse de l'être par cette attribution dès qu'elle en sort. L'arbre liste les images de
  chaque projet et celles qui ne sont rangées nulle part ; le déplacement d'un projet les emporte ; la
  suppression d'un projet les ramène à « sans projet » ; une équipe titulaire d'un projet est notifiée
  des analyses de ses images. `GET /api/v1/containers` nomme le projet de chaque image (`projectId`,
  `projectName`), et **Conteneurs** l'affiche avec un lien vers l'arbre, où les images se rangent par
  les mêmes fenêtres que les dépôts. Les checklists ne mesurent toujours que les dépôts d'un projet —
  [Solutions et projets](../administration/solutions-and-projects.fr.md#ce-qui-reste-propre-aux-depots).

- **Les langages détectés dans un dépôt sont conservés.** Chaque scan de dépôt recense les langages
  de son arbre et les garde ; `GET /api/v1/repositories` donne à chaque dépôt `detectedLanguages`
  d'après son scan terminé le plus récent (`null` si inconnu, `[]` si aucun), et chaque projet de
  `GET /api/v1/solutions` l'union sur les dépôts que l'appelant voit, avec `languagesUnknownFor`. Ils
  s'écrivent comme un manifeste de plugin déclare ses `languages` —
  [Plugins](../administration/plugins.md#les-langages-detectes-dans-un-depot).
- **Vectispire répond aux lignes qu'il mesure** (V56 ajoute `answered_by_kind` et `withdrawn` à
  `t_checklist_answer`). Sur une checklist en brouillon, une ligne liée à une règle reçoit *oui* quand
  sa mesure est atteinte et *non*, avec la mesure pour commentaire, quand elle échoue — quand une
  analyse se termine ou qu'un rapport SARIF, de couverture ou de tests est accepté pour l'un des dépôts
  du projet, et quand la checklist est ouverte, passée à une autre version ou rouverte ; l'absence de
  données ne répond rien, et retire une réponse de Vectispire qui reposait sur des données qu'il n'a
  plus. L'auteur est Vectispire, aucun compte : marqué *automatique* à l'écran, dans l'historique, la
  feuille `Evidence` et `checklist.json`, audité en `CHECKLIST_ANSWERED` sans utilisateur. La réponse
  d'une personne n'est jamais remplacée ; Vectispire ne remplace la sienne que si ce qu'elle affirme
  change — sa valeur, ou son commentaire qui porte les chiffres —, et une nouvelle analyse qui mesure la
  même chose n'écrit donc rien. La soumission et l'approbation
  sont inchangées — des personnes, sous double validation, et un *oui* sur une ligne qui demande une
  preuve l'exige toujours. **Activé par défaut** : le paramètre `checklist_auto_answer`, celui du
  gouverneur de plateforme, revient aux réponses des seules personnes. Les checklists déjà en brouillon
  reçoivent leurs réponses à la prochaine analyse, au prochain import ou à la prochaine ouverture de leur
  projet. Voir [Checklists de sécurité](../guide/security-checklists.fr.md#reponses-automatiques).
- **Les lignes mesurées d'une checklist répondues comme mesuré, en un seul geste.**
  `POST /api/v1/projects/{id}/checklists/{revision}/answers/as-measured`, corps
  `{ edition, lines: [{ itemId, measurementDigest }] }`, sur un brouillon : chaque ligne désignée — telle
  que montrée, avec l'empreinte lue — sans réponse, toujours sur cette preuve et atteinte reçoit un *oui*
  de l'appelant, reposant sur cette mesure — le clic unique d'une ligne mesurée, pour toutes les lignes
  montrées à la fois, chaque réponse une ligne de son historique et une entrée `CHECKLIST_ANSWERED` à
  elle. Les lignes déjà répondues, les lignes désignées dont la preuve a bougé, les lignes atteintes non
  désignées, celles sans données et celles non atteintes — dont le *non* demande un commentaire écrit
  par une personne — sont laissées telles quelles et renvoyées dans `skipped` avec leur raison
  (`already_answered`, `measurement_changed`, `not_shown`, `no_data`, `needs_comment`). La garde du projet entier de toutes les routes de
  checklist ; toute écriture depuis l'édition lue refuse le geste (`checklist-changed`). Voir
  [Checklists de sécurité](../guide/security-checklists.fr.md#lignes-mesurees).
- **Une checklist signée est un document signé** (V55 ajoute `t_checklist_document`).
  `GET /api/v1/projects/{id}/checklists/{revision}/document` renvoie un zip : `checklist.xlsx`, le
  classeur de l'organisation dont seules les cellules de réponse, de commentaire et d'en-tête sont
  écrites, avec une feuille `Evidence` ajoutée, et `checklist.json`, la même déclaration lisible par une
  machine — chacun avec sa signature détachée quand la révision est signée. Ce paquet est rendu et signé
  pendant la signature, puis servi tel qu'enregistré : le téléchargement de l'an prochain est le
  document qui a été signé ; une révision en brouillon ou soumise est rendue à la demande, non signée, et
  le dit. `@AcceptsApiKey(EXPORT)`, audité `CHECKLIST_EXPORTED`. Vérification :
  `cosign verify-blob --key vectispire-signing-key.pub --insecure-ignore-tlog=true --signature checklist.xlsx.sig checklist.xlsx`
  — [Checklists de sécurité](../guide/security-checklists.fr.md).
- **Les lignes de checklist mesurées par les preuves qui ont tourné** (V54 ajoute
  `t_checklist_measurement`). Un responsable sécurité lie une règle à une ligne d'un brouillon
  (`PUT /api/v1/checklist-templates/{slug}/versions/{ordinal}/rules`, sur la `revision` lue, consigné
  `CHECKLIST_TEMPLATE_RULES_BOUND`) : analyse des dépendances, seuil de constats sur des étapes
  intégrées, des plugins ou des outils importés, couverture, suite de tests passée, ou versions de
  composants d'après une liste explicite — chacune avec son âge maximal (exigé, 1 à 366 jours) et ses
  propres paramètres, dans l'empreinte de contenu de la ligne et reportée comme son exigence de preuve.
  `GET /api/v1/projects/{id}/checklists/{revision}/measurements` montre la mesure de chaque ligne liée —
  pass, fail ou no data avec sa raison (`never_examined`, `step_absent`, `examination_unrecorded`,
  `stale`, `not_applicable_anywhere`, …), jamais un succès par défaut — à côté de la réponse. La
  soumission mesure à nouveau et refuse un *oui* face à un échec ; l'approbation mesure à nouveau et
  est refusée quand une mesure a changé depuis la soumission, et fige les autres avec la révision.
  Vectispire ne répond jamais : une réponse peut reposer sur une mesure que la personne a lue, et reste
  la sienne. **Les analyses d'un dépôt antérieures à V49, et les imports SARIF d'une source antérieurs à
  V53, se lisent `examination_unrecorded`** — rien n'a enregistré s'ils ont regardé — jusqu'à sa
  prochaine analyse ou son prochain envoi. Sur l'écran des modèles, un responsable sécurité lie une
  ligne du brouillon à sa règle, le texte de l'indicateur de la ligne à côté des paramètres et la règle
  en mots à côté des deux, un préréglage *secrets à zéro* compris, et enregistre ensemble les lignes
  modifiées ; l'auditeur et une version publiée lisent la règle de chaque ligne. Sur la checklist d'un
  projet, chaque ligne liée montre sa mesure — atteint, non atteint, ou pas de données avec sa raison en
  mots — à quelle date, ses chiffres et, à la demande, les preuves de chaque dépôt ; une ligne atteinte
  ou non atteinte propose de répondre comme mesuré en un clic, en reposant sur la mesure lue. La page dit
  si les mesures sont en direct ou figées par la validation, et **Soumettre** reste grisé, les lignes
  nommées, tant qu'une mesure retient la révision — un *oui* contredit, ou un *oui* sans données auquel
  manque son commentaire ou sa preuve —
  [Checklists de sécurité](../guide/security-checklists.fr.md#lignes-mesurees).
- **La preuve qu'une ligne de checklist demande se définit sur le brouillon du modèle**
  (`PUT /api/v1/checklist-templates/{slug}/versions/{ordinal}/evidence`, sur la `revision` lue) : pour
  chaque ligne, `none`, `link_or_file` ou `file`, et pour une preuve qui expire, sa validité en mois
  (1 à 120). Jusqu'ici chaque ligne importée n'en demandait aucune, si bien qu'aucune preuve n'était
  jamais exigée à la soumission. L'exigence fait partie de ce que la ligne demande : une ligne dont
  l'exigence a bougé est *modifiée* par rapport à la version précédente, et la réponse d'un projet
  reportée sur elle attend confirmation. Confirmer à nouveau une disposition garde l'exigence de chaque
  ligne, et la ligne d'un nouveau classeur prend celle de la version précédente sous la même clé ;
  dériver une version les reporte. Consigné `CHECKLIST_TEMPLATE_EVIDENCE_SET`. L'écran du brouillon la
  fixe ligne par ligne, dans la colonne **Preuve demandée** des items lus, et n'envoie que les lignes
  modifiées — [Modèles de checklists](../administration/checklist-templates.fr.md#4-dire-quelle-preuve-chaque-ligne-demande).
- **Checklists de projet, remplies par des personnes** (V52 ajoute `t_checklist`, `t_checklist_answer`,
  `t_checklist_evidence`, `t_checklist_file`). La checklist d'un projet s'ouvre sur une version de modèle
  publiée (`POST /api/v1/projects/{id}/checklists`), se remplit ligne par ligne — chaque réponse gardée,
  avec son auteur et son instant — se prouve par des liens et des fichiers (25 Mo, rendus seulement en
  téléchargement), se soumet, se renvoie, s'approuve par un approbateur, se rouvre, ou passe à une
  version plus récente avec ses réponses reportées : courantes là où la ligne n'a pas changé, à
  confirmer là où elle a changé. Seul qui voit le projet **entier** la lit ou l'écrit ; tout autre reçoit
  un 404. Chaque écriture nomme l'`edition` lue. Auditées `CHECKLIST_*` ; une approbation part au SIEM
  en `VECTI-SEC-025`, une approbation refusée ou un renvoi en `VECTI-SEC-026`. Supprimer un projet
  supprime ses checklists ; les entrées d'audit restent. Les écrans viennent avec la moitié interface de
  ce lot. `GET /api/v1/projects/{id}/checklists/context` nomme le projet et sa révision la plus récente
  pour une page qui n'a pas encore de checklist à montrer ; la liste et les versions proposées restent
  des tableaux nus.
- **Couverture et rapports de tests depuis les sources déclarées.** Un pipeline envoie un rapport de
  couverture JaCoCo, Cobertura ou lcov (`POST /api/v1/repositories/{id}/coverage-imports?format=…`) ou
  un rapport JUnit — un fichier XML ou un zip de plusieurs (`…/test-report-imports`) — avec une clé
  `report_import` pour laquelle sa source est déclarée. Les chiffres sont gardés, jamais le document ;
  un rapport vide est refusé plutôt qu'enregistré comme zéro, et rien n'ouvre ni ne résout d'issue.
  Audités `COVERAGE_IMPORTED`, `TEST_REPORT_IMPORTED` et `REPORT_IMPORT_REFUSED`, le refus envoyé au
  SIEM comme `VECTI-SEC-027`. `scripts/vectispire-cli.sh` gagne `coverage` et `test-report` —
  [Importer des rapports de couverture et de tests](../administration/plugins.md#importer-des-rapports-de-couverture-et-de-tests).
- **La page d'une analyse montre quelles étapes ont examiné l'arbre.** Une carte *Ce que ce scan a
  examiné* liste les étapes intégrées qui ont produit et celles qui n'ont pas regardé — en échec, ou
  non lancées pour cette cible — de sorte qu'une liste de constats vide ne se lit comme propre que
  pour les étapes qui ont tourné. Les analyses antérieures à cette version affichent *Non
  enregistré* jusqu'à la prochaine analyse de la cible — [Scans](../guide/scans.md#lire-un-scan).
- **Solutions et projets** : une solution contient des projets, un projet référence des dépôts,
  et un droit peut viser un projet entier — [Solutions et projets](../administration/solutions-and-projects.md).
- **Un projet se déplace vers une autre solution** (`solutionId` sur `PATCH /api/v1/projects/{id}`),
  avec ses dépôts, ses droits, ses checklists, ses activations de plugins et ses sources SARIF ; l'accès
  de personne ne change. Un nom que la solution cible contient déjà est refusé par un 409
  `project-name-taken` — [Solutions et projets](../administration/solutions-and-projects.md#deplacer-un-projet-vers-une-autre-solution).
- **Plugins d'analyse** : des analyseurs tiers livrés en images de conteneur, enregistrés par le
  gouverneur de la plateforme, activés par projet, lancés confinés comme les scanners intégrés, et
  seulement quand un langage qu'ils déclarent est présent. Une image déclare son signataire ; la
  signature est vérifiée avant le pull, et un plugin qui n'en déclare aucun est refusé sauf dérogation
  écrite du gouverneur (V60) — `VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED`, activé par défaut.
- **Imports SARIF** depuis des sources internes déclarées (un job de CI, un SonarQube sur site),
  chacune liée à une clé restreinte et à un périmètre, avec la provenance conservée sur chaque
  problème — [Plugins et imports SARIF](../administration/plugins.md). Les politiques de barrière
  ne comptent les résultats des plugins et importés que si elles le disent (`include_plugins`).
- **Git en HTTPS** avec un jeton géré lié à un hôte, à côté des clés SSH ;
  `VECTISPIRE_GIT_ALLOWED_HOSTS` restreint les hôtes d'où l'on clone.
- **Export SIEM** en syslog UDP, TCP ou TLS (RFC 5424, CEF), envoyé après le commit —
  [Export SIEM](../integrations/siem.md).
- **Scans parallèles sur un agent**, de 1 à 16 à la fois (`max_concurrent`), comptés par la base.
- **Une base de vulnérabilités par hôte**, téléchargée une fois sous verrou et partagée en lecture
  seule par toutes les analyses au lieu d'une fois par analyse (quelque 3 Go), dans
  `VECTISPIRE_VULNERABILITY_DB_DIR` ; le rapprocheur tourne désormais sans réseau.
- **Réinitialiser la clé de scellement d'un agent** depuis l'écran Agents, pour un hôte dont
  l'horloge a été remise en arrière ou une clé soupçonnée d'avoir fui.
- L'authentification unique enregistre le second facteur du fournisseur et peut l'exiger
  (`VECTISPIRE_OIDC_REQUIRE_MFA`) ; Vault Transit peut détenir la clé de chiffrement.
- **Se connecter par l'authentification unique ramène à la page demandée**, filtre compris, au
  lieu du tableau de bord — et seulement à une page de cette application : l'écran de connexion ne
  transmet qu'une adresse de retour qu'il suivrait lui-même, et le plan de contrôle la vérifie à
  nouveau avant de la garder.
- **Les écrans n'affichent plus l'atteignabilité**, que rien ne calcule : la liste des problèmes
  perd ses étiquettes atteignable / non atteignable, le détail d'un problème son encadré
  d'atteignabilité, la page EPSS sa carte « appelables et armées » et sa colonne, le rayon d'impact
  sa colonne. Le scorecard facture chaque critique 8 points, le classement EPSS est CVSS × EPSS
  avec le KEV au-dessus, et les chemins d'attaque ne retiennent ni ne signalent plus un nœud sur
  cette base — aucun chiffre qu'une installation a affiché ne bouge, puisque chaque problème valait
  `UNKNOWN`. Le conseiller IA indique que l'exposition n'a pas été évaluée.
- **Le conseiller IA n'invente plus de chiffres d'exploitation.** L'explication d'une CVE que le
  parc ne porte pas affichait une probabilité EPSS de 75 % pour toute CVE, et « activement
  exploitée » pour deux identifiants inscrits dans le code ; une CVE inscrite sans score valait
  85 %. Il affiche désormais l'inscription KEV et le score EPSS que détiennent les flux
  enregistrés, et indique « inconnue » quand ils ne détiennent rien — avant la première
  synchronisation, par exemple. Les phrases d'impact que personne n'avait vérifiées (« un attaquant
  distant peut exécuter du code arbitraire ») disparaissent, aucune mise à niveau n'est proposée
  sans version corrigée enregistrée, et la page EPSS n'affiche plus un percentile de 0 pour une
  CVE que le fichier ne note pas.
- **Les règles fournies ne s'accumulent plus dans le répertoire de travail.** Chaque démarrage du
  plan de contrôle ou d'un agent les dépliait dans un nouveau répertoire
  `vectispire-bundled-rules-*`, et aucun n'était jamais supprimé. Le répertoire disparaît désormais
  à l'arrêt du processus, et le premier démarrage de cette version balaie ce que les précédents ont
  laissé : seulement les répertoires de ce nom, appartenant à l'utilisateur du processus, plus
  anciens que lui et tenus par aucun processus en cours.

### Sécurité

Cette version corrige les constats de la revue de sécurité du 2026-09-26 et leurs suites —
limites d'authentification sous tentatives concurrentes, liaison de l'authentification unique,
SSRF et différences d'analyse des URL de clonage, lectures sortantes bornées, complétude de
l'audit et du SIEM, clé de scellement de l'agent. Jackson est relevé au-dessus du BOM Spring Boot pour
GHSA-q4xh-88c3-wmh7 (High) et deux avis liés, sur le plan de contrôle **et sur l'agent**, dont le SBOM
est désormais scanné par le pipeline — il ne l'était pas, et restait sur une version vulnérable sans que
rien ne le dise. Les commandes `cosign verify-blob --key` que donnent le produit et le guide de
conformité portent désormais `--insecure-ignore-tlog=true` : sans ce drapeau, cosign cherchait la
signature dans un journal de transparence où Vectispire ne publie rien, et refusait chaque export. Les
dépendances et plugins de la construction
sont désormais vérifiés par signature et somme de contrôle. Le détail est dans l'historique des
commits et dans le
[registre des décisions](https://github.com/asmolabs/vectispire/tree/main/docs/architecture/fr/decisions).
