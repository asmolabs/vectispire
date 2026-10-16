# Notes de version

## 0.11.1 — en préparation

À la suite de la 0.11.0 ; pas encore publiée. Ce qui suit est ce que contiendra la 0.11.1, par rapport à la 0.11.0.

### Avant la mise à jour {#avant-la-mise-a-jour-0111}

- **Une valeur de configuration manifestement erronée arrête désormais le démarrage avec un message qui la
  nomme :** `VECTISPIRE_SCAN_MAX_CONCURRENT` inférieur à 1 (lu en silence comme 2 ; pour couper le worker,
  `VECTISPIRE_EMBEDDED_WORKER=false`), et une durée de session, de bail du leader ou de file inférieure à une
  seconde, comme `VECTISPIRE_SESSION_IDLE=60` sans unité, qui était lu comme 60 ms.
- **Un agent distant dont `VECTISPIRE_AGENT_WAIT` ou `VECTISPIRE_AGENT_RETRY` est inférieur à `1s`, ou dont
  `VECTISPIRE_AGENT_HEARTBEAT` est inférieur à `5s`, ne démarre plus** ; il tournait en silence sur le
  plancher. Le message nomme la variable et sa valeur — `30` sans unité vaut 30 ms : écrivez `30s`.
  Vérifiez ces trois variables sur chaque agent avant de le mettre à jour. Une valeur au-dessus de son
  plafond (`5m`, `5m`, `10m`) démarre toujours, ramenée au plafond, avec un avertissement qui nomme la
  variable.

### Changements visibles d'une intégration {#changements-visibles-dune-integration-0111}

- **Les refus du webhook de tickets (400, 401, 403) sont des documents « problem » RFC 9457**, la raison
  dans `detail`, et non plus le corps d'un succès avec `matched: false` et `actionTaken`.
- **SCIM répond à un utilisateur ou un groupe absent (404) et à un `userName` ou un `displayName` déjà pris
  (409, `scimType` `uniqueness`) dans le schéma d'erreur SCIM** au lieu d'un corps vide. Un groupe renommé
  (`PUT` ou `PATCH` `/scim/v2/Groups/{id}`) avec le `displayName` d'un autre groupe reçoit le même `409`,
  sans rien changer : le `PUT` répondait `500`, et un renommage par `PATCH` — `replace` avec le chemin
  `displayName`, ou `displayName` dans la valeur — n'était pas appliqué du tout, et répondait `200` avec
  l'ancien nom. Un `displayName` de groupe de plus de 100 caractères reçoit `400`, et non plus `500`. Un
  `replace` des `members` d'un groupe par `PATCH` les remplace (RFC 7644 §3.5.2.3), avec le chemin
  `members` ou `members` dans la valeur, et une liste vide retire tout le monde : il était lu comme un
  `add`, si bien qu'une personne que l'annuaire retirait du groupe gardait l'équipe et ce qu'elle accorde.
  Comme un `PUT`, il retire les membres non listés, quel que soit qui les a ajoutés. Un membre inconnu est
  ignoré, comme un `add` l'ignore ; un `add` nommant un identifiant qu'aucun compte ne porte, qui répondait
  `500`, est ignoré lui aussi.
  Le document OpenAPI déclare, avec le schéma `ScimErrorResponse`, chaque refus que les routes y répondent :
  les `400` (`scimType` `invalidFilter` sur la liste des utilisateurs), le `403` sur un compte
  administratif (`PUT`, `PATCH`, `DELETE /scim/v2/Users/{id}`), les `404` et les `409` ; et il déclare le
  `201` que répond une création (`POST /scim/v2/Users`, `/Groups`), là où il annonçait `200`.
- **Chaque ligne de la grille OWASP Top 10 (`GET /api/v1/owasp/coverage`) porte `reason` à côté de
  `because`, qui est conservé :** `code`, l'un de quatorze (`NO_SCANNER` … `REPOSITORIES_NOT_EXAMINED`), et
  ses valeurs — `types`, les types de constat qu'il nomme par leur nom d'échange, et pour un périmètre
  examiné en partie `missing`, `applicable` et `gaps` (chaque `gap`, `NEVER_SCANNED`, `LAST_SCAN_FAILED`…,
  avec son nombre de `targets`).
- **Le PDF du rapport OWASP (`GET /api/v1/repositories/{id}/owasp-review/export.pdf`) accepte
  `language=en|fr`**, l'anglais par défaut ; une autre valeur répond 400.
- **`GET /api/v1/issues` accepte `identifier`** : les issues dont l'identifiant est exactement celui donné,
  sans tenir compte de la casse, dans la visibilité de l'appelant ; `search` cherche toujours une
  sous-chaîne. Au-delà de 255 caractères, la longueur de la colonne, il répond 400 ; le document OpenAPI
  déclare cette borne (`maxLength`).
- **Les recherches en texte libre des routes de liste répondent 400 au-delà de 500 caractères**, la raison
  dans `detail` : `search` sur `GET /api/v1/issues` et `GET /api/v1/audit-log`, `name` sur
  `GET /api/v1/inventory/search` et `/api/v1/inventory/versions`, `q` sur `GET /api/v1/blast-radius/explore`.
  Cinq cents est la plus longue colonne que l'une d'elles lit, si bien qu'aucune réponse n'est perdue ;
  elles partaient vers la base quelle que soit leur longueur. Le document OpenAPI déclare la borne
  (`maxLength`), et les champs de recherche des problèmes, du journal d'audit, de la recherche de
  composants et du rayon d'impact n'en acceptent pas davantage — et le disent sous le champ (« 500
  caractères au plus ») une fois qu'il est plein, plutôt que d'ignorer la frappe sans un mot.

- **Les listes d'inventaire se paginent à la demande : `limit` et `offset` sur `GET /api/v1/repositories`,
  `/api/v1/containers`, `/api/v1/users`, `/api/v1/teams`, `/api/v1/api-keys`, `/api/v1/admin/agents` et
  `/api/v1/projects/{id}/reports`.** Sans l'un ni l'autre, chacune répond ce qu'elle répondait — la liste
  entière, dans le même tableau (les exécutions de rapport : les 200 dernières) —, rien ne change donc pour
  un client qui ne demande rien. Avec `limit` (1 à 500) et `offset` (zéro ou un multiple de `limit`), elle
  rend le même tableau découpé dans ce que l'appelant voit, une page plus courte que `limit` étant la
  dernière ; les exécutions de rapport vont alors au-delà des 200 dernières. Un `limit` hors de 1–500, un
  `offset` entre deux pages ou un `offset` sans `limit` répond 400, la raison dans `detail` — jamais une
  page silencieusement plus courte. Les dépôts et les images sont désormais listés par `id`, les agents par
  nom puis `id` et les clés de la plus récente à la plus ancienne puis par `id`, afin que les pages d'une
  liste soient la liste découpée ; une liste sans page a les mêmes lignes qu'avant. `GET /api/v1/users`
  gagne `total`, tous les comptes, que la page les montre tous ou non. Les dépôts d'une découverte de forge
  et la sélection d'import gardent leurs bornes et leurs phrases, désormais une règle partagée avec ces
  listes.

- **D'autres lectures se paginent à la demande : `limit` et `offset` sur `GET /api/v1/history/repositories`,
  `/api/v1/attack-paths/overview`, `/api/v1/licenses/inventory` et `/api/v1/licenses/conflicts` ; `offset`
  sur `GET /api/v1/scans` ; `startIndex` et `count` sur `/Users` et `/Groups` de SCIM.** Sans eux, chacune
  répond ce qu'elle répondait. Les quatre premières suivent la règle des listes d'inventaire ci-dessus, la
  visibilité appliquée avant le découpage. Les dépôts de l'historique de triage sont triés du plus
  récemment scanné au moins récent, ceux jamais scannés en dernier, par `id` à égalité ; la vue d'ensemble
  des chemins d'attaque par `id` de dépôt. L'inventaire des licences et ses conflits gardent leur ordre sans
  page, qui n'en était pas un : une page est découpée dans l'inventaire trié par cible, paquet et version,
  si bien que les pages contiennent toutes les entrées, dans cet ordre. L'historique des scans garde son
  `limit` — 50 par défaut, ramené entre 1 et 200, jamais refusé — et prend un `offset`, zéro ou un multiple
  de la limite retenue, 400 sinon ; pour un lecteur de plus de 1 000 cibles, `offset` plus `limit` vaut
  10 000 au plus, 400 au-delà. **L'historique des scans d'un lecteur restreint est désormais fait de
  ses propres scans les plus récents**, lus avec la visibilité dans la requête : c'étaient les `limit`
  derniers scans du parc réduits ensuite aux siens, souvent aucun alors que les siens existaient ; un
  lecteur du parc entier lit les mêmes lignes. SCIM pagine comme la RFC 7644, les valeurs hors bornes
  interprétées plutôt que refusées ([SSO](../administration/sso.fr.md#provisioning-from-the-directory-scim)) ;
  `/Users` acceptait les deux paramètres et les ignorait.

- **Le document OpenAPI dit quels champs de réponse le serveur envoie à `null`** sur les problèmes et ce
  qui les porte : 34 champs d'un problème — l'`IssueView` des routes de triage et de ticket (`POST
  /api/v1/issues/{id}/triage`, `POST /api/v1/issues/triage`, `PUT /api/v1/issues/{id}/ticket`), les lignes
  du backlog (`GET /api/v1/issues`, avec `slaDueAt`, `slaState` et `slaDays`) et le détail (`GET
  /api/v1/issues/{id}`, avec la `version` d'une observation) —, les champs facultatifs d'une décision de
  triage et ceux d'un problème dans l'historique de triage (`GET /api/v1/history/repositories/{id}`), les
  `cvssScore`, `epssScore` et `epssPercentile` du classement EPSS (`GET /api/v1/epss/priorities`), et les
  `projectName`, `solutionId`, `solutionName` d'une activation de plugin et le `pluginName` d'un plugin de
  rapport. Chacun est typé avec `"null"` à côté de son type et une description qui dit quand, là où le
  document disait `string`, `integer`, `number` ou `boolean` ; le serveur envoyait déjà ces `null`, et
  aucune réponse ne change. Un client généré depuis le document les type désormais `T | null`.

### Nouveautés {#nouveautes-0111}

- **Un administrateur lève l'obligation de changer de mot de passe d'un compte fédéré depuis l'écran
  Utilisateurs** (`DELETE /api/v1/users/{id}/password-change-requirement`). C'est refusé pour un compte qui
  se connecte avec son propre mot de passe, pour son propre compte, et pour celui d'un superutilisateur sauf
  par un superutilisateur. La levée écarte le mot de passe local du compte et ferme ses sessions, si bien que
  le compte ne se connecte plus que par le fournisseur d'identité : un mot de passe qu'un administrateur a un
  jour saisi pour lui ne reste pas valide. Cela remplace l'instruction SQL que la section *Avant la mise à jour* de la 0.11.0
  donnait pour les comptes créés par l'annuaire SCIM
  ([utilisateurs et équipes](../administration/users-and-teams.md#lobligation-de-changer-de-mot-de-passe)).
- **Le changement d'état d'un jeton est signalé une fois**, pour le jeton du gestionnaire de tickets et pour
  chaque connexion de forge : une entrée d'audit (`INTEGRATION_TOKEN_EXPIRING`, `INTEGRATION_TOKEN_STOPPED`,
  `INTEGRATION_TOKEN_RESTORED`), un événement SIEM (`VECTI-SEC-038` à 4, `VECTI-SEC-039` à 7, `VECTI-SEC-040`
  à 2) et un message sur chaque canal de notification configuré — jamais le jeton lui-même, et pour le
  gestionnaire de tickets jamais son adresse, que seuls les administrateurs lisent : il est nommé par sa
  sorte. Remplacer un
  jeton de gestionnaire de tickets refusé annonce qu'il fonctionne de nouveau
  ([notifications](../integrations/notifications.md#integration-token-alerts),
  [SIEM](../integrations/siem.md)).
- **La grille du Top 10 OWASP explique chaque catégorie dans la langue de l'interface**, et le PDF du rapport
  OWASP suit la langue du lecteur pour ses propres mots, contient la grille de couverture du dépôt (les dix
  catégories avec leur état et leur raison) et reproduit le texte du modèle tel qu'il l'a écrit.

- **Les contacts d'une checklist sont liés à des comptes et rappelés chaque semaine.** Les profils que nomme
  la colonne de contact d'un modèle — *PO*, *BA*, *Arch*, chaque valeur sauf `AUTO`, une cellule comme
  *PO / BA* nommant les deux — sont listés sur la page de la checklist sous **Contacts**, chacun lié à un
  compte qui peut remplir la checklist (`GET`, `PUT`, `DELETE /api/v1/projects/{id}/checklists/contacts/{profile}`,
  et `/candidates` pour les comptes proposés). Avec le nouveau paramètre **Rappeler chaque semaine les
  contacts des checklists** (`checklist_reminders_enabled`, désactivé par défaut) et le relais de messagerie
  configuré, chaque compte lié reçoit une fois par semaine les lignes de ses profils encore sans réponse ou
  en attente de confirmation, et les CISO les profils que personne ne rappelle — liés à personne, ou à un
  compte supprimé, désactivé, qui ne peut plus remplir la checklist ou sans adresse. Consigné comme
  `CHECKLIST_CONTACT_CHANGED` et `CHECKLIST_REMINDER_SENT` ; la migration V91 ajoute `t_checklist_contact`
  ([checklists de sécurité](../guide/security-checklists.fr.md#contacts-et-rappels-hebdomadaires), décision 0044).

### Sécurité {#securite-0111}

- **La découverte d'API rapporte au plus 50 000 points d'accès par dépôt, et 50 000 chemins par contrat.**
  Au-delà, l'étape échoue avec un message qui le dit et le dépôt garde son inventaire précédent, plutôt
  qu'une liste coupée ne retire le reste. L'export OpenAPI synthétisé nomme les opérations qui partagent un
  nom en un temps linéaire en leur nombre, avec les mêmes noms qu'avant.

- **L'URL du gestionnaire de tickets (`ticket_base_url`) est refusée quand elle porte un nom d'utilisateur
  ou un jeton** (`https://utilisateur:…@hôte`), comme l'adresse d'une connexion de forge l'était déjà : le
  jeton a son propre champ, qui le chiffre ([tickets](../integrations/ticketing.md#configurer)).

- **Un nom renvoyé par une forge ou saisi par une personne ne change plus le point d'API de la forge
  appelé.** La découverte, les lectures de revue des changements et la vérification d'une connexion encodent
  chaque projet, propriétaire, dépôt, branche et numéro de merge request comme un seul segment de chemin,
  barres obliques comprises, et refusent celui qui n'est fait que de points, qui se lit alors inconnu ou
  illisible, en mots.
- **Le document d'un rapport téléchargé par le gouverneur de la plateforme est envoyé au SIEM comme
  `VECTI-SEC-032`**, le SHA-256 de l'export en tête, l'action `REPORT_DOWNLOADED` et la cible l'exécution :
  le gouverneur ne peut pas prendre l'export d'un projet, et un document est cet export mis en forme. Le
  téléchargement de tout autre reste seulement journalisé, comme copie d'un export déjà signalé quand le
  plugin l'a reçu ([SIEM](../integrations/siem.fr.md),
  [plugins de rapport](../administration/report-plugins.fr.md#demander-un-rapport)).
- **Le `Dockerfile`, `Dockerfile.agent` et `Dockerfile.cli` nomment leurs images de base par digest**
  (`image:tag@sha256:…`, l'index multi-architecture), si bien qu'un même fichier construit les mêmes bases
  jusqu'à ce qu'une mise à jour relue les déplace ; le contrôle `dockerfile-policy` refuse une image de base
  nommée par son seul tag, par un digest qui n'est pas un sha256 entier, ou sous un nom d'étape de sa propre
  ligne. Les images publiées avec Jib l'étaient déjà.
- **Un enregistrement qui nomme à la fois un dépôt et une image est celui du dépôt dans toutes les
  lectures d'un lecteur restreint**, comme il l'était déjà dans l'historique des scans : les derniers scans
  du tableau de bord, le registre des verdicts de la barrière, le registre des exceptions, la liste des
  issues et les chiffres qui en dérivent, et le rayon d'impact ne le montrent plus — ni le nom de son dépôt,
  ni ne le comptent, ni ne le parcourent de page en page — à un lecteur à qui l'image est accordée et pas le
  dépôt. Un lecteur à qui les deux sont accordés le voit une fois, là où les derniers scans le montraient
  deux fois, et le rayon d'impact le compte pour une seule cible. Vectispire n'écrit pas aujourd'hui de tels
  enregistrements ; une base restaurée ou modifiée à la main peut en contenir, de même que les issues d'une
  installation qui a fait tourner la 0.9.0 ou une version antérieure, dont la synchronisation des issues
  copiait les deux colonnes du scan qu'elle lisait.

### Corrigé {#corrige-0111}

- **Un rapport de scanner corrompu ou absent ne résout plus les problèmes de la cible.** Un rapport de
  secrets qui n'était pas du JSON, pas une liste de constats, tronqué, ou pas écrit du tout se lisait
  « aucun secret », et tous les problèmes de secrets du dépôt étaient résolus, leur triage avec eux ; de
  même pour un rapport d'analyse du code sans ses résultats, un rapport du rapprochement de vulnérabilités
  sans ses correspondances, un rapport IaC d'une forme inconnue, et une sortie du catalogueur qui n'est
  pas un SBOM, qui résolvait tous les problèmes de licence et de fin de vie. Chacun est désormais une étape
  en échec, nommée sur le scan, et laisse ces problèmes tels quels. Une image gitleaks à vous qui n'écrit
  aucun rapport sur un arbre propre (la v8.2.0 le fait ; la v8.5.0 et les suivantes écrivent une liste
  vide) fait maintenant échouer son étape secrets au lieu de la passer. Mettez aussi à jour les agents
  distants : un agent 0.11.0 lit encore un tel rapport comme propre, et seul son SBOM est revérifié par le
  plan de contrôle.
- **La chart Helm transmet le relais de messagerie et l'adresse publique au plan de contrôle.** Elle ne
  transmettait ni l'un ni l'autre : une installation Kubernetes ne pouvait envoyer aucun e-mail — ni
  alerte, ni rapport hebdomadaire, ni rappel de checklist — et ses liens n'avaient pas d'adresse.
  Nouvelles valeurs `mail.*`, `secrets.mailPassword` et `publicUrl`, qui vaut par défaut
  `https://<ingress.host>` ; sans `mail.host`, rien ne change.
- **Les titres, paragraphes, liens et cartes suivent désormais les tailles et espacements que leur donne
  chaque écran** ; les styles globaux du gabarit les écrasaient. Les captures de la documentation française
  montrent les champs de date au format jj/mm/aaaa.
- **Deux instances du plan de contrôle qui démarrent ensemble sur une base vide créent un seul premier
  compte** ; l'une échouait à démarrer, ou, avec des `VECTISPIRE_BOOTSTRAP_USERNAME` différents, un second
  SUPERUSER était créé.
- **Un triage en masse lit ses issues en une requête, et les vérifie et les écrit en une transaction** ; une
  issue modifiée entre-temps par une analyse ou une personne refuse tout le lot en 409
  `issue-changed-meanwhile`. La liste des groupes SCIM ne fait plus une requête par équipe.
- **Les documents CSAF, OpenVEX et CycloneDX exportés, le paquet de preuves et les événements SIEM sont
  datés par l'horloge du plan de contrôle**, à la microseconde qu'il conserve.
- **L'export OpenAPI synthétisé à partir des points d'accès découverts d'un dépôt est du JSON valide quel
  que soit le contenu de ses chemins et résumés**, avec une opération par méthode, et un gestionnaire de
  toutes les méthodes est développé en chacune des méthodes que le chemin ne déclare pas.
- **Un panneau qui ne peut pas se charger le dit désormais, avec la raison donnée par le serveur**, au lieu
  de rester vide — le tableau de bord, la comparaison de SBOM, les agents, l'attestation, l'historique, le
  journal d'audit et la conformité.
- **Les listes de dépôts et d'images se rafraîchissent en arrière-plan pendant un scan**, sans clignoter et
  sans effacer une erreur ; elles sont paginées par 20, et la page en cours est conservée d'un
  rafraîchissement à l'autre.
- **Sur l'écran des politiques de gate, une dérogation dont la cible n'a plus de nom affiche son type dans
  la langue du lecteur** (« Dépôt n° 12 »).
- **Sur la page OWASP, le sélecteur de périmètre et celui du dépôt du rapport sont annoncés par leur
  libellé** (« Périmètre », « Dépôt ») à un lecteur d'écran, sur la grille comme sur la vue hebdomadaire,
  et non plus par la valeur qu'ils affichent.
- **La page `/error`, à laquelle aucun écran ne menait, disparaît** ; l'adresse affiche désormais l'écran
  « Page non trouvée ».
- **Un lien vers un identifiant ouvre les problèmes de cet identifiant et d'aucun autre** : une CVE du plan
  de remédiation, et un identifiant que plusieurs problèmes partagent dans un rapport OWASP, ouvraient la
  liste par une recherche, si bien que `CVE-2021-4428` listait aussi `CVE-2021-44228`. La liste affiche
  l'identifiant en pastille, qui le retire ([problèmes](../guide/issues.md#filtres-a-connaitre)).
- **Un rapport OWASP compte les problèmes derrière un identifiant cité comme la liste qu'ouvre son lien les
  liste**, sans tenir compte de la casse : un identifiant que deux scanners écrivaient dans deux casses en
  comptait un, et son lien menait à ce seul problème quand la liste montrait les deux.
- **Le classement EPSS nomme un dépôt enregistré sans nom par son adresse** (`corp/ledger`), comme tous les
  autres écrans : ses lignes affichaient une cible vide.
- **Une action à fort impact qu'aucune version ne corrige affiche « aucune version corrigée publiée » sur
  le tableau de bord**, comme le plan de remédiation le faisait déjà, au lieu d'une flèche qui ne mène à
  rien. Le document OpenAPI déclare désormais `HighImpactFix.recommendedVersion` comme `string` ou `null`,
  ce que le serveur envoie depuis que le champ ne porte plus « latest-patch » ; la réponse elle-même ne
  change pas.

## 0.11.0 — 25 octobre 2026

La 0.11.0 note une cible sur ce qui est ouvert plutôt que sur son pire constat, analyse chaque cible chaque
semaine, refuse à la barrière une cible que rien n'a examinée, découvre et importe les dépôts d'une forge,
produit des rapports par des plugins signés, et s'installe sur Kubernetes avec une chart Helm. Trois versions
candidates l'ont précédée — `v0.11.0-rc.1`, `rc.2` et `rc.3`, étiquetées le 6, le 12 et le 13 octobre 2026.
Ce qui suit est par rapport à la 0.10.0 ; la 0.10.x n'est plus suivie
([politique de sécurité](https://github.com/asmolabs/vectispire/blob/main/SECURITY.md#versions-suivies)).

### Avant la mise à jour

Chaque point est détaillé plus bas ; voici ce qu'il faut faire avant que la nouvelle image démarre. La
première liste vaut pour toute installation venant de la 0.10.0 ; une installation en `v0.11.0-rc.1` la lit
aussi, puis la seconde.

- **Sauvegardez la base.** Les migrations V65 à V90 s'exécutent au démarrage et n'ont pas de retour
  arrière : revenir à 0.10.0, c'est restaurer cette sauvegarde et le digest de l'image précédente
  ([sauvegarde et restauration](https://github.com/asmolabs/vectispire/blob/main/docs/fr/BACKUP_AND_RESTORE.fr.md)).
- **Mettez à jour chaque agent `delegated` avec le plan de contrôle.** Les secrets sont désormais
  scellés liés à ce qu'ils transportent (`sealed:v2:`), et un agent antérieur à cette version —
  `v0.11.0-rc.1` comprise — n'en reçoit aucun : sa clé de scellement est refusée, et ses scans de dépôts
  portant une clé ou un jeton attendent un exécutant capable de les mener
  ([agents](../administration/agents.fr.md#before-delegating-credentials-pin-the-signing-key)).
- **Avec le profil `with-agent` ou `sso` de la composition, complétez `.env`.** Déclarez
  `VECTISPIRE_AGENT_TOKEN` et `VECTISPIRE_AGENT_SIGNING_KEY` (vides si inutilisées) — l'agent ne démarre plus
  sans ces deux lignes — et réglez `KEYCLOAK_ADMIN_PASSWORD`, qui ne vaut plus `admin` par défaut (*Les
  identifiants de l'agent et le Keycloak d'évaluation*, plus bas).
- **Un pipeline qui interroge la barrière sur une cible pas encore analysée échoue désormais.** De même
  pour une cible dont le dernier scan a échoué. Analysez d'abord, attendez la fin du scan, puis
  interrogez la barrière ; repérez avant la mise à niveau, dans la vue d'ensemble Sécurité, les cibles
  marquées jamais analysées ou dernier scan échoué : chacun de leurs pipelines passera au rouge (*La
  barrière refuse une cible que personne n'a examinée*, plus bas).
- **Vérifiez qui écrit les réglages qui ont changé de mains.** `notification_allow_private_url`,
  `ticket_project` et `ticket_user` reviennent désormais à un administrateur, `evidence_retention_days` au
  gouverneur de la plateforme, et la déclaration d'applicabilité (`GET /api/v1/compliance/soa`) exige la
  lecture de gouvernance. Les valeurs enregistrées sont gardées ; un script qui écrit ces réglages par
  `PUT /api/v1/settings` avec la clé d'un CISO, ou qui lit la déclaration sans lecture de gouvernance,
  reçoit 403. Un `ticket_project` GitHub enregistré autrement que `propriétaire/dépôt` est refusé au
  prochain ticket : corrigez-le (*Trois réglages qu'un CISO pouvait changer ne sont plus les siens* et
  *Quatre écarts d'autorisation fermés*, plus bas).
- **Prévenez les équipes que leurs notes vont baisser.** La formule du score compte les moyennes, les
  basses et chaque issue supplémentaire ; rien n'a changé dans leurs dépôts. Un contrôle qui lit la lettre
  du badge ou le `score` de l'API la verra baisser, et celui qui lit `score` ou `grade` sur
  `GET /api/v1/scorecards/global` ne trouve ni l'un ni l'autre : le portefeuille n'a plus de note unique
  (*Formule du score*, plus bas).
- **Prévenez le SOC que `VECTI-SEC-030` porte désormais la sévérité de l'issue en retard.** Elle valait 6,
  sous le minimum par défaut, si bien qu'aucun dépassement n'atteignait le SOC ; au réglage par défaut, les
  dépassements critiques et élevés arrivent désormais, et une règle qui les attend à la sévérité 6 ne les
  reconnaît plus — reconnaissez la signature (*Autres changements*, plus bas).
- **Attendez-vous à ce que toute cible non planifiée soit réanalysée chaque semaine.** Toutes passent à
  l'intervalle par défaut de l'installation à la mise à niveau, réparties sur la semaine. Dimensionnez les
  workers ou les agents en conséquence, passez en **manuel uniquement** les cibles qui doivent le rester,
  ou mettez `scan_default_interval_days` à `0` pour garder l'ancien comportement partout. Un script qui
  coupait les réanalyses en envoyant un intervalle de `0` doit envoyer `scanManualOnly: true` : `0` signifie
  désormais le défaut (*Toute cible sans planification est désormais analysée chaque semaine*, plus bas).
- **Sur MySQL, démarrez le serveur avec `--max-allowed-packet=160M`.** Au paquet par défaut de 64 Mio,
  l'export d'un rapport est gardé jusqu'à environ 32 Mio et son document environ 31 Mio ; la composition
  livrée le fait désormais ([plugins de rapport](../administration/report-plugins.fr.md)).
- **Une intégration qui crée des dépôts sans condition doit lire un 409 comme « déjà là ».** Une cible
  dépôt n'est enregistrée qu'une fois (*Une cible dépôt n'est enregistrée qu'une fois*, plus bas).
- **Lisez la file d'approbation pour les demandes qu'un refus de tracker y a placées.** Jusqu'à la
  0.11.0, un ticket fermé comme *Won't Fix*, *Declined*, *Rejected*, *Risk Accepted*, *Withdrawn* ou *not
  planned* chez GitHub était mis en file comme `not_affected` avec `inline_mitigations_already_exist`, et
  ces demandes restent telles quelles. Listez les issues en `pending_approval` qu'un webhook a mises en
  file — `select id, triaged_by, triage_comment from t_issue where triage_status = 'pending_approval' and
  triaged_by like '%_webhook'` — et refusez celles qui viennent d'un refus : décidez-les comme *Ne sera
  pas corrigé — risque accepté*, avec une date de réexamen, si c'est ce qu'elles sont. Rien ne les
  convertit pour vous : seule une personne sait distinguer, dans le commentaire, un refus d'un faux
  positif. Une demande mise en file désormais s'accorde telle quelle : l'approuver avec un autre statut qui
  règle, à la main ou par script, répond 409 `triage-approval-differs` (*Ne sera pas corrigé — risque
  accepté*, plus bas).
- **Réimportez le catalogue de règles si votre jeu actif en vient avec `generic`.** Ce jeu garde les règles
  qui font double emploi avec gitleaks, et chaque clé divulguée sa jumelle *SAST*, jusqu'à ce que le
  catalogue soit importé de nouveau et le nouveau jeu activé ; l'activation compte, règle par règle, les
  issues ouvertes que ces règles laissent derrière elles avant d'aller plus loin
  ([jeux de règles](../administration/rule-sets.md#depuis-le-catalogue-amont)).
- **Levez l'indicateur de changement de mot de passe des comptes créés par l'annuaire SCIM.** Ils le
  gardent après la mise à niveau et restent retenus sur l'écran de changement de mot de passe après une
  connexion unique ; le journal d'audit les nomme (`USER_CREATED`, « SCIM provisioned account: … »), et
  `update t_user set must_change_password = false where username = '…'` le lève pour chacun. L'annuaire ne
  lie plus un compte privilégié existant à un sujet du fournisseur d'identité sans
  `VECTISPIRE_OIDC_LINK_PRIVILEGED_ACCOUNTS=true` — et jamais un compte à second facteur local
  ([authentification unique](../administration/sso.fr.md)).
- **Prévenez les administrateurs que changer leur propre mot de passe révoque les clés d'API qu'ils ont
  émises.** La clé de pipeline de l'un d'eux cesse de fonctionner au changement : émettez-en une nouvelle.

Depuis `v0.11.0-rc.1`, en plus :

- **Les migrations V84 à V90 s'exécutent** — V83 et V85 ne sont pas utilisées ; la sauvegarde ci-dessus
  vaut. Depuis `v0.11.0-rc.2`, V89 et V90 s'exécutent. Depuis `v0.11.0-rc.3`, aucune migration ne
  s'exécute.
- **Chart Helm avec des agents dans le cluster : complétez les valeurs, sinon `helm upgrade` refuse de la
  rendre.** Ajoutez `ports` à chaque entrée de `agents.networkPolicy.allowTo` — `[{port: 443}]` pour le
  contrôleur d'ingress ; donnez aux agents un sélecteur de nœud (ou une affinité de nœud obligatoire) et
  des tolérances à eux, ou réglez `agents.acknowledgeSharedNodes` ; et passez `agents.controlPlaneUrl` en
  `https://` ([installation](../getting-started/installation.fr.md#kubernetes) ; *Le chemin d'un agent du
  cluster vers l'Ingress*, plus bas).
- **Ne vous fiez pas au `.sig` d'un paquet de rapport produit par une version candidate** : il était fait
  avec la clé de la plateforme sur des octets écrits par un plugin (*Le fichier d'un plugin de rapport
  n'est plus signé brut*, plus bas). Et les documents de rapport produits avant cette version n'ont
  enregistré aucune cible : seul les lit qui voit tout.

Depuis `v0.11.0-rc.3`, deux changements peuvent refuser ce que rc.3 acceptait :

- **Un import depuis une forge refuse un dépôt dont l'URL de clonage n'est pas sur l'hôte de la
  connexion.** Si les clones SSH de la forge passent par un autre hôte que son adresse web, importez en
  HTTPS, sinon l'aperçu liste ces dépôts comme refusés (*Un import depuis une forge ne clone que depuis
  l'hôte de sa connexion*, plus bas).
- **Dans un pod, une destination qu'un administrateur règle se voit refuser les ports 6443 et 10250 sur
  toute adresse.** Une forge, un webhook, un serveur d'IA ou un collecteur SIEM joint sur l'un d'eux ne
  répond plus (*Kubernetes : dans un pod…*, plus bas).

Et la composition nomme désormais MySQL et Keycloak par empreinte — les serveurs que désignaient `mysql:8` et
`26.0`, tirés une fois ; lisez l'entrée avant de la démarrer sur un hôte qui gardait un `mysql:8` plus ancien
(*La composition nomme son MySQL et son Keycloak par empreinte*, plus bas).

### Changements visibles d'une intégration

#### Formule du score (0.11.0)

**Les notes baissent parce que les moyennes, les basses et chaque issue de plus comptent désormais —
pas parce qu'un projet s'est dégradé. Rien n'a changé dans vos dépôts.** La formule du scorecard est
remplacée, partout à la fois — les fiches, les scorecards de projet et de solution, le classement du
tableau de bord et la pastille publique —
([décision 0036](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0036-the-posture-score-formula.md),
[comment elle est calculée](../guide/repositories.fr.md#comment-la-note-du-scorecard-est-calculee)).

- **Le score vaut `100 × e^(−points de risque / 55)`, arrondi et jamais moins de 1**, sur des **points de
  risque** qui pèsent ce qui est ouvert : 25 une issue activement exploitée (CISA KEV, quelle que soit sa
  sévérité, compté dans cette classe seulement), 10 un critique, 4 un haut, 0,5 un moyen, 0,125 un bas, 4
  une licence interdite. **Toute issue exploitée plafonne le score à 54 (D).** Il n'y a plus de bonus
  pour un scan terminé. Les seuils ne changent pas. L'ancienne formule — cent moins 25 par KEV en plus de
  sa sévérité, 8 par critique, 4 par haut, 5 par licence, plus 5 pour un scan — atteignait 0 à vingt-sept
  hautes et lisait cinquante ou cinq cents moyennes à 100, A+. Quelques chiffres, avant → après : un
  critique 97 A+ → 83 B ; un critique exploité 72 B → 54 D ; cinquante moyennes 100 A+ → 63 C ; une
  licence interdite 100 A+ → 93 A ; vingt-sept hautes 0 F → 14 F. Sur les onze cibles semées de la
  comparaison, huit changent de note et aucune ne monte.
- **Un nouveau champ, `riskPoints`**, sur `GET /api/v1/scorecards/repositories/{id}` et
  `…/containers/{id}`, sur le `scorecard` de `GET /api/v1/projects/{id}/compliance` et
  `…/solutions/{id}/compliance`, et sur chaque ligne du classement de maturité
  (`GET /api/v1/dashboard/posture-analytics`, `targetScoreboard[].riskPoints`) — `null` exactement quand
  le score l'est. Routes authentifiées seulement.
- **La pastille publique (`GET /api/v1/scorecards/badges/{token}.svg`) garde son aspect et ne montre que
  la lettre** — elle peut changer de lettre et de couleur à son prochain rendu sans que personne ait
  touché au dépôt, et ne montre jamais les points de risque : ils diraient à quiconque lit le README
  combien est ouvert, et quand cela bouge.
- **Un projet ou une solution est noté par son maillon le plus faible** : son score est le plus bas
  score des cibles analysées que vous en voyez, chacune telle que sa propre fiche la calcule, plafonné à
  la part analysée comme avant, et la fiche nomme cette cible dans un nouveau champ, `weakestTarget`
  (nature, id, nom, son propre score, sa note et ses points de risque). C'était la formule sur le backlog
  cumulé de la portée, qui notait une portée d'autant plus bas qu'elle tenait de cibles. Ses
  `riskPoints` sont tout le backlog ouvert de la portée, chaque issue et chaque licence une fois.
- **Le `licenseViolationCount` d'une portée peut baisser.** Un projet ou une solution qui range à la
  fois une image et un dépôt nommés par un même scan comptait deux fois les licences interdites de ce
  scan ; chacune est comptée une fois désormais, comme le faisait déjà la fiche de chaque cible.
- **`GET /api/v1/scorecards/global` change de forme : le portefeuille n'a pas de note unique.** Une note
  sur tout un parc est écrasée par sa taille, ou est la note de la pire cible sous un autre nom. La
  réponse porte désormais `grades` — chaque note, `NO_DATA` compris, avec le nombre de cibles que vous
  voyez qui la lisent —, `weakestTarget` (`null` quand aucune n'est analysée), `riskPoints`,
  `totalTargets`, `observedTargets` et les compteurs ouverts (`openCriticalCount`, `openHighCount`,
  `openKevCount`, `overdueCount`, `licenseViolationCount`). **`score`, `grade`, `targetId`, `targetKind`,
  `targetName`, `hasAttestation` et `recommendations` ont disparu**, plutôt que d'être gardés avec un sens
  qu'ils n'ont plus : une intégration qui applique un seuil au `score` global doit passer à la
  répartition ou à la cible la plus faible. Le tableau de bord montre les trois mêmes chiffres.
- **Le classement départage les ex æquo par les points de risque**, le moins d'abord, là où il gardait
  l'ordre de la liste : dans F tous les scores sont maintenus à 1, et à 54 le plafond de l'exploité en
  tient beaucoup.
- **`GET /api/v1/dashboard/trends` gagne `score_formula_changed_on`**, le jour (ISO, UTC) où les notes de
  cette installation ont changé de formule — le jour de sa mise à jour, écrit par la migration V69 quand
  l'installation avait déjà un scan terminé ; `null` sur une installation neuve. Le graphique de tendance
  du tableau de bord trace une ligne datée à ce jour, et le dit en toutes lettres sous le graphique.
- **Rien d'autre ne lit la note.** La barrière, les événements SIEM, les notifications, les tickets et les
  exports (SARIF, VEX, CSAF, CycloneDX) sont inchangés. Un contrôle de votre côté qui lit la lettre de la
  pastille ou le `score` de l'API — « pas pire que B » — la verra baisser.

#### Toute cible sans planification est désormais analysée chaque semaine (0.11.0)

**Un dépôt ou une image sans intervalle de scan ni expression cron n'était analysé que si quelqu'un le
demandait — et c'est ce que recevait toute cible ajoutée par les formulaires. Il est désormais réanalysé
selon l'intervalle par défaut de l'installation, sept jours sauf si un administrateur le change.** Pour
garder une cible telle qu'elle était, passez-la en **manuel uniquement**. Les cibles laissées sans
planification exprès ne se distinguent pas de celles que personne n'a planifiées : toutes passent au
défaut à la mise à jour.

- **Un nouveau réglage, `scan_default_interval_days`** (*Réglages › Scanners › Planification des
  analyses*, défaut `7`, `0` pour aucun défaut — l'ancien comportement, pour toutes les cibles à la fois)
  ([comment](../administration/settings.md#default-rescan-interval)).
- **Les passages sont étalés sur la semaine.** Chaque cible sous le défaut a son propre moment dans
  l'intervalle, dérivé de son type et de son identifiant, et le garde d'une semaine à l'autre : mille
  cibles arrivent à quelques-unes par heure, jamais toutes ensemble. La migration V70 inscrit la mise à
  jour comme leur dernier passage programmé, si bien que le premier passage tombe dans la semaine qui suit
  la mise à jour et non dans sa première minute — `lastScheduledScanAt` de ces cibles vaut l'instant de la
  mise à jour jusque-là. L'intervalle ou l'expression cron propre à une cible se comporte exactement comme
  avant.
- **De nouveaux champs sur `GET /api/v1/repositories` et `GET /api/v1/containers`**, et dans ce que
  renvoient leur création et leur mise à jour : `scanManualOnly` (booléen) et `schedule`, la planification
  en vigueur telle que le serveur la décide — `mode` (`manual`, `cron`, `interval` ou `default`) et
  `intervalMinutes` (l'intervalle effectif sous `interval` et `default` ; `null` pour une expression cron,
  pour manuel uniquement et pour `default` quand l'installation n'en a pas). Lisez `schedule` plutôt que de
  recalculer la priorité à partir des autres champs.
- **`scanManualOnly` sur `POST`/`PATCH /api/v1/repositories` et `/api/v1/containers`.** `true` vide
  l'intervalle et l'expression ; envoyé avec un intervalle positif ou une expression, il est refusé (400) ;
  une mise à jour qui nomme un intervalle ou une expression sans lui quitte le manuel. **Un intervalle de
  `0` signifie désormais « non défini » — le défaut — et non plus « manuel uniquement »**, et il est stocké
  `null` (`scanIntervalMinutes` se relit `null`, pas `0`). Un intervalle négatif est refusé (400). Un script
  qui coupait les réanalyses en envoyant `0` doit envoyer `scanManualOnly: true`.
- **Un passage programmé est sauté tant qu'un scan de la cible est en cours**, comme il l'était tant
  qu'un scan attendait. Le bouton *Scanner* ne change pas.
- **Une règle de checklist d'analyse des dépendances qui exige une planification correspondante compte
  le défaut** : un dépôt sans planification propre, sous un défaut hebdomadaire, satisfait désormais un
  âge maximal de sept jours ; un dépôt en manuel uniquement jamais.

#### Une cible dépôt n'est enregistrée qu'une fois (0.11.0)

**Ajouter un dépôt qui est déjà une cible — le même dépôt, sur la même branche et le même sous-chemin —
est refusé, comme une modification qui ferait d'une cible le doublon d'une autre.** Deux URL désignent le
même dépôt une fois écartés le schéma, la partie utilisateur, le port, la casse, un `.git` final et les
barres obliques finales : `git@gitlab.example.org:Team/API.git` et `https://gitlab.example.org/team/api`
n'en font qu'un ([la règle et ses limites](../guide/repositories.fr.md#filed-once)). Un autre répertoire
d'un monodépôt, ou une autre branche, est une autre cible et reste accepté.

- **`POST /api/v1/repositories` et `PATCH /api/v1/repositories/{id}` répondent 409** avec le type
  `urn:vectispire:problem:target-already-registered`. Quand l'appelant voit la cible existante, le
  problème porte son identifiant dans `existingRepositoryId` et le `detail` la nomme ; sinon ni l'un ni
  l'autre — le refus dit que la cible existe, rien de laquelle. Un script qui enregistre des dépôts sans
  condition doit lire ce 409 comme « déjà là ».
- **La base l'impose** (migration V73, un index unique sur une empreinte des trois parties) : deux
  créations qui passent la vérification en même temps donnent une cible et un 409, sur PostgreSQL comme
  sur MySQL.
- **Rien n'est supprimé à la mise à jour.** Les cibles déjà enregistrées deux fois continuent de
  fonctionner, sont analysées et restent modifiables ; la plus ancienne de chaque paire est celle à
  laquelle un nouvel enregistrement est comparé. **Une nouvelle route, `GET
  /api/v1/repositories/duplicates`** (administrateurs), les liste, groupées, la plus ancienne d'abord,
  chaque cible sous la forme de la liste des dépôts, pour les [fusionner à la main](../guide/repositories.fr.md#filed-twice-before-this-release).
- **Jusqu'au premier tour de maintenance après la mise à jour** (trente secondes après le démarrage,
  puis toutes les heures), les cibles enregistrées avant elle ne sont pas encore comparées, et le doublon
  de l'une d'elles est accepté — puis listé par la route ci-dessus.

#### La barrière refuse une cible que personne n'a examinée (0.11.0)

**`POST /api/v1/gate` répondait `passed: true` pour une cible jamais analysée** : son backlog était vide,
et un backlog vide satisfait toutes les politiques — alors que la vue d'ensemble Sécurité disait de la
même cible qu'elle n'avait jamais été analysée. Elle échoue désormais, fermée, comme la vue d'ensemble
l'a toujours dit ([la règle](../integrations/ci-gate.md#a-target-nobody-examined-never-passes)).

- **Une nouvelle règle de violation, `observation`**, à côté de `kev`, `severity` et `coverage` :
  `passed: false`, HTTP 200 comme pour tout refus, sans `issueId`, `identifier`, `severity` ni `package`,
  et une `reason` qui nomme le cas — aucun scan de la cible n'est terminé (jamais analysée, ou seulement
  des scans en attente ou en cours), ou le dernier scan terminé a échoué. Elle vient en tête de
  `violations`. Un client qui aiguille sur `rule` rencontre une quatrième valeur.
- **Aucun indicateur de politique ni aucun champ de requête ne l'assouplit.** `include_triaged`,
  `fixable_only` et le seuil restreignent toujours les constats pris en compte, et cette règle n'en
  prend aucun.
- **Le verdict repose sur le dernier scan *terminé*.** Un scan en attente ou en cours n'est pas encore
  un examen : une cible réanalysée selon sa planification garde le verdict de son scan précédent pendant
  que le suivant tourne, et une cible dont le premier scan tourne encore échoue.
- **Enregistré et signalé comme tout refus** : une ligne au registre des verdicts, comptée dans son taux
  de refus, et un événement `SECURITY_GATE_FAILED` vers le SIEM.
- **La vue d'ensemble Sécurité et tout ce qui en dépend concordent avec la route.** Une cible jamais
  analysée ou dont le dernier scan a échoué y est désormais *en échec* (`passed: false`, la même
  violation) ; `failingCount` la compte — sur `GET /api/v1/security/overview`, parmi les cibles en échec
  du tableau de bord et dans le rapport de posture hebdomadaire — et le PDF de posture la lit en échec. Le
  champ `observation` et les comptes jamais analysées et dernier scan échoué ne changent pas ; les
  chiffres de conformité écartaient déjà ces cibles des cibles conformes et ne bougent pas.
- **Le script de barrière, l'action GitHub et le modèle GitLab ne changent pas** : ils sortent déjà en
  1 sur `passed: false` et affichent la raison de la violation.

#### Ne sera pas corrigé — risque accepté (0.11.0)

**Un cinquième statut de triage, `will_not_fix` : la vulnérabilité s'applique, et l'équipe a décidé de
ne pas la corriger.** Un risque accepté n'avait pas de statut à lui et s'enregistrait comme
`not_affected`, avec une justification choisie dans une liste où aucune n'est vraie d'un produit exposé
— et signée comme telle dans les documents VEX ([décision 0041](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0041-will-not-fix-is-not-not-affected.md),
[accepter un risque](../guide/issues.fr.md#accepting-a-risk)).

- **`POST /api/v1/issues/{id}/triage` et `POST /api/v1/issues/triage` acceptent `will_not_fix`.** Il
  **exige** `expires_in_days` (1–3650), sa date de réexamen, et **refuse** une `justification` (400) :
  chaque justification VEX dit pourquoi un produit n'est pas exposé. Il règle l'issue comme
  `not_affected` et `fixed` — il cesse de faire échouer la barrière et sort des chiffres de risque —, il
  passe donc par la double validation comme eux, et revient à `under_review` à sa date de réexamen.
  `GET /api/v1/issues?triage_status=will_not_fix` filtre dessus. Un client qui aiguille sur
  `triageStatus` rencontre une nouvelle valeur.
- **C'est une exception.** `GET /api/v1/exceptions` la liste, la compte dans `granted`, et elle se revoit
  — confirmée, prolongée ou révoquée — comme une levée.
- **Les documents VEX disent que le produit est exposé.** CycloneDX `exploitable` avec la réponse
  `will_not_fix`, OpenVEX `affected` avec l'action statement « Will not fix: … », CSAF `known_affected`
  avec une remédiation `no_fix_planned`. SARIF la marque supprimée, comme les autres statuts réglés.
- **Chaque format VEX lit désormais un triage par une seule table**
  ([comment un triage se lit en VEX](../guide/exports.fr.md#comment-un-triage-se-lit-en-vex)) :
  `pending_approval` est *en cours d'investigation* partout, un `not_affected` sans justification est
  *en cours d'investigation* au lieu d'en recevoir une, une issue résolue est `fixed`, et les
  justifications CycloneDX s'écrivent dans le vocabulaire de CycloneDX (`code_not_present`,
  `code_not_reachable`, `requires_environment`, `protected_by_mitigating_control`). Un consommateur qui
  compare les documents d'avant et d'après la mise à niveau voit changer des déclarations sur des issues
  que personne n'a touchées : ce sont les corrections plus bas.
- **Le webhook de ticket propose `will_not_fix` pour un refus** — Jira *Won't Fix*, *Declined*,
  *Rejected* ; ServiceNow *Won't Fix*, *Risk Accepted*, *Withdrawn* ; GitHub *not planned* ; GitLab
  *wontfix* —, sans justification et avec une date de réexamen proposée à quatre-vingt-dix jours, que
  l'approbateur remplace par la sienne. Un refus était mis en file comme `not_affected` avec
  `inline_mitigations_already_exist`, une atténuation dont le tracker n'avait jamais parlé, et que les
  documents signés auraient portée une fois la demande approuvée ; et le *not planned* de GitHub, sa seule
  façon de fermer sans avoir terminé, qui ne dit rien de l'atteignabilité, comme `not_affected` avec
  `vulnerable_code_not_in_execute_path`. Seul un faux positif explicite est encore proposé comme
  `not_affected` ([le webhook entrant](../integrations/ticketing.fr.md#inbound-webhook)).
- **Une demande en attente d'approbation dit ce qu'elle demande, et s'accorde telle quelle.** Une demande
  gardait sa justification, son commentaire et sa date de réexamen et perdait son statut, et l'approbateur
  en choisissait un : le *Won't Fix* d'un tracker pouvait être accordé en `not_affected`, et le VEX signé
  disait alors « non exposé ». La demande garde désormais son statut (migration V88). Chaque forme d'issue
  (`GET /api/v1/issues`, `GET /api/v1/issues/{id}`, la réponse d'un triage) gagne `triageRequestedStatus`
  — `not_affected`, `will_not_fix` ou `fixed` tant que `triageStatus` vaut `pending_approval`, null sinon —
  et `GET /api/v1/exceptions` gagne `requested_status` sur chaque entrée. Approuver avec un autre statut qui
  règle reçoit **409** de type `urn:vectispire:problem:triage-approval-differs` avec le membre
  `requestedStatus` ; un approbateur en désaccord refuse la demande (`under_review` ou `affected`) puis
  décide
  ([accordée telle que demandée, ou refusée](../administration/four-eyes.fr.md#granted-as-asked-or-turned-down)).
  La fenêtre de triage s'ouvre sur le statut demandé et la date de réexamen proposée, qu'elle vidait. Les
  demandes mises en file avant la mise à niveau n'ont enregistré aucun statut, et s'accordent comme
  l'approbateur le choisit.
- **Un webhook ne bouge plus une issue qu'une personne a réglée** (`not_affected`, `will_not_fix`,
  `fixed`). La parole du tracker est inscrite au journal d'audit ; quand elle contredit la décision,
  l'entrée est `TRIAGE_CONTRADICTED_BY_TRACKER`, signalée au SIEM comme `VECTI-SEC-037`
  ([catalogue](../integrations/siem.fr.md#catalogue-des-evenements)).
- **La description du réglage de double validation** nomme désormais les trois statuts qu'il couvre :
  `NOT_AFFECTED`, `WILL_NOT_FIX` ou `FIXED`.

#### Autres changements

- **Le webhook des tickets synchronise chaque issue qui porte le ticket, et répond `issueIds`.** Une
  référence sur deux issues — un ticket attaché à plusieurs constats, ou un numéro GitLab ou GitHub
  enregistré avec et sans son `#` — faisait répondre `500` à `POST /api/v1/tickets/webhook/{provider}` à
  chaque livraison. Chacune est désormais synchronisée, et la réponse gagne `issueIds`, toutes les issues
  synchronisées, de la plus ancienne à la plus récente ; `issueId` reste, la première d'entre elles
  ([webhook entrant](../integrations/ticketing.fr.md#inbound-webhook)).
- **SCIM répond à un filtre non pris en charge `400 invalidFilter`, plus par tous les comptes.**
  `GET /scim/v2/Users` évalue `userName eq "…"` et `externalId eq "…"` ; tout autre filtre —
  `emails[value eq "…"]`, un `and`, `co`, une valeur sans guillemets — renvoyait la liste entière, qu'un
  annuaire cherchant un compte avant de le créer lisait comme sa correspondance. Il répond désormais `400`
  dans le schéma d'erreur de SCIM avec `scimType: invalidFilter` (RFC 7644 §3.4.2.2). Un annuaire qui
  n'envoie que ces deux filtres, ou aucun, ne voit aucune différence
  ([authentification unique](../administration/sso.fr.md#provisioning-from-the-directory-scim)).
- **Un triage peut recevoir 409 `issue-changed-meanwhile`.** `POST /api/v1/issues/{id}/triage`,
  `POST /api/v1/issues/triage` et `POST /api/v1/exceptions/{issueId}/reviews` refusent une décision quand un
  scan ou une autre décision a écrit l'issue entre la lecture et l'écriture de la requête — le `type` du
  problème est `urn:vectispire:problem:issue-changed-meanwhile`, et rien n'est consigné. Relisez l'issue et
  refaites la décision (*Un triage fait pendant un scan n'est plus perdu*, plus bas).
- **`VECTI-SEC-030` (délai de remédiation dépassé) est aussi sévère que le constat en retard** : sévérité
  CEF 8 pour un constat critique, 7 pour un élevé, 5 pour un moyen, 3 pour un faible — dans l'en-tête CEF
  comme dans la priorité syslog, et c'est elle que la sévérité minimale compare. Elle valait 6, sous le
  minimum par défaut (Élevée) : avec la configuration d'usine, aucun dépassement n'atteignait le SOC, pas
  même celui d'un constat critique. Au réglage par défaut, les dépassements critiques et élevés arrivent
  désormais ; Moyenne laisse aussi passer les moyens. **Une règle du SOC qui attend la sévérité 6 pour ces
  alertes doit être adaptée** — reconnaître `VECTI-SEC-030` à sa signature, et lire la sévérité comme
  celle du constat. Un événement déjà en file à la mise à jour part à 6, tel qu'il a été émis —
  [Export SIEM](../integrations/siem.fr.md#catalogue-des-evenements).
- **Plus aucune requête n'est réessayée dans le dos de son appelant.** Le client HTTP par lequel passe
  chaque appel sortant renvoyait un GET après un 429 ou un 503, en dormant ce que disait `Retry-After`, et
  après une connexion coupée ; un webhook, un ticket, une revue de modèle ou un téléchargement de catalogue
  qui échoue une fois échoue désormais une fois, et un appelant qui réessaie le dit.
- **La CLI est un asset de version, signé comme le script de barrière.** `vectispire-cli.sh` est joint à
  la version avec son paquet Sigstore, `vectispire-cli.sh.cosign.bundle`, signé par `release.yml` au tag
  et vérifié par la même commande `cosign verify-blob` que le jar ; les notes de version affichent son
  SHA-256. Les snippets de la fenêtre **CI/CD** de *Dépôts* et de
  [`CI_CD_INTEGRATION`](https://github.com/asmolabs/vectispire/blob/main/docs/fr/CI_CD_INTEGRATION.fr.md#-obtenir-la-cli)
  téléchargeaient `scripts/vectispire-cli.sh` à l'URL brute du dépôt au tag et l'exécutaient sans
  contrôle ; ils téléchargent désormais l'asset, comparent son SHA-256 à celui qu'ils épinglent, et
  arrêtent le job sur tout autre fichier. Un pipeline copié d'un ancien snippet continue de fonctionner,
  sans contrôle, jusqu'à ce qu'il soit remplacé — la 0.10.0 et les précédentes ne portent pas d'asset CLI.
- **Publier une version de modèle de checklist peut répondre 409 `checklist-template-unrenderable`.**
  `POST /api/v1/checklist-templates/{slug}/versions/{ordinal}/publish` remplit le classeur une fois,
  comme le ferait une approbation, et refuse un classeur dans lequel aucune approbation ne pourrait
  écrire ; le membre `cells` du problème nomme chaque cellule en cause (`cell`, `kind` — `shared` ou
  `array` — et `range`). Voir *Corrigé* plus bas.
  **Ouvrir une checklist de projet, ou la faire passer à une autre version, peut répondre 409
  `checklist-version-unrenderable`** — `POST /api/v1/projects/{id}/checklists` exécute le même essai sur
  la version d'ouverture ou d'arrivée, et refuse une version publiée plus tôt qui y échoue, avec le même
  membre `cells` ; rien n'est enregistré ni consigné. La version quittée n'est jamais essayée.
  `GET /api/v1/projects/{id}/checklists/offered` liste toujours une telle version, avec un nouveau membre,
  `unrenderable` — le `detail` de l'essai et les mêmes `cells` —, null sur toute autre version.
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
- **Le rapport OWASP est dans la section *Sécurité* du menu**, après *Chemins d'attaque*, et non plus sous
  *Conformité & preuves* : il lit les constats, comme les écrans de Sécurité. Même page, mêmes accès.
- **Le rapport OWASP porte ce que son écran relie** (`GET` et `POST`
  `/api/v1/repositories/{id}/owasp-review`). Un bloc `CATEGORY` gagne `category`, le code Top 10:2021 que
  nomme son titre (`A01`…`A10` ; `null` sur tout autre bloc). `categoryFindings` donne les dix codes, un
  zéro compris, chacun avec le nombre d'issues ouvertes du dépôt au triage non réglé rangées dans la
  catégorie — le `total` de `GET /api/v1/issues?repository_id=…&owasp_category=…&unsettled=true` pour le
  même appelant, maintenant, et non à l'analyse revue. `issueLinks` associe chaque identifiant d'un
  constat montré au modèle aux issues ouvertes du dépôt qui portent exactement cet identifiant
  maintenant (`issueId` s'il y en a une, `null` s'il y en a plusieurs ; `count`) ; un identifiant
  qu'aucune issue ouverte ne porte est omis, et un identifiant que la prose du rapport cite sans que le
  modèle l'ait vu n'y figure jamais. Un rapport écrit avant cette version n'a consigné aucun ensemble
  d'identifiants et lit `issueLinks: null`. La migration V84 ajoute `t_ai_review_result.evidence_identifiers`.
- **Une règle de checklist a un sixième type, `component_present`, et une mesure une nouvelle raison,
  `inventory_absent`.** `kind` sur la route des règles et dans `boundRule`, `ruleKind` sur une mesure,
  peuvent valoir `component_present` ; ses `components` portent un `purlPrefix` et aucune `versions`. Une
  entrée de `component_versions` peut être une plage Maven (`[1.17,2.0)`). Un client qui aiguille sur
  `kind` ou `reason` doit traiter les nouveaux jetons ; un client qui les ignore lit toujours une règle et
  une absence de données. Chaque règle liée auparavant garde sa forme canonique et son empreinte de
  contenu ([Composants](../administration/checklist-templates.md#composants-presence-versions-et-plages)).
- **Une ligne `component_versions` n'échoue plus sur une analyse dont la rétention a purgé le SBOM.** Elle
  échouait avec « its newest analysed scan stored no SBOM » — et Vectispire répondait *non* — alors que
  l'inventaire laissé par l'analyse listait encore chaque paquet. Elle lit désormais cet inventaire, comme
  `component_present`, et un inventaire vide à côté d'une charge purgée est une absence de données,
  `inventory_absent`, qui retire le *non* automatique. `dependency_analysis` exige toujours le SBOM
  conservé : c'est ce qu'elle mesure.
- **Une règle de checklist a un septième type, `change_review`, et une mesure quatre raisons et une source de
  plus.** Le `kind` d'une règle peut valoir `change_review`, avec `minimumApprovals`, `windowDays` et une
  `branch` facultative sur `ChecklistRuleForm` (sa part est `minimumRatio`, comme le minimum de la
  couverture) ; une `reason` peut valoir `forge_unlinked`, `forge_unreadable`, `review_incomplete` ou
  `no_change_merged`, le `status` d'un dépôt de même, et sa `source` `forge_review`. Seulement sur une ligne
  liée au nouveau type ; un client qui traite ces vocabulaires de façon exhaustive a besoin des nouveaux
  membres.
- **Une règle de tests peut nommer plusieurs motifs de suites, `suitePatterns`, chacun devant être satisfait** —
  tests unitaires **et** fonctionnels sur une même ligne ([les types de règles](../administration/checklist-templates.fr.md)).
  `ChecklistRuleForm` gagne `suitePatterns` (2 à 10 motifs), indiqué à la place de `suitePattern`, jamais à
  côté ; chaque motif est jugé sur ses propres suites, avec le même `minimumTests`. Une règle à un seul motif
  s'écrit `suitePattern` exactement comme avant — sa forme canonique et son empreinte inchangées, si bien
  qu'aucune ligne liée n'est marquée modifiée.
- **Un import de couverture répond `packagesState`**, et une mesure de checklist a trois raisons de
  plus. `POST` et `GET /api/v1/repositories/{id}/coverage-imports` portent `packagesState` — `kept`,
  `too_many`, `path_refused`, `inconsistent`, ou `null` pour un import accepté avant cette version — et la
  `reason` d'une règle peut valoir `packages_unrecorded`, `packages_not_kept` ou `scope_matches_nothing`,
  seulement sur une ligne de couverture [limitée à un périmètre de paquets](../administration/checklist-templates.fr.md#couverture-sur-un-perimetre-de-paquets).
  Un client qui distingue les valeurs de `reason` doit les traiter ; celui qui ne les connaît pas lit
  toujours une absence de données. Le formulaire d'une règle (`boundRule`, la route des règles) gagne un
  `scope` facultatif ; une règle qui n'en a pas garde sa forme canonique et son empreinte de contenu. Le
  schéma V71 ajoute une colonne et une table, rien à faire.
- **L'export de projet passe au schéma 1.1** : chaque `inventory.components[]` gagne `sources` — `build`,
  `scanner` ou les deux, qui a listé le composant sur ses cibles. Un champ facultatif, selon la règle du
  schéma ; un plugin écrit pour 1.0 lit 1.1 comme il lisait 1.0. Les occurrences de
  `GET /api/v1/inventory/search` gagnent `source` (`scanner`, `build`, `both`) et `scannerVersion`, et les
  composants consolidés du projet (`GET /api/v1/projects/{id}/components`) `sources`. Les `kinds` d'une
  source peuvent désormais contenir `sbom` ; un client qui les liste doit montrer tel quel un type qu'il
  ne connaît pas, comme le fait l'écran.
- **Un refus de plugin a une troisième raison, `registry_authentication_required`**, et une mesure de
  checklist une raison assortie, `plugin_registry_authentication_required` : l'image du plugin déclare
  un signataire, et son registre n'a pas laissé lire la signature. Un client qui distingue les valeurs
  de `refusal` ou de la `reason` d'une mesure doit traiter la nouvelle ; celui qui ne la connaît pas lit
  toujours un refus.
- **L'historique de triage d'une issue reçoit des entrées d'origine `reopen`**, dans
  `GET /api/v1/issues/{id}` (`decisions`) et dans l'historique d'une cible
  (`GET /api/v1/history/repositories/{id}`), avec un nouveau champ, `previousResolvedAt` — `null` sur
  toute autre entrée. Leur `actor` est `null`, comme sur une `expiry`. Le CSV de l'historique reçoit une
  dernière colonne, `decision_previous_resolved_at` ; le compte `decisions` d'une cible n'inclut pas les
  réouvertures.

### Nouveautés

- **Kubernetes : une chart Helm** dans `deploy/helm/vectispire/`
  ([installation](../getting-started/installation.md#kubernetes),
  [décision 0038](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0038-deploying-on-kubernetes.md)).
  - **Ce qu'elle fait tourner.** Le plan de contrôle par empreinte, contre un MySQL externe, ses secrets
    en fichiers, une racine en lecture seule, des mises à jour `Recreate` et un Ingress. Elle ne lance
    aucun conteneur : chaque scan va à un agent, et les plugins de rapport répondent
    `409 report-executor-unavailable` sur Kubernetes pour l'instant.
  - **Où tournent les agents.** Hors du cluster sur un hôte Docker (recommandé, la chart n'y déploie
    rien), ou, sur option, dans le cluster en pods avec un sidecar `docker:dind` privilégié sur des
    nœuds à eux. La variante rootless ne se rend que sur acquittement, parce qu'elle ne scanne pas.
  - **Dans un namespace qui vous est attribué.** Rien de ce que produit la chart n'est à l'échelle du
    cluster. Les agents peuvent rester dans le namespace de la release (`agents.namespace: ""`,
    `agents.createNamespace: false`) ; leur pod privilégié n'est alors admis que si le niveau Pod
    Security de ce namespace le permet.
  - **Ce qu'elle refuse de rendre.** `trustedProxies` sans `networkPolicy.enabled`, puisque n'importe
    quel pod pourrait sinon appeler le pod en direct et annoncer n'importe quelle adresse de client ; des
    agents sans clé de signature épinglée, sans rien dans `agents.networkPolicy.excludeCidrs` ou avec cette
    règle désactivée, sans
    sélecteur de nœud et tolérance à eux, ou avec un `controlPlaneUrl` qui n'est pas en `https://`. Chacun
    a un acquittement explicite là où un déploiement en a besoin, sauf HTTPS. Elle tient aussi le control
    plane à l'écart du nœud de tout agent, de n'importe quelle release dans n'importe quel namespace, par
    une anti-affinité obligatoire, et exclut de la sortie des agents les adresses de métadonnées du cloud
    — `169.254.0.0/16` et celles hors de cette plage — quoi que dise la liste.
  - **Vérifiée en CI** pour chacune de ces formes, et que celles d'un seul namespace ne produisent rien
    hors de leur namespace.
- **L'export d'un projet, signé, et son schéma publié** — le premier lot des plugins de rapport
  ([décision 0035](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0035-report-plugins.md),
  acceptée le 2026-10-03). `GET /api/v1/projects/{id}/export` renvoie un zip d'`export.json` — les cibles
  du projet, leurs analyses les plus récentes, les verdicts de la barrière, les issues non résolues avec
  leur triage, les décomptes, les composants, l'état de conformité et les énoncés de checklist, en
  `vectispire-project-export` 1.0 — et d'`export.json.sig`, vérifiable par `cosign verify-blob --key`
  contre la clé publique de l'instance. Pour les comptes en écriture et les auditeurs qui voient tout le
  projet, images comprises, et les clés d'intégration de portée `export` ; ni source, ni valeur de secret,
  ni identifiant, ni adresse e-mail. Au-delà de 100 000 issues ou composants ou de 64 Mio, il est
  refusé (409 `project-export-too-large`), jamais tronqué. Le schéma est servi à
  `GET /api/v1/schemas/project-export/1`. Audité `PROJECT_EXPORTED`, envoyé au SIEM comme le nouveau
  `VECTI-SEC-032` ; `VECTI-SEC-033` est réservé aux plugins eux-mêmes
  ([comment](../guide/exports.fr.md#export-de-projet)).
- **Le registre des plugins de rapport** — le deuxième lot de la décision 0035. Le gouverneur de la
  plateforme enregistre un plugin de rapport à partir de son manifeste — une image épinglée par digest, la
  majeure d'export qu'il lit, l'unique fichier qu'il écrit et son type tiré d'une liste fermée (Office Open
  XML, OpenDocument, PDF, CSV, texte brut ; ni HTML, ni paquet à macros), le plafond de sa sortie et son
  délai, et un signataire, **obligatoire sans dérogation** — par `POST /api/v1/report-plugins`. **Double
  validation active, chaque digest de manifeste attend une seconde personne** : un administrateur, un CISO ou un
  autre gouverneur l'approuve (`POST /api/v1/report-plugins/{id}/manifests/{digest}/approval`), jamais le
  compte qui l'a enregistré (409 `report-plugin-four-eyes`) — même une fois la double validation coupée,
  puisqu'il a été enregistré sous elle —, pendant que le manifeste approuvé précédent continue de servir.
  Ramener un plugin à un digest approuvé auparavant attend aussi une seconde personne. Un responsable sécurité active un plugin approuvé pour un projet qu'il voit en entier
  (`PUT /api/v1/projects/{id}/report-plugins/{pluginId}`) ; le gouverneur retire un digest avec une
  justification, et celui-ci ne tourne ni ne s'enregistre plus jamais. Pas de suppression. Chaque geste est
  audité (`REPORT_PLUGIN_*`) et envoyé au SIEM comme le nouveau `VECTI-SEC-031`. L'image d'un plugin privé
  est tirée et vérifiée avec la configuration Docker du plan de contrôle : le manifeste ne porte aucun identifiant, et Vectispire n'en
  stocke aucun ([comment](../administration/report-plugins.fr.md)).
- **Les exécutions de rapport** — le troisième lot de la décision 0035. Un compte en écriture ou un auditeur
  qui voit un projet entier demande un rapport à un plugin activé pour lui
  (`POST /api/v1/projects/{id}/reports`, 202) : l'exécution est mise en file dans la base et prise en charge
  par l'exécuteur **du plan de contrôle** — le point d'accès Docker qu'utilise le worker intégré, jamais un
  agent — deux à la fois par défaut (`VECTISPIRE_REPORT_CONCURRENCY`). À la prise en charge, il exécute le
  manifeste approuvé à ce moment, construit l'export du projet pour le demandeur tel qu'il le voit alors,
  vérifie le signataire de l'image avec cosign **avant le pull** (sans dérogation, la configuration Docker du
  plan de contrôle pour un registre privé), et exécute l'image **sans aucun réseau**, l'export seul et en
  lecture seule, un répertoire de sortie borné par le `max_output_bytes` du manifeste et 16 fichiers, le délai
  du manifeste, code de sortie 0 ou échec. Une exécution est `pending`, `running`, `produced`, `failed` ou
  `refused`, avec son motif (`GET /api/v1/projects/{id}/reports`) ; une seule d'un plugin par projet à la
  fois (409 `report-run-in-progress`) ; son exécuteur renouvelle son bail tant qu'elle tourne, et une
  exécution dont l'exécuteur est mort passe en échec `executor_lost` quand le bail expire — dix-sept minutes
  sans renouvellement. Une exécution produite garde l'export qu'elle a reçu, purgé par la fenêtre
  des preuves ; rien d'autre n'est gardé d'une exécution qui n'a pas produit. **Sur MySQL, cet export est
  borné par `max_allowed_packet`** : environ 32 Mio au paquet par défaut de 64 Mio, refusé
  `export_too_large` avant que le plugin ne s'exécute ; démarrez MySQL avec `--max-allowed-packet=160M` pour
  les 64 Mio entiers, comme le fait désormais la composition livrée. **Une installation dont le
  worker intégré est coupé ne peut pas exécuter de plugins de rapport** dans cette version : 409
  `report-executor-unavailable` ; une exécution mise en file avant la coupure du worker passe en échec
  `executor_unavailable` quand rien ne l'a prise en charge pendant dix-sept minutes alors qu'aucun exécuteur
  ne travaillait, plutôt que de rester en attente pour toujours. Journalisé `REPORT_REQUESTED`, `PROJECT_EXPORTED` (`VECTI-SEC-032`, l'export
  atteignant un plugin), `REPORT_PRODUCED`, `REPORT_FAILED`, `REPORT_REFUSED` — ce dernier envoyé au SIEM
  comme le nouveau `VECTI-SEC-033` ([comment](../administration/report-plugins.fr.md#demander-un-rapport)).
- **Les documents de rapport, vérifiés, signés et téléchargeables** — le quatrième lot de la décision 0035.
  À la fin d'une exécution, le fichier écrit par le plugin est **vérifié sur ses octets** contre le type de
  média de son manifeste : un paquet Office Open XML avec les garde-fous de zip de l'import de checklist, sa
  partie principale du type déclaré, et aucun projet VBA, feuille macro, partie à macros, contrôle ActiveX ni
  relation externe autre qu'un lien hypertexte ; un paquet OpenDocument avec son `mimetype` en premier et
  stocké, sans `Basic/` ni `Scripts/` ; un PDF de `%PDF-` à `%%EOF` ; un CSV ou un texte en UTF-8 valide,
  sans NUL ni rien qu'un navigateur lirait comme du HTML. Un fichier qui n'est pas ce qu'il déclarait est
  **refusé**, le nouveau motif `output_refused`, jeté sans signature — son SHA-256 gardé sur l'exécution —
  et envoyé au SIEM comme `VECTI-SEC-033`. Un fichier qui passe est stocké comme un **paquet** avec
  `provenance.json`, une déclaration in-toto dans une enveloppe DSSE signée par la clé de la plateforme — le
  fichier lui-même n'est jamais signé brut — qui nomme l'exécution, le projet, le demandeur, le plugin, son manifeste, son image et son signataire vérifié,
  le schéma et le SHA-256 de l'export, le type de média et le SHA-256 du fichier, la version du produit et
  la clé de signature. `GET /api/v1/projects/{id}/reports/{runId}/document` le télécharge — toujours en
  pièce jointe, `nosniff`, sous `Content-Security-Policy: sandbox` — pour quiconque voit le projet entier,
  journalisé `REPORT_DOWNLOADED` ; `cosign verify-blob-attestation` le vérifie contre la clé publique de
  l'instance. **La signature atteste la provenance, pas la vérité** : elle dit ce
  que l'installation a donné à quelle image et ce qui en est revenu, pas que le document rend fidèlement
  l'export — l'export conservé est ce qui permet de le vérifier. Les documents sont purgés avec les exports
  par la fenêtre des preuves, et avec leur projet. Sur MySQL à son `max_allowed_packet` par défaut, le fichier
  d'une exécution est abaissé à environ 31 Mio, ce que `--max-allowed-packet=160M` ramène au plafond du
  manifeste. Les exécutions gagnent `outputMediaType`, `signingKeyId`
  et `packageSha256` ([comment](../administration/report-plugins.fr.md#le-document-et-comment-le-verifier)).
- **Le plugin de rapport de démonstration** — le cinquième lot de la décision 0035. `vectispire-report-demo`
  rend l'export d'un projet en `summary.xlsx` — une feuille `Summary` (le projet, qui a demandé, la version,
  l'instant de l'export, la barrière par cible, les comptes), une ligne par issue sur `Issues`, une par
  ligne de checklist sur `Checklists` — et le même export en les mêmes octets : pas d'horloge, dates et ordre
  du zip fixes. Un autre schéma ou une autre majeure le fait sortir en 2, un export auquel manque une partie
  en 1, chacun avec sa raison. **Une troisième image est publiée**, `ghcr.io/asmolabs/vectispire-report-demo`,
  distroless, signée par empreinte avec la même identité que les deux autres, son SBOM et sa provenance
  attestés ; son manifeste est joint à la version, `vectispire-report-demo.manifest.json`, rempli avec cette
  empreinte et l'identité du tag et signé avec son paquet Sigstore — vérifiez-le, puis enregistrez-le comme
  n'importe quel plugin de rapport. C'est le test du contrat autant qu'un exemple : chaque build rend les
  exports que la suite génère et vérifie le classeur
  ([comment](../administration/report-plugins.fr.md#le-plugin-de-demonstration)).
- **Les plugins de rapport à l'écran** — le sixième lot de la décision 0035. **Administration → Plugins de
  rapport**, pour les rôles qui lisent la gouvernance, liste chaque plugin de rapport avec ses empreintes
  approuvée et en attente et l'historique de ses manifestes — qui a enregistré, approuvé et retiré chacun, et
  si la double validation s'appliquait. Le gouverneur de la plateforme enregistre un plugin ou lui donne un
  nouveau manifeste en collant le JSON, que la page vérifie champ par champ et explique en mots avant de
  l'envoyer ; il l'active et le désactive, et retire une empreinte avec une justification de 20 à 500
  caractères. Un responsable sécurité approuve une empreinte en attente ; sous la double validation, le
  compte qui l'a enregistrée voit le bouton désactivé et pourquoi. La page d'un projet gagne une section
  **Rapports**, pour un lecteur qui voit le projet entier : les plugins activés pour lui (les responsables
  sécurité les activent et les désactivent), **Demander un rapport** pour les comptes en écriture et les
  auditeurs, les exécutions avec leur état et leur raison en mots — un refus distinct d'un échec —, suivies
  tant qu'une attend ou tourne, le téléchargement du paquet signé d'une exécution produite, ce qu'il contient
  et le lien vers les commandes qui le vérifient, et **Télécharger l'export**. Chaque refus que le serveur
  nomme (un plugin désactivé, aucun manifeste approuvé, aucun exécuteur, une exécution déjà en cours, la
  double validation) est dit dans la langue du lecteur. Marquer les documents d'un manifeste retiré vient
  avec le lot suivant ([comment](../guide/exports.fr.md#rapports)).
- **Les documents de rapport retirés, et demander si un document tient toujours** — le septième lot de la
  décision 0035. Retirer un digest de manifeste retire désormais **chaque document qu'il a produit**, qui reste
  stocké et téléchargeable : ses exécutions portent `withdrawnAt`, `withdrawnBy` et `withdrawalJustification`,
  le téléchargement répond `Vectispire-Document-Status: withdrawn` (`upheld` pour tout autre document), et une
  exécution en cours au moment du retrait ne signe rien (échec `plugin_unavailable`).
  `GET /api/v1/report-documents/{sha256}`, pour tout compte connecté, prend le SHA-256 d'un paquet ou du
  fichier qu'il contient et répond son `standing` — `upheld`, `withdrawn` ou `unknown` — avec les exécutions qui
  l'ont produit, leurs digests de plugin, de manifeste et d'image, leur clé de signature et leur retrait. Le
  document d'un projet que l'appelant ne voit pas en entier répond `unknown`, exactement comme un document jamais
  produit. Dans la section **Rapports** d'un projet, l'exécution d'un document retiré est marquée **Retiré**
  avec la date, qui l'a retiré et pourquoi, et son téléchargement est suivi de ce qu'il vaut.
  `REPORT_PLUGIN_WITHDRAWN` compte les documents retirés ; V79 ajoute trois index aux exécutions
  ([comment](../administration/report-plugins.fr.md#linstallation-se-porte-t-elle-toujours-garante-dun-document)).
- **Connexions de forge : un jeton en lecture seule vers un GitHub ou un GitLab, sondé avant d'être
  gardé** ([Connexions de forge](../administration/forge-connections.fr.md), décision 0037, lot D1 — la
  découverte et l'import des dépôts suivent). `/api/v1/forge-connections`, administrateurs seulement, à
  l'écran avec le lot D7 (ci-dessous). Le jeton est présenté une fois à la forge par la garde sortante et refusé quand il est
  rejeté, plus large que la lecture (GitLab : `read_api` ; GitHub : un jeton *fine-grained*, ou un
  classique sur Enterprise Server, signalé `canWrite`), ou que le serveur est antérieur à GitLab 16 ou
  GHES 3.12. Un serveur autogéré sur le réseau interne est atteint quand l'administrateur le dit, derrière
  sa propre AC quand elle est épinglée pour cette connexion — aucun interrupteur n'ignore la vérification.
  Le jeton est chiffré avec sa ligne pour contexte, remplacé sur place, rescellé quand la connexion est
  enregistrée pendant une rotation d'`ENCRYPTION_KEY`, et jamais renvoyé. Journalisé
  `FORGE_CONNECTION_CHANGED` et `FORGE_CONNECTION_REFUSED` ; signalé `VECTI-SEC-034`, et `VECTI-SEC-036`
  pour une adresse bloquée ou une portée refusée.
- **Découvertes de forge : les dépôts d'un GitLab listés en arrière-plan, gardés comme un instantané et
  comparés d'une exécution à l'autre** ([Découvrir les dépôts](../administration/forge-connections.fr.md#decouvrir-les-depots),
  décision 0037, lots D2 et D3 — le choix et l'import des dépôts suivent, et le listage de GitHub avec le
  lot D4). `POST /api/v1/forge-connections/{id}/discoveries` répond 202 avec une exécution `pending` qu'une
  instance du plan de contrôle prend sous bail — un redémarrage la reprend — et
  `GET …/discoveries/{discoveryId}` rend compte de sa progression ; une par connexion à la fois (409
  `forge-discovery-in-progress`). Les groupes et projets dont le jeton est membre sont listés
  (`membership=true`, `min_access_level=10`) avec leur branche par défaut, archivé, fork, visibilité,
  dernière activité, langage et taille — **une valeur que GitLab n'a pas donnée est gardée `null`,
  inconnue, jamais zéro** — et un projet dans l'espace personnel d'un utilisateur est marqué `personal`.
  `…/repositories?change=new|changed|gone` lit la comparaison ; **seule une exécution complète marque un
  dépôt disparu**, et rien n'est supprimé. Bornes : trente minutes et 20 000 dépôts par exécution, une
  attente de limite de débit d'au plus une minute passée dans l'exécution — au-delà de l'une d'elles,
  l'exécution finit `partial`. Chaque requête passe par la garde sortante et l'AC épinglée de la connexion ;
  une page suivante sur une autre origine n'est jamais suivie — l'exécution échoue, journalisée
  `FORGE_CONNECTION_REFUSED` et signalée `VECTI-SEC-036`. Chaque découverte mise en file est journalisée
  `FORGE_DISCOVERY_REQUESTED` (une demande répondue 409 n'écrit rien), sans signal SIEM. Administrateurs
  seulement ; à l'écran avec le lot D7 (ci-dessous).
- **Découvertes de forge : les dépôts d'un GitHub aussi** — github.com, Enterprise Cloud avec résidence des
  données (`<sous-domaine>.ghe.com`) et Enterprise Server 3.12 ou ultérieur sous `/api/v3`
  ([ce qui est listé](../administration/forge-connections.fr.md#decouvrir-les-depots), décision 0037, lot D4).
  Une découverte GitHub ne répond plus 409 `forge-discovery-unsupported`. Un jeton *fine-grained* liste le
  propriétaire de la connexion ; un jeton classique (Enterprise Server) chaque organisation dont son
  utilisateur est membre et les dépôts propres de l'utilisateur, marqués `personal` et proposés décochés. Le
  listage donne la branche par défaut, archivé, fork, la visibilité (`internal` comprise), `pushed_at`, le
  langage et la taille, pagine par `Link` sur l'origine propre de la connexion, et attend la fin des limites de
  débit primaires et secondaires de GitHub. **Une organisation que le jeton ne peut pas lire — authentification
  unique non autorisée, liste d'adresses IP autorisées — n'arrête plus rien** : l'exécution continue, finit
  `completed`, et la nomme dans un nouveau membre de la découverte, `unreadableNamespaces` (`path`, `reason`),
  et dans `detail` ; **aucun de ses dépôts n'est marqué disparu par cette exécution**. Importés comme ceux de
  GitLab, l'organisation une solution et chaque dépôt son propre projet. Migration V80
  (`t_forge_discovery.unreadable_namespaces`).
- **Imports de forge : les dépôts d'une découverte sélectionnés, prévisualisés et importés comme des cibles
  ordinaires** ([Sélectionner et importer](../administration/forge-connections.fr.md#selectionner-et-importer),
  décision 0037, lots D5 et D6 — l'écran est le lot D7). `GET …/discoveries/{discoveryId}/selection` est le
  tableau, filtré et paginé sur le serveur — archivés et forks masqués par défaut, inactivité, langage,
  visibilité, espace de noms, un motif de chemin, personnels et présents — avec la **présence par identité**
  de chaque dépôt (la règle de doublon du formulaire de dépôt : son URL de clonage HTTPS ou SSH contre celle
  de chaque cible, quels que soient la branche et le sous-chemin) et la solution et le projet que propose
  l'organisation de GitLab (groupe de premier niveau → solution, sous-groupe parent → projet) ; `POST` dessus
  applique proposed / all / none / invert / add / remove. `POST …/imports/preview` dit ce qui serait créé,
  réutilisé, écarté ou refusé, l'identifiant de clonage par hôte, les premiers scans et **qui verra les
  nouvelles cibles** ; `POST …/imports` crée jusqu'à 1 000 cibles **en une transaction**, par les gestes et
  les entrées d'audit mêmes des formulaires, replanifié dans celle-ci pour qu'**un rejeu ne crée rien**. La
  branche par défaut de la forge ; aucune planification propre — le défaut s'applique, au créneau de chaque
  cible plutôt qu'à toutes au tic suivant ; des premiers scans seulement sur demande, un toutes les 60
  secondes par défaut (de 10 s à 10 min) ; aucun droit. Une entrée `FORGE_IMPORT_APPLIED` par import, signalée
  **`VECTI-SEC-035`** une fois quand il a créé quelque chose. Administrateurs seulement. Le jeton de la
  connexion ne clone jamais. Supprimer une cible importée supprime sa provenance ; supprimer la connexion
  garde les cibles. Migration V78 (`t_forge_import_link`).
- **Connexions de forge, découverte et import à l'écran** ([À l'écran](../administration/forge-connections.fr.md#a-lecran),
  décision 0037, lot D7). **Administration → Connexions de forge**, administrateurs seulement : chaque
  connexion avec le type et les portées de son jeton, s'il peut écrire (*Non communiqué* pour un jeton GitHub
  à granularité fine — inconnu, pas lecture seule), son expiration annoncée quatorze jours à l'avance, la
  déclaration de réseau, l'AC épinglée, la dernière découverte et les cibles importées ; l'ajout avec une AC
  collée en PEM dont la forme est lue et commentée en mots avant l'envoi, le refus de la sonde affiché tel
  que le serveur le formule ; le remplacement du jeton en place ; le renommage ou le changement de la
  déclaration de réseau ou de l'AC ; la suppression, cibles conservées. La page de chaque connexion procède
  en trois étapes : **découvrir** (l'exécution suivie avec un espacement croissant jusqu'à sa fin, ses
  compteurs, la raison en mots d'une exécution partielle ou échouée, les chiffres de la comparaison ouvrant
  chacun sa liste), **choisir** (la table filtrée par le serveur, ce que chaque filtre n'a pas pu juger
  compté, proposition / tous / aucun / inverser / par identifiant, espaces personnels décochés au départ, un
  identifiant écarté par le serveur nommé) et **classer et importer** (le classement par espace de noms ou
  par dépôt, l'identifiant de clonage par hôte, premières analyses désactivées par défaut et espacées de
  10 s à 10 min, un aperçu disant qui verra chaque cible, un import qui envoie exactement ce qui a été
  prévisualisé — mille au plus à la fois — et un résultat qui lie chaque cible). Aucune route ne change.
- **Une ligne de checklist peut mesurer la revue des changements — *toute merge request est approuvée par
  un pair avant la fusion*** ([la règle](../administration/checklist-templates.fr.md#revue-des-changements-comment-ils-arrivent-sur-une-branche),
  [ce que l'on demande à la forge](../administration/forge-connections.fr.md#revues-des-changements-ce-que-les-checklists-demandent-a-la-forge),
  décision 0037, lot G3). Une règle `change_review` indique les approbations par d'autres personnes que
  l'auteur (`minimumApprovals`), la fenêtre (`windowDays`), la part des changements fusionnés qui doit les
  avoir (`minimumRatio`) et, au besoin, la branche. Un tour de maintenance horaire lit la forge de chaque
  dépôt par la connexion qui l'a importé — ou une dont la découverte a listé son URL —, jamais sur une
  requête : les **réglages** quand la forge en a (règles d'approbation de GitLab Premium et Ultimate,
  *Empêcher l'approbation par l'auteur* et la branche protégée ; rulesets et protection de branche GitHub),
  qui font réussir la ligne seuls quand ils exigent les approbations, refusent celle de l'auteur et refusent
  un push direct ; et l'**historique** sur toutes les éditions — la **Community Edition de GitLab** comprise,
  qui n'a pas de règle d'approbation et répond 404 pour les réglages : les merge requests ou pull requests
  fusionnées dans la fenêtre et qui a approuvé chacune, **une approbation par l'auteur n'étant comptée nulle
  part**. La ligne montre *47 of 47 merged merge requests approved by a peer in 30 days*, ou les réglages en
  une phrase, et le document signé l'imprime. Pas de données, jamais une réussite, pour un dépôt qu'aucune
  connexion ne connaît, un jeton refusé (sur GitHub, un jeton *fine-grained* demande aussi **Pull requests:
  read** ; le `read_api` de GitLab le couvre déjà), plus de 500 changements dans la fenêtre, ou rien de
  fusionné. L'éditeur de modèles propose le type, avec un pair, tous les changements et trente jours.
  Migration V81 (`t_forge_review_reading`).
- **Une ligne de checklist répond à « la bibliothèque X est utilisée » et à « les versions de la famille Y
  utilisées », et à une plage de versions**
  ([Composants](../administration/checklist-templates.md#composants-presence-versions-et-plages)). Une
  règle `component_present` est satisfaite quand un paquet correspondant à son préfixe figure dans le
  SBOM analysé le plus récent, **quelle que soit sa version — y compris une version gérée par un BOM
  Maven, que Syft écrit `UNKNOWN`** : une ligne sans réponse automatique sur un projet conforme qui
  utilise un BOM en a désormais une. Elle échoue quand le paquet est absent, et n'a pas de données sans
  analyse récente, ou quand la dernière analyse ne conserve plus son SBOM et que son inventaire ne liste
  rien. Un préfixe d'espace de noms (`pkg:maven/org.example.platform`) liste, par dépôt, chacun de ses
  paquets avec ses versions, vingt au plus et les autres comptés — sur `component_versions` aussi. Une
  ligne `component_versions` accepte désormais des **plages de versions Maven** à côté des versions
  exactes pour un paquet `pkg:maven/` — `[1.17,2.0)`, `[1.17.7]`, `(,2.0)`, des unions — dans l'ordre
  de Maven : `1.17-SNAPSHOT` et `1.17-RC1` avant `1.17`, `5.3.0.RELEASE` égale à `5.3.0` ; une plage
  illisible est refusée en mots à la liaison. Quand une version reste non indiquée, la preuve dit qu'elle
  est gérée hors du SBOM et qu'un SBOM produit par le build la résout. L'éditeur de règles du modèle
  propose les deux, en français et en anglais.
- **Une ligne de couverture peut mesurer un périmètre de paquets**
  ([comment l'écrire](../administration/checklist-templates.fr.md#couverture-sur-un-perimetre-de-paquets)).
  Une règle `coverage_threshold` accepte un `scope` facultatif — des motifs `include` et `exclude` sur les
  chemins des paquets, `**/service/**`, `org/example/**`, `**` pour des segments entiers et `*` au sein
  d'un seul — décidé dans le modèle plutôt que dans le filtre de couverture de chaque build, où aucun
  relecteur ne le voyait. Le chiffre est le couvert sur le total des paquets correspondants ; la preuve
  dit combien correspondent, et le résumé de la mesure — la feuille `Evidence` du document signé — énonce
  le périmètre à côté du chiffre. Pour le mesurer, un import de couverture conserve désormais ses comptes
  par paquet à côté de ses totaux (un `<package>` JaCoCo ou Cobertura, le répertoire d'un fichier lcov),
  jusqu'à 10 000 paquets et seulement s'ils s'additionnent aux totaux. Un périmètre qui ne correspond à
  rien, un import antérieur à cette version (renvoyer le rapport) ou un import dont les paquets n'ont pas
  été conservés est une absence de données dite en ces mots — jamais 0 %, 100 % ni les totaux du rapport.
  Les motifs qui ne se liraient pas comme écrits — `org.example.service`, `**/serv**`, `?` — sont refusés à
  la liaison de la règle. Tant qu'une ligne n'est pas liée de nouveau avec un périmètre, rien ne change.
- **Le SBOM d'un build complète l'inventaire du scanner** ([Importer le SBOM d'un build](../administration/plugins.md#importer-le-sbom-dun-build),
  [décision 0039](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0039-a-build-sbom-completes-the-scanners-inventory.md),
  lot G10). Le scanner lit les poms d'une arborescence Maven : une version gérée par la BOM d'un parent
  sortait en `UNKNOWN`, et une bibliothèque tirée transitivement n'était pas listée du tout, si bien
  qu'une ligne de checklist demandant si elle est utilisée répondait un faux « non ». Une source déclarée
  peut désormais livrer `sbom` : `POST /api/v1/repositories/{id}/build-sbom-imports` prend le JSON
  CycloneDX que le build a écrit (le `makeAggregateBom` de `cyclonedx-maven-plugin`, le plugin CycloneDX
  de Gradle), spécification 1.4 à 1.6, jusqu'à 32 Mo (`VECTISPIRE_MAX_BODY_SBOM_IMPORT`) et 50 000
  composants, sans rien récupérer de ce à quoi il renvoie ; la commande `build-sbom` de la CLI l'envoie.
  **L'inventaire de chaque scan est celui du scanner, complété par le SBOM de build le plus récent de sa
  branche** : l'union des deux, reconnue par purl, la version déclarée par le build l'emportant, celle du
  scanner gardée à côté. Le scan terminé le plus récent est complété dès la réponse à l'import, et chaque
  scan suivant quand son inventaire est écrit ; les scans plus anciens gardent ce qu'ils ont reçu. La
  recherche de composants, l'inventaire consolidé, son export CycloneDX, l'export de projet, l'inventaire
  des licences et ses décomptes, et les lignes de checklist `component_versions` et `component_present` lisent tous les lignes
  complétées, chacune disant qui l'a listée. La correspondance des vulnérabilités est inchangée, et un
  SBOM n'ouvre aucune issue. Audité `BUILD_SBOM_IMPORTED` ; un refus `REPORT_IMPORT_REFUSED`,
  `VECTI-SEC-027`. Les SBOM partent avec la fenêtre de preuve et avec leur dépôt. Migration V82
  (`t_build_sbom`, `t_build_sbom_component`, cinq colonnes de `t_component`), rien à faire.
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
  pour elles plutôt que de le deviner. Les lignes d'une cible supprimée partent avec elle (migration V67),
  et le relevé est purgé par la fenêtre des preuves, *Evidence kept for (days)* (`evidence_retention_days`,
  400 jours par défaut, zéro le garde pour toujours), comme les verdicts de la barrière et les relevés de
  conformité : une semaine est gardée tant qu'une partie d'elle est dans la fenêtre, et une semaine purgée
  se lit comme reconstituée dans la vue hebdomadaire ci-dessous.
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
  ouverte entre cette résolution antérieure et sa réouverture. Chaque semaine et catégorie donne aussi
  **`reopened`**, les issues qu'une réouverture consignée a ramenées dans la semaine — ce qui fait monter
  les ouverts sans chiffre d'apparues correspondant. **Il vaut `null`, pas zéro, sur une semaine commencée
  avant que les réouvertures soient consignées** (datées par l'application de V68, à un jour près) ;
  `reopenedRecordedFrom` nomme la première semaine qui l'a.
- **La grille OWASP courante prend aussi un projet ou une solution : `GET /api/v1/owasp/coverage?project_id=…`
  ou `?solution_id=…`**, avec les règles de la vue hebdomadaire — les deux à la fois répondent 400, un
  périmètre inexistant et un périmètre dont l'appelant ne voit rien répondent 404 dans les mêmes termes, et
  un périmètre vu en partie est calculé sur les cibles qu'il voit. Chaque chiffre est restreint au
  périmètre, y compris le fait que quelque chose ait été analysé : un projet que rien n'a analysé se lit
  *non mesuré*, si couvert que soit le reste du parc. La réponse gagne `scope` (`kind`, `id`, `name`,
  `partial`, `targetCount`, `null` sans périmètre) ; les déclarations restent celles de la catégorie, quel
  que soit le périmètre. Sans paramètre, la grille est inchangée. À l'écran, la grille courante de la page
  OWASP a le sélecteur de périmètre de la vue hebdomadaire, le périmètre gardé dans l'adresse, et chaque
  nombre d'ouverts ouvre le backlog de sa catégorie dans le même périmètre.
- **De nouveaux filtres du backlog pour les chiffres de cette vue** : `owasp_category` (`A01`…`A10`,
  rangée comme la grille range les issues — une vulnérabilité est `A06`), `open_at` (ouverte à la fin de
  ce jour, UTC) et `first_seen_from` / `first_seen_to` / `resolved_from` / `resolved_to` — `open_at` et
  l'intervalle de résolution lisent de même les résolutions antérieures d'une issue rouverte — et
  `reopened_from` / `reopened_to` (une réouverture que l'historique de triage a consignée dans
  l'intervalle). **`owasp_category=any`** liste les issues rangées dans l'une des dix catégories — les
  totaux d'une semaine — et jamais un constat de licence, de qualité, de plugin ou d'import, qu'aucune
  catégorie ne tient. **Avec une date
  et sans `state`, `GET /api/v1/issues` liste tous les états**, puisque les issues ouvertes un jour passé
  sont pour la plupart résolues depuis ; le défaut reste `open` sinon.
- **L'écran du rapport OWASP gagne une vue « Par semaine »** (*Rapport OWASP* → *Par semaine*, ou
  `/owasp?view=weekly`) : une carte de chaleur des dix catégories sur 12, 26 ou 52 semaines ou un
  intervalle choisi, pour tout le parc ou un projet ou une solution ; les courbes de ce qui est ouvert par
  catégorie ; les issues apparues, rouvertes (empilées sur les apparues, en violet) et résolues chaque
  semaine ; les chiffres de la semaine sélectionnée et
  leur évolution depuis la précédente ; et la grille de cette semaine. **Les semaines reconstituées sont
  hachurées** et leurs courbes en pointillé — leurs ouverts incluent les risques acceptés, d'où l'absence
  d'évolution affichée sur la semaine où le relevé commence. **Les risques acceptés sont montrés à part**,
  en gris, jamais ajoutés aux ouverts. Chaque nombre ouvre le backlog qu'il compte — ouvertes au dimanche
  de la semaine (non réglées, sur une semaine relevée), ou apparues / résolues / rouvertes de son lundi à
  son dimanche, dans le même périmètre — **les totaux compris**, qui ouvrent les issues rangées dans une
  catégorie quelconque (sauf le total des ouverts d'une semaine relevée où une catégorie n'était pas
  mesurée : la grille n'y comptait rien, la liste les tiendrait). Une semaine antérieure à l'enregistrement
  des réouvertures affiche un tiret pour elles, pas un zéro. Le backlog dit ce qu'on lui a demandé dans un
  bandeau, avec le chemin du retour et de quoi le retirer. Les chiffres s'exportent en CSV, une ligne par semaine et catégorie avec l'indicateur
  « reconstituée » ; *Imprimer / PDF* imprime la vue sans les menus de l'application (le « enregistrer en
  PDF » du navigateur — aucun PDF n'est produit par le serveur). Fenêtre, périmètre et semaine
  sélectionnée sont dans l'adresse : un lien reproduit la vue.
- **Le rapport OWASP renvoie vers les constats qu'il décrit.** Sous chaque catégorie, *Voir les N
  constats* ouvre les constats ouverts et non tranchés du dépôt dans cette catégorie — la liste que
  le chiffre de la grille ouvre — ou dit qu'il n'y en a aucun. Les identifiants montrés au modèle (CVE,
  règles, paquets) renvoient vers leur constat, ou vers une recherche quand plusieurs constats le
  portent ; un identifiant que le texte cite sans que le modèle l'ait reçu reste du texte.
- **Le rapport OWASP peut être rédigé après chaque scan de dépôt**
  ([rapport OWASP](../guide/risk-analysis.md#le-rapport-owasp-redige-par-un-modele)). Avec **Write the
  OWASP report after each repository scan** (`ai_review_owasp_after_scan`, désactivé par défaut) et la
  revue par modèle activée, un scan de dépôt qui se termine demande au modèle le rapport de ce dépôt,
  construit à partir de ce scan — jamais pour un scan en échec, jamais pour une image de conteneur. La
  demande est mise en file avec les résultats du scan et le rapport est rédigé à côté des scans, sans
  jamais en retenir un : un rapport à la fois par instance, et aucun commencé tant qu'un rapport est en
  cours de rédaction, par une autre instance ou depuis le bouton, car un modèle local répond à une
  demande à la fois. Un dépôt dont le rapport est en cours n'est pas redemandé, et les scans d'un même
  dépôt qui arrivent pendant que son rapport attend sont fondus en un seul, à partir du plus récent. Un
  échec est enregistré sur le rapport comme pour un rapport demandé à la main, et le scan reste terminé.
  Le journal d'audit enregistre chacun comme `AI_REVIEW_REQUESTED`, sans utilisateur. Désactivé, rien ne
  change. Une demande retenue par une instance qui s'arrête avant de la commencer est perdue ; le scan
  suivant la redemande.
- **Expérimental : d'autres poids du scorecard, à côté de ceux de production.**
  `GET /api/v1/scorecards/simulation`, réservé aux administrateurs, note chaque cible, chaque projet et
  chaque solution visibles avec la formule de la fiche et avec les poids demandés, avec les points de
  risque de chaque ligne ; sans paramètre les deux s'accordent. Elle a servi à décider la formule
  ci-dessus, met côte à côte les deux façons de noter une portée — le maillon le plus faible qu'utilise
  la fiche et la somme rejetée — et est retirée à la version suivante
  ([comment](../guide/repositories.fr.md#score-simulation)).

### Sécurité

- **Kubernetes : dans un pod, une destination qu'un administrateur règle se voit aussi refuser les ports 6443
  et 10250 sur toute adresse** — ceux du serveur d'API et des kubelets — à côté du service d'API du cluster :
  kube-proxy renvoie le service vers des adresses qu'aucun réglage ne nomme. Sont concernés les connexions
  forge, les webhooks, le serveur d'IA et le collecteur SIEM. Un serveur d'API publié sur 443 par un cluster
  managé revient à la NetworkPolicy, comme le disent désormais le guide d'installation et le README de la chart.
- **Un import depuis une forge ne clone que depuis l'hôte de sa connexion.** Un dépôt dont l'URL de clonage —
  HTTPS, ou SSH quand une clé est choisie — n'est pas sur l'hôte de la connexion est refusé par l'aperçu et par
  l'import, et aucun identifiant de cet hôte ne lui est proposé : la liste de la forge ne décide plus d'où une
  cible est clonée. Un GitLab dont les clones SSH passent par un hôte à part importe en HTTPS.
- **Le contrôle de santé de la base de la composition ne met plus le mot de passe root de MySQL sur une ligne
  de commande.** `mysqladmin ping -p"…"` tournait toutes les dix secondes avec le mot de passe parmi ses
  arguments, que `ps` montre à tout utilisateur du conteneur et de l'hôte. Il le lit désormais dans un fichier
  d'options lisible par son seul propriétaire, écrit par une commande interne du shell et supprimé après
  chaque ping. Concerne `docker-compose.yml` ; la chart Helm ne fait tourner aucune base.
- **La composition nomme son MySQL et son Keycloak par empreinte.** `mysql:8` et
  `quay.io/keycloak/keycloak:26.0` étaient des étiquettes qu'un registre peut republier, et les données de la
  base sont entre les mains de la première image ; ce sont désormais `mysql:8.4.11@sha256:…` et
  `keycloak:26.0.8@sha256:…`, ce que les deux étiquettes désignaient le 15 octobre 2026, et
  `docker compose up` les tire une fois. Un volume créé par un serveur 8.4 — ce que `mysql:8` désigne depuis
  2024 — passe à 8.4.11 sans rien à faire. Un volume créé par un `mysql:8` plus ancien que l'hôte gardait
  d'ailleurs, de 8.0 à 8.3, est mis à niveau sur place au premier démarrage et ne s'ouvre plus avec ce
  serveur : sauvegardez-le d'abord. Le Keycloak d'évaluation ne garde rien d'un redémarrage à l'autre.
- **Les identifiants de l'agent et le Keycloak d'évaluation ne sont plus à portée de `docker inspect` ni
  d'une valeur par défaut publiée.** Le profil `with-agent` de la composition passait `VECTISPIRE_AGENT_TOKEN`
  et `VECTISPIRE_AGENT_SIGNING_KEY` dans l'environnement, que tout client du démon — les deux proxys de socket
  compris — relit ; ce sont désormais des fichiers sous `/run/secrets/`, lus par l'arbre de configuration
  comme le font les agents du chart Helm. **Gardez les deux lignes dans `.env`**, vides si inutilisées :
  l'agent ne démarre pas tant que l'une n'est pas déclarée. L'administrateur du Keycloak du profil `sso`
  valait `admin`/`admin` par défaut ; il refuse désormais de démarrer sans `KEYCLOAK_ADMIN_PASSWORD` dans
  `.env`, et le mot de passe publié du realm d'évaluation est temporaire, changé à la première connexion
  ([connexion unique](../administration/sso.fr.md)).
- **Un jeton HTTPS scellé pour un agent est lié à son hôte et à son nom d'utilisateur, et une clé de
  déploiement à sa nature.** Le jeton était scellé seul, son hôte voyageant à côté : l'enveloppe restait
  valable quel que soit l'hôte associé. L'agent ne l'ouvre plus que sous l'hôte et le nom d'utilisateur
  pour lesquels elle a été scellée, et refuse le scan sinon. Le format d'enveloppe est `sealed:v2:` et
  l'agent s'en porte garant dans l'annonce signée de sa clé de scellement ; la migration V86 oublie les
  clés de scellement acceptées auparavant, que chaque agent à jour annonce de nouveau à son démarrage.
- **Trois réglages qu'un CISO pouvait changer ne sont plus les siens.** *Autoriser une URL de webhook
  privée* revient à un administrateur, comme l'interrupteur privé du SIEM : le bouton de test des canaux
  citant l'erreur de l'envoi — une connexion refusée, un délai dépassé, un statut HTTP, et l'interrupteur
  coupé, l'adresse vers laquelle un nom se résolvait — un CISO pouvait en tirer la carte du réseau interne.
  Le bouton répond désormais délivré ou non délivré, la cause dans le journal du serveur. Le projet du
  tracker et son compte Jira reviennent à un administrateur, comme son URL et son jeton : le jeton agit sur
  tout projet de son hôte, et choisir le projet choisissait où il écrivait ; un projet GitHub doit s'écrire
  `propriétaire/dépôt`, refusé sinon à l'enregistrement et à l'envoi, où un chemin après lui dirigeait la
  requête du jeton vers une autre ressource. Et *Evidence kept for (days)* revient au gouverneur de
  plateforme : un CISO ou un administrateur pouvait la régler à un jour et purger, au tour suivant, les
  verdicts de la barrière, les relevés de conformité et les semaines OWASP qui attestent que leurs propres
  contrôles ont tourné ([réglages](../administration/settings.fr.md#qui-peut-changer-quoi)). Les valeurs
  enregistrées sont gardées ; une intégration qui les écrit par `PUT /api/v1/settings` sous un autre rôle
  reçoit désormais 403.
- **Quatre écarts d'autorisation fermés.** Une clé limitée à un dépôt pouvait exporter le projet dont ce
  dépôt était le seul, alors qu'une telle clé ne voit jamais un projet entier ; elle y est désormais traitée
  comme absente, comme sur ses checklists. Un administrateur pouvait révoquer la clé d'API d'un gouverneur
  de la plateforme, que seul un gouverneur administre ; c'est refusé. Le registre des exceptions lisait
  toutes les exceptions et filtrait ensuite, et son curseur, comme celui du registre des verdicts de la
  barrière, désignait la dernière ligne lue, visible ou non : un lecteur restreint à un dépôt, parcourant
  une ligne à la fois, connaissait l'heure de chaque verdict et l'instant et l'identifiant de chaque
  acceptation de risque du parc. Les pages d'un lecteur restreint sont désormais lues dans ses cibles. Et
  la déclaration d'applicabilité (`GET /api/v1/compliance/soa`, `…/soa/{framework}`) était lisible par tout
  compte connecté, alors que ses revues en retard exigeaient déjà la lecture de gouvernance ; les deux
  l'exigent désormais, comme la référence le disait.
- **Un document de rapport, et une révision de checklist, sont lus par qui voit ce qu'ils contiennent.**
  Un document était servi à quiconque voyait le projet entier au moment du téléchargement : un dépôt retiré
  du projet après l'exécution laissait ses constats lisibles par quelqu'un à qui il n'avait jamais été
  montré. Une exécution enregistre désormais les cibles que son export a contenues, et le téléchargement
  comme la route de statut d'un document exigent aussi que l'appelant voie chacune d'elles ; les documents
  produits avant cette version n'en ont enregistré aucune et ne sont lus que par qui voit tout
  ([décision 0042](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0042-a-report-document-is-read-by-who-sees-what-it-carried.md)).
  Les mesures conservées d'une soumission et d'une approbation, le paquet signé et l'énoncé qu'embarque
  l'export d'un projet portent la preuve de chaque dépôt que le projet contenait alors, et étaient servis à
  quiconque voyait le projet entier aujourd'hui. Ils exigent désormais aussi que l'appelant voie chacun de
  ces dépôts — nommés par la preuve conservée elle-même, si bien que les révisions soumises avant cette
  version sont couvertes sans migration ; tout autre apprend que la révision n'existe pas, et l'export d'un
  projet qui porte un tel énoncé est refusé plutôt que tronqué. Une exécution de rapport enregistre ces
  dépôts parmi les cibles de son export
  ([décision 0042 §5](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0042-a-report-document-is-read-by-who-sees-what-it-carried.md)).
- **L'annuaire SCIM ne lie plus un compte privilégié existant, ni un compte à second facteur local, à un
  sujet du fournisseur d'identité.** Il ne pouvait pas accorder ces rôles, mais il pouvait lier un
  compte qui en détenait déjà un, et la connexion suivante sautait le mot de passe et le second facteur
  de ce compte. Une première liaison d'un compte privilégié est désormais refusée sauf si
  `VECTISPIRE_OIDC_LINK_PRIVILEGED_ACCOUNTS=true` l'autorise — la règle que suit déjà une revendication à
  la connexion — et celle d'un compte à second facteur local toujours
  ([authentification unique](../administration/sso.fr.md)).
- **Changer son propre mot de passe révoque les clés d'API qu'on a émises**, comme le faisait déjà la
  réinitialisation par un administrateur : les autres sessions se fermaient, mais une clé émise par
  qui connaissait l'ancien mot de passe continuait d'agir pour le compte. La réponse porte
  `revokedApiKeys`, et chaque clé révoquée est une entrée d'audit à part. La clé de pipeline d'un
  administrateur qui change son mot de passe cesse de fonctionner : émettez-en une nouvelle.
- **Le passage de relais de l'authentification unique n'est plus une session.** Le cookie vivait
  soixante secondes, la ligne derrière lui l'heure d'une session, et sa valeur servait de jeton
  porteur tant qu'elle n'était pas échangée. Il est désormais rangé à part, seulement échangeable, et
  expire avec le cookie.
- **Les compteurs de connexion ne se contournent plus.** Un nom que la collation de la base confond avec
  celui d'un compte — `jeßica` pour `jessica`, `æ` pour `ae` — comptait sur un compteur à lui, si bien que
  le verrouillage distinguait un compte existant d'un compte absent ; le nom est désormais replié comme
  MySQL le compare, vérifié contre la collation du serveur lui-même. La collation lit aussi par-dessus des
  caractères qu'un nom de compte ne contient jamais — le trait d'union conditionnel, les espaces et liants
  de largeur nulle, le gluon de mots, l'indicateur d'ordre des octets, la plupart des caractères de
  contrôle — si bien que `alice` saisi avec un trait d'union conditionnel (U+00AD) ouvrait `alice` et
  rencontrait son verrouillage en comptant sous un nom à lui ; un nom saisi hors de la grammaire des noms de
  compte (lettres, chiffres, `.`, `_`, `-`) reçoit désormais la réponse d'un nom inconnu, bon mot de passe
  compris, et une orthographe accentuée comme `Àlice` n'ouvre plus `alice` non plus. Un appelant IPv6
  avait un nouveau compteur pour chaque adresse de son /64, que son hôte choisit à volonté ; les plafonds de
  connexion, de jetons porteurs et du webhook le comptent désormais par son /64, et le journal d'audit garde
  l'adresse complète. Et une connexion réussie effaçait les échecs de son adresse : se connecter à son
  propre compte entre deux essais remettait à zéro le plafond par adresse. Seuls les compteurs du compte et
  du nom repartent désormais à zéro.
- **La garde sortante refuse davantage de ce qu'aucun réglage ne doit atteindre.** Les adresses de
  métadonnées du cloud hors du lien local — `100.100.100.200` chez Alibaba, `fd00:ec2::254` en IPv6 chez
  AWS, l'ancienne `192.0.0.192` d'Oracle, le WireServer `168.63.129.16` d'Azure — et l'adresse non
  spécifiée (`0.0.0.0`, `::`), qui atteint la machine locale, sont refusées sous toute politique, pour un
  clone comme pour une requête. Une base ou un démon Docker réservés comme `localhost` le sont sur toute
  adresse de bouclage. La page suivante d'un listage de forge doit rester sous le chemin de l'API de la
  connexion, pas seulement sur son hôte ([connexions de forge](../administration/forge-connections.fr.md)).
- **Le chemin d'un agent du cluster vers l'Ingress ouvre le port qu'il nomme, pas tous les ports.**
  `agents.networkPolicy.allowTo`, dans la chart Helm, devenait une règle de sortie sans `ports` : l'entrée
  dont un agent a besoin pour joindre le contrôleur d'ingress — dont les pods sont dans la plage de pods
  exclue une fois l'adresse LoadBalancer traduite par kube-proxy — ouvrait tous les ports de ces pods à ce
  qui s'échappe d'un scanner, et une entrée pour un hôte Git interne tous les ports de cet hôte. Chaque
  entrée porte désormais ses propres `ports` (`protocol` vaut TCP par défaut) et forme une règle à elle ;
  **une entrée sans eux est refusée au rendu**, le message nommant la correction, puisque la chart ne peut
  distinguer tous les ports voulus de ports oubliés. `agents.networkPolicy.dnsTo`, vide par défaut,
  restreint le DNS du port 53 de n'importe où à vos résolveurs
  ([installation](../getting-started/installation.fr.md#kubernetes)).
- **Le fichier d'un plugin de rapport n'est plus signé brut par la clé de la plateforme.** `v0.11.0-rc.1`
  mettait dans le paquet un `<output>.sig` détaché, fait avec la clé qui signe les VEX, les CSAF et l'export
  du projet : une image de plugin pouvait ainsi obtenir la signature de la plateforme sur n'importe quels
  octets qu'elle écrivait. Le paquet ne contient plus que le fichier et `provenance.json`, et le fichier est
  lié par le sujet de la provenance
  ([comment vérifier](../administration/report-plugins.fr.md#le-document-et-comment-le-verifier)). Les
  paquets produits par une version candidate gardent leur `.sig` : ne vous y fiez pas.
- **Le catalogue de règles amont est lu sans suivre de lien.** Un lien symbolique publié en amont — un
  `LICENSE` pointant vers un fichier de cet hôte, un secret monté sous `/run/secrets` par exemple — était suivi
  par la récupération : montré dans l'aperçu de la licence, ou conservé comme règle. Un fichier lié est
  désormais écarté, une licence liée laisse le catalogue sans licence et la récupération est refusée, et aucun
  fichier n'est ouvert à travers un lien ([jeux de règles](../administration/rule-sets.fr.md)).

### Corrigé

- **Un jeton du gestionnaire de tickets, un secret de webhook ou une clé d'API IA enregistrés dont l'état n'a
  pas pu être lu le disent**, avec la raison du serveur, au lieu de « aucun enregistré ».
- **Le rapport rédigé par un modèle, sur la page OWASP, se rafraîchit seul** toutes les cinq secondes pendant
  sa rédaction, et son sélecteur de dépôt ne propose plus que les dépôts de la solution ou du projet choisi
  au-dessus de la grille — le dépôt choisi et son rapport sont retirés quand le périmètre ne les contient plus.
- **Le sélecteur de dépôt de la surface d'attaque est annoncé par son libellé**, et non plus par son texte
  d'invite ou le dépôt affiché.
- **Les écrans n'affirment plus ce qu'ils n'ont pas lu.** Un échec de lecture des conflits de licences
  affichait « Aucun conflit bloquant » sur une liste que personne n'avait lue ; un état illisible des flux de
  menaces affichait « 0 CVE KEV » et « Jamais » ; le plan de remédiation et les chemins d'attaque gardaient les
  chiffres du périmètre ou du dépôt précédent sous la nouvelle sélection. Chacun dit désormais que la lecture a
  échoué, avec la raison donnée par le serveur — comme les autres panneaux des écrans licences, remédiation,
  posture de sécurité, qualité, détail d'un scan et chemins d'attaque, qui restaient vides.
- **Les jours insérés dans une phrase s'écrivent jj/mm/aaaa comme toutes les autres dates** : la note de
  changement de formule du score et les axes des graphiques du tableau de bord, la vue OWASP hebdomadaire
  (fenêtre, semaine, cases, tableau des chiffres, note sur les réouvertures), le bandeau du backlog ouvert
  depuis la vue hebdomadaire, et les dates « réalisé le » et « valable jusqu'au » d'une preuve de checklist.
  La vérification i18n de l'interface refuse désormais un format de date qui n'est pas jour, mois, année.
- **Le registre des verdicts et la posture de sécurité nomment la politique qui a décidé dans la langue du
  lecteur** — « Défaut intégré », « Politique globale », « Politique de la cible » avec sa version — au lieu
  de la valeur stockée (`BUILT_IN`, « global v2 »).
- **Les dates d'expiration et de refus du jeton du tracker, et celles des écrans des forges, s'écrivent
  jj/mm/aaaa** comme toutes les autres, au lieu de commencer par l'année (`2026-09-29`) : la carte du tracker
  dans les Paramètres, et les écrans de connexion, de découverte, de sélection et d'import des forges.
- **Le registre des verdicts de la barrière ne tombe plus sur un verdict qui ne nomme aucune cible.** Une
  seule ligne de ce genre — restaurée ou écrite à la main, l'application n'en enregistre jamais — faisait
  répondre 500 au registre entier et à la section 09 du paquet de preuves ; elle est désormais listée sans
  cible, aux seuls lecteurs de tout le parc. Le registre **nomme aussi chaque cible** (`target_name`) au lieu
  d'afficher « Dépôt 5 », et seulement les cibles que le lecteur peut voir.
- **L'attestation est datée par la vérification de la chaîne d'audit faite par le serveur** (`checkedAt` sur
  `GET /api/v1/audit-log/verify`), et non plus par l'horloge du navigateur.
- **L'échantillon de 300 constats du rapport OWASP rédigé par l'IA garde les plus risqués** — KEV d'abord,
  puis par sévérité — au lieu des premiers types de constat par ordre alphabétique, qui pouvaient écarter
  toutes les vulnérabilités.
- **La documentation dit quelle adresse cliente `trustedProxies` croit** derrière un répartiteur de charge ou
  un nœud Kubernetes qui traduit l'adresse source, et comment la rétablir selon le répartiteur ; la note du
  guide SIEM sur `src` derrière un répartiteur n'était plus à jour.
- **Sans fournisseur d'identité, le rapport de conformité compte le TOTP local.** Les contrôles de
  journalisation étaient plafonnés à 65 avec « aucun second facteur » dès qu'aucun fournisseur n'était
  configuré, même quand chaque compte avait enrôlé le TOTP. Quand chaque compte actif qui a un mot de passe
  l'a enrôlé, le plafond est de 85 — celui qui s'applique déjà à un fournisseur à côté d'un mot de passe
  ouvert, puisque le TOTP se choisit compte par compte ; sinon il reste à 65 et le rapport dit combien de ces
  comptes n'ont pas de second facteur.
- **La grille OWASP et la référence REST disent comment une catégorie est vraiment couverte** : par le type
  du constat ou, pour l'analyse de code, par la catégorie que déclare la règle — pas par le type seul, et pas
  « trois catégories sur dix ». La référence liste désormais les routes du rapport OWASP
  (`/repositories/{id}/owasp-review`, son PDF) et la déclaration de catégorie
  (`PUT /owasp/coverage/{category}/declaration`).
- **La fenêtre Imports d'un dépôt dit si un import de couverture a gardé ses comptes par paquet**, et sinon
  pourquoi (trop de paquets, un chemin refusé, des chiffres incohérents, ou importé avant que les paquets
  soient gardés). Le titre de la fenêtre d'une politique de barrière suit le changement de langue, et les
  filtres des constats et de la surface d'attaque gardent un nom accessible une fois une valeur choisie.
- **Un écran n'affiche plus la réponse d'une requête précédente.** Changer la fenêtre du tableau de bord,
  chercher une deuxième CVE sur la page EPSS, ouvrir un autre dossier dans l'historique ou choisir un autre
  paquet dans le rayon d'impact pouvait laisser à l'écran la réponse plus lente de la demande précédente,
  sous le nouveau libellé — l'explication IA d'une CVE sous les chiffres d'une autre. C'est désormais la
  dernière demande qui s'affiche. La page de surface d'attaque attend la fin des scans qu'elle a lancés
  plutôt que le premier point d'accès, et les pages rayon d'impact et surface d'attaque signalent l'échec
  du chargement d'une liste au lieu de rester vides.
- **Une sévérité a une seule couleur sur tous les écrans** : critique rouge, élevée orange, moyenne bleue,
  faible grise. Élevée était rouge sur la liste des constats et les solutions, orange sur les exceptions,
  les chemins d'attaque et le tableau de bord.
- **Le balayage des tickets n'écrase plus une référence attachée par une personne pendant qu'il ouvrait un
  ticket.** Le balayage lit ses candidates, puis appelle le tracker ; une référence attachée entre-temps
  était remplacée par celle du ticket tout juste ouvert, et le ticket de la personne perdait son lien.
  L'issue garde désormais celle de la personne, et le ticket ouvert est nommé dans le journal et dans son
  entrée d'audit comme non enregistré sur l'issue. Marquer un ticket fermé ne touche de même qu'une issue
  qui porte encore cette référence.
- **Le différentiel de SBOM n'invente plus de licences.** Un composant qui n'en déclarait aucune en
  recevait une devinée d'après son nom — `MIT` pour tout ce qui contient « mit » (`commit-graph`,
  `summit-ui`), `Apache-2.0` pour `spring-` et `commons-`, `GPL-3.0` pour « gpl » — et des autres seule la
  première licence déclarée était lue : `GET /api/v1/sbom/diff` et `…/diff/latest` rapportaient des
  changements de licence que personne n'avait déclarés. Une licence est désormais la déclaration du SBOM
  du build, sinon toutes celles que déclare le SBOM du scanner (jointes par `OR`), sinon `UNKNOWN` — la
  lecture qu'utilisait déjà l'inventaire des licences. **Et un SBOM illisible n'est plus un SBOM vide** :
  le différentiel avalait l'erreur d'analyse et ne comparait rien, ce qui se lisait comme tous les
  composants retirés ou comme aucun changement ; il répond désormais 409 de type
  `urn:vectispire:problem:sbom-unreadable`, et le serveur journalise quel scan.
- **Un triage fait pendant un scan n'est plus perdu.** Un scan lisait les issues de la cible au début de
  l'écriture de ses résultats et les enregistrait entières à la fin ; une décision validée entre-temps — un
  triage, une approbation, une revue, un ticket attaché — était ramenée à ce que le scan avait lu, sans
  erreur ni ligne de journal. Chaque issue porte désormais une révision (migration V89) : un scan qui trouve
  une issue modifiée sous lui la relit et l'intègre de nouveau, la décision gardée, et un import SARIF de
  même ; une décision dont un scan a modifié l'issue sous elle est refusée par 409
  `issue-changed-meanwhile` au lieu d'effacer les changements du scan.
- **Un tracker derrière une CA interne est joint : sa CA peut être épinglée, comme celle d'une connexion de
  forge.** Chaque appel au tracker — ouvrir un ticket sur GitLab, GitHub, Jira ou ServiceNow, le fermer, la
  recherche des transitions de Jira, celle de l'incident sur ServiceNow — était vérifié contre le seul
  magasin de confiance de l'environnement Java, si bien qu'un tracker hébergé dont le certificat venait de la
  CA de l'organisation échouait à la négociation à chaque appel : aucun ticket n'était jamais ouvert, et le
  balayage horaire réessayait avec une ligne du journal du serveur pour seule trace. Le réglage
  `ticket_ca_pem`, réservé à un administrateur, reçoit cette CA en PEM ; elle est vérifiée à
  l'enregistrement selon la règle des connexions de forge (une CA, en cours de validité, au plus 8
  certificats et 16 384 caractères) et **remplace** le magasin de l'environnement pour le seul tracker — les
  CA publiques ne sont alors pas reconnues pour lui, et son nom reste vérifié. L'écran des réglages affiche
  son sujet et son expiration, lus sur `GET /api/v1/settings/ticket-ca` ([un tracker derrière une CA
  interne](../integrations/ticketing.md#internal-ca)).
- **Un jeton de tracker qui expire est annoncé avant, et celui que le tracker refuse est dit hors
  d'usage.** Un jeton expiré — GitLab impose désormais une expiration, un an au plus par défaut — faisait
  échouer le balayage horaire à chaque appel avec une ligne de journal pour seule trace, pour toujours.
  L'expiration que donnent GitLab et GitHub est lue à l'enregistrement du jeton puis chaque jour (à travers
  la CA épinglée), une date peut être déclarée pour Jira et ServiceNow (`ticket_token_expires_on`, réservée
  à un administrateur), et la carte du tracker l'annonce quatorze jours à l'avance comme la liste des
  connexions de forge, *Expiration inconnue* quand rien n'est connu ; un `401` ou un `403` rencontré par le
  balayage (un `401` par la vérification quotidienne) affiche *Ne fonctionne plus* — mais pas la limite de
  débit de GitHub, un `403` portant `x-ratelimit-remaining: 0` ou `retry-after` — jusqu'à ce qu'un appel
  soit de nouveau accepté ou qu'un nouveau jeton soit enregistré. Chaque changement est journalisé une fois
  au niveau `WARN`, pas chaque heure. `GET` et `PUT /api/v1/settings/ticket-token` répondent `expiresAt`,
  `expirySource`, `refusedStatus`, `refusedSince` et `checkedAt` à côté de `configured` ([quand le jeton
  expire](../integrations/ticketing.md#token-expiry)).
- **L'import du catalogue laisse de côté les règles qui font double emploi avec gitleaks, qui trouvaient
  chaque clé divulguée une seconde fois.** Choisir `generic` importait `generic/secrets/gitleaks/`, 175
  règles portées des règles gitleaks que l'étape des secrets exécute déjà, et 27 règles de
  `generic/secrets/security/` dont une règle par défaut dédiée de gitleaks trouve déjà le format de jeton
  (identifiants de clé d'accès AWS, GitHub, Slack, Stripe, clés privées…). Chaque fuite devenait une issue
  *secret* et une jumelle *SAST*, et trier le secret laissait la jumelle ouverte : elle pouvait encore faire
  échouer la barrière, pesait sur le score et comptait sa catégorie OWASP deux fois. Les deux groupes sont
  désormais laissés de côté sauf si **Les inclure malgré tout** est coché — pour une installation dont les
  analyses n'ont pas d'étape des secrets — et l'écran dit combien. Les 23 autres règles de
  `generic/secrets/security/` — une empreinte bcrypt, des identifiants dans une URI, une clé secrète
  AWS… — sont toujours importées. Un jeu importé auparavant garde ces règles jusqu'au prochain import,
  dont l'activation compte les issues qu'elles laissent derrière elles comme toute activation. L'entrée
  d'audit de l'import porte désormais l'empreinte de la licence avant les langages, qu'une sélection de onze
  langages avait repoussée au-delà des 255 caractères de l'entrée. `POST /api/v1/rule-sets/catalogue`
  accepte `includeGitleaksDuplicates`, `false` en son absence, et `GET /api/v1/rule-sets/catalogue` répond
  `gitleaksDuplicates` ([jeux de règles](../administration/rule-sets.md#depuis-le-catalogue-amont)).
- **Une catégorie OWASP ne se lit propre que là où l'analyse la plus récente de chaque cible l'a
  examinée.** La grille tenait une catégorie pour mesurée dès qu'une cible du périmètre avait une analyse :
  un projet fait d'images seules affichait A05 et A07 *Rien trouvé*, alors que l'analyse d'une image ne
  cherche ni secrets ni erreurs de configuration, et un dépôt dont l'étape des secrets avait échoué
  affichait A07 propre quand même. Chaque cible porte désormais ce que sa dernière analyse terminée a
  examiné — les types que ses étapes ont produits et les langages que ses règles d'analyse de code ont lus
  — et une catégorie n'est mesurée sur un périmètre que si chaque cible qui peut être examinée pour elle
  l'a été ; une seule qui ne l'a pas été la rend *Non mesurée*, et la ligne dit combien et pourquoi. Une
  cible que rien ne peut examiner pour une catégorie (une image, pour les secrets) est laissée de côté, et
  les constats ouverts sont comptés quoi qu'ait examiné la cible. L'analyse de code est créditée par dépôt
  et par langage, dans la grille comme dans le relevé mensuel de conformité, et le relevé hebdomadaire suit
  la même règle. Une catégorie qui se lisait *Rien trouvé* avant la mise à niveau peut se lire *Non
  mesurée* après : rien ne l'avait examinée.
- **Les documents VEX ne déclarent plus ce que personne n'a décidé.** L'agrégat OpenVEX cherchait
  `false_positive` et `accepted_risk`, des statuts qui n'ont jamais existé : chaque `not_affected` approuvé
  en sortait `affected`, et une issue en cours d'examen ou en attente d'approbation aussi, là où CycloneDX
  disait `in_triage` et CSAF `under_investigation`. L'export CSAF par cible n'avait pas de cas pour
  `pending_approval`, si bien que le produit ne figurait dans aucune liste de statut ; il est
  `under_investigation`. Une ligne `not_affected` sans justification — ancienne ou importée — recevait
  `vulnerable_code_not_in_execute_path` chez CycloneDX et
  `vulnerable_code_cannot_be_controlled_by_adversary` chez CSAF, devinées d'après l'écriture de ce qui s'y
  trouvait ; elle est désormais déclarée en cours d'investigation, puisque personne n'a fait cette
  affirmation. Et CycloneDX recevait les libellés de justification d'OpenVEX, que son schéma n'accepte pas,
  et répondait `will_not_fix` sur chaque `not_affected` — rien à corriger dans un produit qui n'est pas
  affecté ; ses justifications sont désormais dans son propre vocabulaire
  ([comment un triage se lit en VEX](../guide/exports.fr.md#comment-un-triage-se-lit-en-vex)).
- **Appliquer la suggestion de l'assistant n'échoue plus pour chaque constat absent de la liste KEV.**
  L'assistant suggère dans le vocabulaire VEX, `under_investigation` pour ceux-là, et la fenêtre le
  prenait comme statut de triage : la liste des statuts n'affichait rien et le serveur refusait la
  décision. Il s'applique désormais comme *en cours d'examen*.
- **Un compte créé par l'annuaire SCIM n'est plus retenu sur l'écran de changement de mot de passe.**
  Il recevait un mot de passe aléatoire à changer, ce que ses sessions fédérées ne pouvaient pas faire.
  Les comptes que l'annuaire a créés en 0.10.0 ou en `v0.11.0-rc.1` gardent l'indicateur après la mise à
  niveau, et restent retenus sur cet écran après une connexion unique : un administrateur le lève pour
  chacun — le journal d'audit les nomme (`USER_CREATED`, « SCIM provisioned account: … ») — par `update
  t_user set must_change_password = false where username = '…'`, aucun écran ne le levant pour un compte
  sans mot de passe à changer.
- **Des écritures d'audit simultanées pouvaient casser la chaîne d'audit, et déclencher une fausse
  alerte de falsification.** Deux entrées écrites au même instant — deux requêtes sur un serveur, ou deux
  serveurs — pouvaient se chaîner toutes deux sur le même prédécesseur ; la vérification déclarait alors
  la chaîne rompue, et le SIEM recevait `AUDIT_CHAIN_BROKEN`, sans que rien ait été modifié. Les entrées
  sont désormais écrites une à une, entre serveurs aussi (migration V66). Une installation qui a vu une
  rupture inexpliquée doit relancer la vérification après la mise à jour : les entrées écrites ensuite se
  chaînent correctement ; une rupture déjà enregistrée reste où elle est, puisque réécrire un journal
  d'intégrité est précisément ce qu'il doit révéler.
- **Le premier paquet de preuves d'une installation sans `vectispire.signing.key` répondait 500.** La clé
  de signature créée à la première utilisation rejoignait la transaction en lecture seule du paquet, dans
  laquelle MySQL et PostgreSQL refusent d'écrire. Elle est désormais créée hors de celle-ci.
- **Un démon Docker en `tcp://` avec `DOCKER_TLS_VERIFY` est joint en TLS.** Le client lisait
  `DOCKER_TLS_VERIFY` et `DOCKER_CERT_PATH` puis construisait sa connexion sans eux : un démon à
  l'écoute en TLS sur 2376 recevait du HTTP en clair, et chaque appel échouait. Le certificat client
  sous `DOCKER_CERT_PATH` (`ca.pem`, `cert.pem`, `key.pem`) est désormais utilisé ; un répertoire auquel
  il en manque un arrête l'exécuteur avec un message qui nomme les fichiers, plutôt que de joindre le
  démon en clair
  ([décision 0038](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0038-deploying-on-kubernetes.md)).
- **Un plugin signé dont l'image vit dans un registre privé est vérifié au lieu d'être refusé.** Le
  vérificateur de signature interrogeait le registre de façon anonyme, si bien qu'un registre qui ne
  sert rien à un pull anonyme répondait « unauthorized » et que le plugin était refusé comme
  `signature_unverified` — un problème de signataire à l'écran pour une signature que personne n'avait
  lue. cosign reçoit désormais, le temps de son exécution, les identifiants que les tirages de
  l'exécuteur utilisent pour ce registre (sa configuration Docker ; Vectispire n'en stocke aucun), en
  lecture seule et effacés avec le conteneur. Un registre qui refuse encore — pas d'identifiants, ou
  ceux détenus refusés — donne le nouveau refus `registry_authentication_required`, qui dit lequel.
- **Le guide des conteneurs disait les identifiants de registre stockés chiffrés avec
  `ENCRYPTION_KEY`.** Ils ne l'ont jamais été : un tirage utilise la configuration Docker de l'exécuteur
  qui analyse. Le guide le dit désormais, et explique comment donner à un exécuteur les identifiants
  d'un registre privé.
- **Un dépôt `git://` que son serveur ne sert pas était retenté un quart d'heure avant d'échouer sur
  « the clone failed ».** `git daemon` répond à un chemin qu'il n'a pas, ou n'exporte pas, par un refus
  qui lui est propre, lu comme un échec inconnu — transitoire : l'analyse attendait une minute, puis
  cinq, et dépensait ses trois tentatives sur la même réponse. Elle échoue désormais dès sa première
  tentative, comme un dépôt absent en HTTPS ou en SSH l'a toujours fait, avec
  `git://… could not be found.` Un hôte dont le nom ne se résout pas, en `git://` ou en SSH, est
  toujours retenté — le réseau peut revenir — et dit désormais `… could not reach its host.` là où il
  disait `The clone of … failed.`
- **Un modèle de checklist dont aucune approbation ne pourrait remplir le classeur était publié, et
  découvert à la première approbation.** Une cellule que Vectispire écrit — une réponse ou un
  commentaire d'une ligne d'item, une valeur de l'en-tête — qui porte la cellule maîtresse d'une formule
  partagée (une formule d'aide recopiée dans la colonne des commentaires, typiquement) ou une formule
  matricielle sur plusieurs cellules ne peut pas être écrite sans casser les cellules qui en dépendent.
  L'approbation la refusait, à raison, mais seulement une fois qu'un projet avait répondu à chaque
  ligne : la révision restait soumise, son brouillon ne pouvait même pas être exporté, et la version ne
  pouvait jamais être signée. La publication exécute désormais une fois le rendu de l'approbation
  elle-même, avec des réponses factices et rien de conservé, et refuse une telle version en nommant
  chaque cellule — l'approbation d'une version publiée auparavant les nomme toutes aussi, là où elle
  nommait la première. Une version publiée avant cette version-ci avec une telle cellule refuse toujours
  ses approbations : publiez-en une corrigée et faites-y passer les checklists des projets — voir
  [une formule dans une cellule que Vectispire écrit](../administration/checklist-templates.fr.md#une-formule-dans-une-cellule-que-vectispire-ecrit).
  Une checklist n'est plus non plus **ouverte sur une telle version, ni passée à celle-ci** : le même
  essai y est exécuté, les cellules sont nommées à l'écran, et rien n'est ouvert — aucun projet ne
  commence une checklist qui ne pourrait jamais être approuvée. Quitter une telle version n'est jamais
  refusé : c'est la sortie — [quand le serveur refuse](../guide/security-checklists.fr.md#quand-le-serveur-refuse).
  L'écran des modèles et celui de la checklist de projet nomment tous deux les cellules dans la langue du
  lecteur et disent quoi faire. Les versions proposées à un projet listent une telle version désactivée,
  *ne peut pas être approuvée*, ses cellules nommées en dessous — au lieu de la proposer pour la refuser
  une fois choisie.
- **Une issue rouverte ne laissait aucune trace dans son historique de triage.** Quand une analyse ou un
  import retrouvait une issue résolue, il la rouvrait et effaçait une décision `fixed` sans aucune
  entrée : l'historique montrait `fixed` comme dernier mot d'une issue de nouveau ouverte et en revue, et
  la résolution qu'elle avait eue — de quand à quand — était perdue. La réouverture est désormais une
  entrée à part entière : le triage qu'elle quitte (ou qu'elle garde, pour un jugement qui survit au
  retour), le jour où la résolution qu'elle clôt avait commencé, et l'analyse qui a retrouvé l'issue ;
  personne n'est nommé, puisque personne n'a décidé (migration V68). Une réouverture antérieure à la mise
  à jour reste sans entrée.
- **Le registre des exceptions n'échoue plus sur une issue qui ne nomme aucune cible.** Une seule issue
  exemptée sans dépôt ni conteneur faisait échouer le registre — l'écran, la réponse de chaque revue, et le
  dossier de preuves qui scelle le registre. L'application ne crée aucune issue de ce genre, mais le schéma
  l'admet, écrite à la main ou restaurée d'ailleurs. Elle est désormais listée sans cible pour un lecteur
  qui voit tout le parc, et pour aucun lecteur restreint.
- **Le rapport OWASP range chaque constat là où la grille OWASP le range.** Le modèle choisissait
  lui-même les catégories, et plaçait les secrets commités sous A02 quand la grille du même écran les
  compte en A07. Il reçoit désormais la catégorie de chaque constat telle que la grille la place — par
  type, ou par la catégorie que déclare une règle d'analyse statique —, la consigne de ne jamais en
  déplacer un, et les constats que la grille ne place nulle part à part, sous *Not placed by the
  scanners*, plutôt que dans une catégorie de son choix. Il reçoit aussi l'état de chaque catégorie dans
  la grille, et ne se fait plus dire qu'une catégorie sans constat est une catégorie qu'aucun scanner n'a
  regardée : le *rien trouvé* de la grille dit qu'un scanner l'a fait. Le « How to read this » du PDF dit
  la même chose, et dit de laquelle des deux façons un rapport a été rédigé : un rapport antérieur à
  cette version a été rangé par le modèle. Les `inputs` d'un rapport (`GET
  /api/v1/repositories/{id}/owasp-review`) gagnent une colonne `owasp_category`, en deuxième position, et
  la couverture du dépôt au-dessus du tableau.
- **Un dépôt sans rapport OWASP le dit.** La carte affichait *Aucun constat classé dans cette
  section*, qui se lit comme un rapport n'ayant rien trouvé ; et tout échec de lecture, une 500 comprise,
  s'affichait comme une absence de rapport. Seule une 404 veut désormais dire « pas encore de rapport » ;
  le reste est une erreur.
- **L'interrupteur de la revue par modèle dit ce qu'il envoie.** `ai_review_enabled` s'intitulait *Review
  the code with a local model*, avec une aide qui décrivait ce qu'une telle revue trouverait, et les
  avertissements de fuite parlaient de code source qui sortait. Rien n'appelle une revue de code : ce qui
  sort, ce sont les constats ouverts du dépôt — identifiants, composants, chemins, descriptions, une
  description pouvant citer une ligne commitée — pour le rapport OWASP. L'interrupteur s'intitule désormais
  *Let a model write the OWASP report*, et son aide, les réglages du fournisseur et des points d'accès,
  l'acquittement d'un point d'accès distant, sa confirmation et le bandeau disent ce qui est envoyé
  aujourd'hui, et ce qui le serait le jour où une revue de code sera branchée.
- **Recharger la checklist d'un projet, ou ouvrir un lien vers elle, ne répond plus 404.** Le serveur ne
  renvoyait à l'interface que les chemins d'un ou deux segments ; `/projects/{id}/checklist` et
  `/solutions/{id}/compliance` en ont trois, et répondaient « Nothing is served at this path » sauf en y
  arrivant par un clic. Toutes les routes de l'interface sont désormais renvoyées, et le build le vérifie.
- **Un modèle avec une colonne d'identifiant devant son domaine est proposé dans les bonnes colonnes.**
  La colonne à gauche du domaine décalait toutes les colonnes proposées (contrôle sur l'identifiant,
  contact sur le domaine, KPI sur l'objectif).
- **Suivre un lien d'une analyse à une autre pouvait afficher l'analyse précédente.** La page d'une
  analyse gardait la première à l'écran jusqu'à la réponse de la seconde, et si la première réponse
  arrivait en dernier, elle remplaçait la seconde : l'adresse nommait l'analyse 35, l'en-tête, les
  plugins et les résultats étaient ceux de la 34. La page efface désormais l'analyse précédente et annule
  sa requête quand l'adresse change.
- **Changer de mot de passe ne ramène plus au tableau de bord.** Un compte dont le mot de passe avait
  été fixé par un administrateur, suivant un lien qu'on lui avait transmis, se connectait, était envoyé
  changer son mot de passe puis vers le tableau de bord, le lien oublié ; il en allait de même d'un
  changement ouvert depuis la barre du haut ou la page du compte. Le changement ramène désormais à la
  page demandée — ou à celle d'où il a été ouvert — et seulement à une page de Vectispire : une adresse
  qui mène ailleurs est ignorée.
- **Le compte d'un scan nomme des issues, sa liste des occurrences, et chaque compte dit ce qu'il compte.**
  Le détail d'un scan titrait *Constats* un nombre d'issues — une par empreinte, qui ne porte pas de ligne —
  au-dessus d'une liste de *constats* tenant une ligne par endroit signalé par un outil : un scan affichait
  « 28 » au-dessus de 56 lignes. La carte dit désormais *Issues*, avec les occurrences en dessous
  (*28 issues · 56 occurrences*), la liste s'intitule *Occurrences dans ce scan*, et l'historique comme les
  analyses récentes du tableau de bord appellent ce même nombre des issues — de même que la ligne de chaque
  scan dans le PDF de l'historique exporté, qui lisait *28 findings, 3 new, 2 resolved* et lit désormais
  *28 issues, …* (ce document est rédigé en anglais) ([scans](../guide/scans.md#lire-un-scan)). Les
  sélecteurs de scans de la comparaison SBOM disent *7 issues*, avec le séparateur de milliers de la langue,
  au lieu d'un nombre nu ; le tableau des cibles en échec du tableau de bord intitule son décompte
  *Violations* : il compte les violations de la politique de la barrière, pas des constats ; et le détail
  d'un scan intitule *Identifiant* la colonne d'identifiant de sa liste d'occurrences. Aucun nombre n'a
  changé.
- **Les dates, les nombres et les libellés s'écrivent de la même façon sur tous les écrans, dans la langue
  du lecteur.** Quelques écrans écrivaient les dates dans la langue du navigateur ou une locale codée en dur
  (mois en premier, année sur deux chiffres, mois en anglais pour un lecteur francophone) ; toutes suivent
  désormais le format unique de l'interface, jour/mois/année sur 24 heures. Les pourcentages suivent chaque
  langue — *50%* en anglais, *50 %* en français avec une espace insécable — et les décimales portent le
  séparateur du lecteur (*11,4 jours*, pas *11.4 jours*). Les sévérités, les statuts, les états de
  conformité et les référentiels sont des libellés là où des écrans affichaient la valeur brute
  (`critical`, `PARTIAL`, `NON_COMPLIANT`, `ISO_27001`), l'écran EPSS n'affiche plus d'entités HTML en
  texte (`&gt; 20%`), et la suggestion VEX `under_investigation` de la revue IA s'affiche *En cours
  d'analyse*. Les derniers libellés figés dans une langue suivent la préférence de langue : les étiquettes
  de changement du différentiel d'inventaire, l'état d'un canal de notification, les étiquettes
  « UNPROTECTED » et « HIGH RISK » de la surface d'attaque — désormais « NON PROTÉGÉ » et « RISQUE ÉLEVÉ »
  — et le texte alternatif de l'image du badge.
- **« 1 analyses », « 1 cible(s) » : les nombres s'accordent désormais avec leur nom**, en français
  comme en anglais. Quarante-six messages — analyses planifiées, constats qui seront résolus, entrées
  absentes de la chaîne d'audit, cibles jamais analysées, composants listés, lignes de checklist
  répondues… — étaient écrits au pluriel ou avec « (s) » et le restaient quel que soit le nombre. Chacun a
  désormais un singulier et un pluriel choisis par la règle de la langue : en français 0 prend le singulier
  (« 0 dépôt »), en anglais le pluriel (« 0 repositories »). Les derniers suivent : le verdict de la
  chaîne d'audit, l'avertissement de suppression d'une équipe, le « les lignes 3 demandent encore de
  l'attention » des checklists et les autres messages qui nomment des lignes, et six libellés comptés
  (rayon d'impact, EPSS, licences, fichiers de règles).
- **L'écran des réglages parle français à un lecteur français, et son aide se lit comme du texte.**
  Vingt et un réglages montraient au lecteur français le libellé et l'aide anglais du serveur — l'URL, le
  compte, le type de ticket, les étiquettes et l'interrupteur d'URL interne du gestionnaire de tickets,
  les canaux Slack, Discord et e-mail, le seuil des notifications, la durée de conservation des preuves,
  la visibilité des cibles, les licences interdites, le périmètre certifié et la règle des quatre yeux
  notamment — et l'aide française du fournisseur de tickets citait encore des valeurs qui n'existent plus ;
  chacun a désormais la sienne. Dix-sept aides anglaises affichaient des astérisques de markdown en
  toutes lettres (`**in place of**`) ; elles sont écrites sans. L'aide du fournisseur nomme désormais
  les cinq valeurs (`gitlab`, `github`, `jira`, `servicenow`, `none`), et celles du compte et des
  étiquettes disent ce qu'en fait ServiceNow. La fenêtre *Imports* d'un dépôt dimensionne ses titres
  *Dernière couverture*, *Dernier rapport de tests* et *Imports SARIF* en titres de section plutôt
  qu'en titres de page.
- **Les écrans nomment l'OWASP Top 10:2021, et ne revendiquent pas plus que ce que fait l'outil.**
  Vectispire classe selon l'édition 2021 seulement, et le menu, les pages de couverture, la carte de
  chaleur, le filtre des issues, le catalogue des jeux de règles, le PDF de posture et l'API de couverture
  disaient « OWASP Top 10 » sans l'édition ; ils disent désormais *OWASP Top 10:2021*. *SOC 2 Type II* — le
  rapport d'un auditeur sur une période, qu'aucun outil ne produit — devient *SOC 2* ; le journal d'audit
  dit « immuable » est à altération détectable ; *Télécharger le coffre de preuves* devient *Télécharger le
  paquet de preuves*. Les titres des contrôles CRA citent le règlement (UE) 2024/2847 tel qu'adopté —
  article 14, paragraphe 1, pour les vulnérabilités activement exploitées, annexe I partie II, article 13 —
  là où ils suivaient les articles 10 et 11 de la proposition de 2022 ; leurs codes (`CRA-ART10-*`,
  `CRA-ART11-*`) sont enregistrés avec chaque déclaration et chaque évaluation, et restent. Les
  descriptions du document OpenAPI ont suivi ; aucun champ n'a bougé.
- **Les licences de l'interface voyagent désormais avec elle.** `ng build` écrit les notices des
  paquets npm qu'il embarque (Angular, Optimus UI, chart.js…, MIT pour la plupart) à côté du dossier
  `browser/`, et seul ce dossier arrivait dans le jar et l'image ; la notice MIT du shell (Sparked,
  le gabarit Sakai de PrimeTek porté sur Optimus UI — du code recopié, pas un paquet) n'était livrée
  nulle part non plus. Les deux sont maintenant dans le jar sous `static/licenses/`
  (`3rdpartylicenses.txt`, `sparked/LICENSE.md`), `NOTICE` nomme le shell, et le build refuse un
  bundle qui aurait perdu l'une ou l'autre.

### Performances

- **Deux colonnes des issues sont indexées (migration V90).** `t_issue.ticket_ref`, que le webhook des
  tickets cherche à chaque livraison et que le balayage des tickets lit pour les issues qui n'en portent
  aucune, et `t_issue.triage_expires_at`, que le tic de maintenance lit pour les dates de réexamen passées :
  les deux lisaient toute la table.
- **Le classement de maturité du tableau de bord ne relit plus les SBOM de tout le parc à chaque
  affichage.** Son terme de licences — cinq points par licence refusée, comme sur la fiche de score de
  chaque cible — était compté sur tout l'inventaire des licences à chaque ouverture de la page : le SBOM
  de chaque analyse relu et chaque ligne de composant lue, pour un lecteur à qui cinq cibles sont
  attribuées comme pour un administrateur. Mesuré sur deux cents cibles de deux analyses et 250
  composants chacune, un affichage coûtait environ 420 ms ; il en coûte désormais 30 à 50. Les licences de
  chaque cible sont comptées une fois, puis recomptées seulement quand ses analyses changent — une nouvelle
  analyse, un SBOM retiré par la purge de rétention, une cible supprimée — et un changement de politique
  de licences s'applique dès l'affichage suivant. Les scores du classement ne changent pas, à une
  précision près : quand deux analyses d'une cible déclarent le même composant sous des licences
  différentes, c'est désormais la licence de la plus récente qui est retenue, dans le classement comme
  dans l'inventaire des licences, là où elle dépendait de l'ordre de lecture des analyses.
- **La fiche de score du portefeuille et l'écran des licences ne relisent plus l'historique du parc pour
  ce que ces décomptes comptent déjà.** Le terme de licences de la fiche du portefeuille, le résumé des
  licences de tout le parc et celui du dossier de preuves sont des comptes par licence, désormais tirés
  des mêmes décomptes par cible que le classement ; les analyses rattachées à aucune cible sont
  décomptées ensemble et ne comptent, comme avant, que pour un lecteur qui voit tout le parc. Un lecteur
  à qui des cibles sont attribuées voit son inventaire des licences lu sur les analyses de ses seules
  cibles, là où chaque analyse, chaque composant et chaque constat de licence de l'installation étaient
  lus puis filtrés. Sur le même parc, chacun de ces appels coûtait de 340 à 840 ms, pour l'un comme pour
  l'autre lecteur ; une fois les décomptes faits, la fiche du portefeuille coûte désormais 40 à 55 ms, un
  résumé environ 20 et l'inventaire d'un lecteur restreint environ 25. L'inventaire des licences et les
  conflits de licences de tout le parc, pour un administrateur, relisent toujours le SBOM de chaque
  analyse et chaque ligne de composant, puisqu'ils listent une ligne par composant de chaque analyse,
  mais seulement les colonnes utiles : 220 à 350 ms au lieu de 380 à 620. Les réponses ne changent pas
  — mêmes entrées, mêmes comptes, même score pour un administrateur et pour un lecteur restreint — à une
  précision près : quand un composant que le SBOM ne déclare pas a des lignes dans deux analyses d'une
  cible avec des URL de paquet différentes, c'est désormais celle de la plus ancienne qui est affichée,
  là où elle dépendait de l'ordre dans lequel la base rendait les lignes.

## 0.10.0 — 1er octobre 2026

Lisez d'abord **Avant la mise à jour** : cinq de ses points arrêtent
quelque chose tant qu'un opérateur n'a pas agi, et c'est voulu.

### Avant la mise à jour {#avant-la-mise-a-jour-0100}

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
