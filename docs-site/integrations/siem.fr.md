# Export SIEM

Vectispire transmet à votre SIEM les événements de sécurité qu'un SOC surveille — une vulnérabilité
activement exploitée dans votre parc, une construction refusée par la gate, un plafond de force brute
atteint, une décision de privilège ou de triage, un journal d'audit qui ne se vérifie plus — au format
**ArcSight CEF**, par webhook ou par syslog.

Il se configure dans **Paramètres → Intégrations → SIEM**, par un administrateur ou un responsable
sécurité.

## Protocoles et points d'arrivée

Le protocole choisit le transport, et chaque protocole lit **un seul** format de point d'arrivée :

| Protocole | Point d'arrivée | Ce qui circule |
|---|---|---|
| **Webhook** | une URL `https://` (ou `http://`) | un `POST` JSON `{"cef": "<ligne CEF>"}`, redirections refusées |
| **Syslog UDP** | `hôte:port` | un message RFC 5424 par datagramme |
| **Syslog TCP** | `hôte:port` | RFC 5424, préfixé de sa longueur (RFC 6587) |
| **Syslog TLS** | `hôte:port` | RFC 5424, préfixé de sa longueur, dans TLS 1.2 ou 1.3 |

`hôte:port` est un nom ou une adresse IPv4 suivis d'un port, par exemple
`collector.example.com:6514` ; une adresse IPv6 s'écrit entre crochets, `[2001:db8::1]:514`. Il n'y a
pas de schéma — pas de `syslog+tls://` — et le port est obligatoire, parce que les valeurs par défaut
diffèrent selon le transport (514 en UDP et TCP, 6514 en TLS) et qu'un port deviné est un collecteur
qui ne reçoit rien. Un point d'arrivée mal formé est refusé à l'enregistrement, pas au premier
événement.

L'en-tête syslog porte la facilité 10 (`authpriv`), une sévérité dérivée de la sévérité CEF (très
élevée → critical, élevée → error, moyenne → warning, faible → notice), le nom d'hôte de l'instance,
`vectispire` comme application et l'identifiant de signature CEF en `MSGID`, pour qu'un collecteur
puisse aiguiller sur l'en-tête sans analyser le contenu. Le message n'a pas de marque d'ordre des
octets : les analyseurs CEF attendent `CEF:0|` au premier octet.

!!! warning "UDP ne garantit pas la livraison"
    Un datagramme qui part est compté comme livré ; le réseau peut le perdre sans que rien ne le
    dise. Utilisez TCP ou TLS quand un événement manqué compte.

### TLS

Le certificat du collecteur est vérifié **contre le nom d'hôte saisi** — la vérification du nom
d'hôte est active, quelle que soit la confiance — au moyen du magasin de confiance de l'environnement
Java, ou de la **CA du collecteur** que vous épinglez.

Un collecteur dont le certificat vient d'une autorité privée n'a plus besoin de cette autorité dans
le magasin de l'environnement. Collez le certificat de l'autorité, en PEM (`-----BEGIN
CERTIFICATE-----`), dans **CA du collecteur**, affiché pour *Syslog TLS* seulement. Elle sert alors
**à cette connexion seule, et à la place du magasin de l'environnement** : les autorités publiques ne
sont pas reconnues pour le collecteur, et rien d'autre de ce que Vectispire contacte — trackers,
modèles, webhooks — ne reconnaît l'autorité épinglée. Un paquet d'une racine et de ses
intermédiaires est accepté, jusqu'à 8 certificats et 16 384 caractères.

L'enregistrement refuse ce qui ne fonctionnerait pas ou ferait trop confiance : un certificat qui
**n'est pas une autorité** (le certificat du collecteur lui-même, qui rendrait « de confiance »
quiconque en détient une copie), une autorité **expirée ou pas encore valide**, une autorité dont
l'usage de clé interdit de signer des certificats, tout ce qui n'est pas un certificat — une clé
privée collée par erreur est refusée sans être recopiée dans la réponse — et une autorité envoyée
avec un autre protocole. Une autorité est publique : elle est conservée telle quelle, non chiffrée,
et réaffichée avec son sujet et son expiration. Une autorité épinglée qui expire ensuite n'est plus
reconnue : les événements en file sont abandonnés avec le motif « the pinned SIEM collector CA is
unusable … expired », et le remède est de coller l'autorité renouvelée.

Vider le champ retire l'autorité épinglée ; quitter le protocole *Syslog TLS* la retire aussi. Par
l'API, `tlsCaPem` absent de `PUT /api/v1/siem/config` conserve celle qui est enregistrée, pour qu'un
script écrit avant ce champ ne la retire pas. Le test de connexion vérifie contre l'autorité du
formulaire, enregistrée ou non.

### L'en-tête d'autorisation est réservé au webhook

Un webhook peut porter un en-tête `Authorization` — `Bearer <jeton>`, `Splunk <jeton_hec>` —
conservé chiffré. Une trame syslog n'a nulle part où le mettre : le champ est masqué pour les
protocoles syslog, et un en-tête envoyé avec l'un d'eux est refusé. Diriger l'export vers un nouveau
point d'arrivée efface l'en-tête enregistré, à moins de le saisir à nouveau : un en-tête est émis pour
un collecteur.

### Collecteurs privés

Un collecteur sur un réseau privé — le cas habituel — est refusé tant que **Autoriser une destination
SIEM privée** n'est pas activé. Ce réglage est propre à l'export et **réservé à un administrateur** :
l'export est configuré et testé par un responsable sécurité, et l'interrupteur qui décide jusqu'où il
peut porter n'est pas entre les mêmes mains. Il est désactivé par défaut. Jusqu'en septembre 2026,
l'export suivait *Autoriser une URL de webhook privée*, qu'un responsable sécurité peut régler ; une
installation dont le collecteur est privé doit faire activer le nouveau réglage par un administrateur
après la mise à jour, sans quoi les événements sont refusés et l'outbox le signale.

Ce réglage est celui du SIEM, et n'est hérité d'aucun autre canal : ni *Autoriser une URL de webhook
privée* (notifications) ni *Autoriser une URL de tracker privée* n'ouvrent le réseau interne à
l'export. Son changement est audité (`SETTING_UPDATED`) et transmis comme `VECTI-SEC-019`.

L'adresse de métadonnées du nuage, le proxy du démon Docker et la base de données sont refusés quel
que soit ce réglage, en syslog exactement comme en webhook : l'adresse vers laquelle un nom se résout
est vérifiée une fois, et la connexion est ouverte vers cette adresse-là.

### Le test de connexion

Le test envoie l'événement de contrôle par le protocole du formulaire et répond l'une de trois
issues : **délivré**, **refusé par la politique sortante**, ou **non délivré** — le collecteur n'a
pas pu être joint ou n'a pas accepté l'événement. L'erreur de la socket elle-même — une connexion
refusée, un délai dépassé, un statut HTTP — est écrite dans le journal du serveur, pas renvoyée :
elle distingue un port fermé d'un serveur à l'écoute, ce qui ferait du bouton un scanner de chaque
réseau que l'export peut atteindre.

## Sévérité minimale

Chaque événement porte une sévérité CEF de 0 à 10. La sévérité minimale garde les bandes qui
l'atteignent :

| Réglage | Transmet |
|---|---|
| Critique | 9–10 |
| Élevée (par défaut) | 7–10 |
| Moyenne | 4–10 |
| Faible | tout |

La sévérité comparée est celle de l'événement. Chaque type a une sévérité fixe, donnée dans le
[catalogue](#catalogue-des-evenements), sauf `VECTI-SEC-030`, qui prend celle du constat en retard : le
seuil qui transmet la sévérité d'un constat transmet son dépassement.

Le test de connexion part toujours, quel que soit le seuil.

## Livraison

Un événement est écrit dans l'**outbox, dans la même transaction** que le changement qui l'a causé,
et le planificateur l'envoie **après la validation de cette transaction** — en moins d'une minute par
défaut. Rien n'est envoyé sur le chemin de la requête : une connexion, une ingestion de scan ou une
synchronisation n'attendent jamais votre collecteur.

- **Un changement annulé n'envoie rien.**
- **Un événement qui ne peut pas être écrit avec son changement ne coûte pas le changement.** Pour
  un événement signalé par une entrée d'audit, et pour un refus de la barrière, le changement est
  alors écrit seul et l'événement mis en file juste après, dans une transaction à lui — le seul cas
  où un arrêt au mauvais moment peut encore perdre un événement ; le serveur journalise un
  avertissement quand il se produit.
- **Un collecteur indisponible est relancé** selon l'attente croissante de l'outbox — huit tentatives
  sur environ quatre heures — puis marqué en échec, où il reste visible.
- **La livraison est au moins une fois.** Un collecteur peut accepter un événement et
  l'enregistrement de cette acceptation échouer : un événement peut donc arriver deux fois.
  Dédupliquez sur `externalId`, identique sur chaque copie.
- **La destination est lue au départ de l'événement.** Corriger une coquille dans le point d'arrivée
  livre ce qui attendait ; couper l'export abandonne ce qui était en file.
- **Couper l'export, ou le diriger vers un autre collecteur, prévient le collecteur quitté.**
  `VECTI-SEC-028` lui est envoyé aussitôt, par son propre protocole, après l'enregistrement du
  changement et quelle que soit la sévérité minimale — c'est le message qui explique le silence qui
  suit. Il nomme le compte et l'adresse à l'origine du changement, jamais la nouvelle destination. Il
  est envoyé au mieux : un collecteur hors service ne maintient pas l'export allumé. L'entrée d'audit
  du changement dit si l'avis est arrivé (« stop notice delivered to the previous collector », ou
  « NOT delivered », la cause dans le journal du serveur). Un avis qui n'arrive jamais est justement le
  cas sur lequel alerter : continuez d'alerter sur l'absence du flux.
- **Les événements de sécurité viennent du journal d'audit.** Un événement existe quand son entrée
  d'audit existe, et porte le même acteur, la même adresse et la même cible.

## Wazuh

Wazuh lit les événements de Vectispire avec le décodeur et les règles livrés dans
[`ci/siem/wazuh/`](https://github.com/asmolabs/vectispire/blob/main/ci/siem/wazuh), vérifiés sur Wazuh 4.14 avec de vrais événements envoyés en syslog TLS.

- **Transport : Syslog TLS vers un relais rsyslog sur l'hôte Wazuh.** L'écoute syslog de Wazuh ne lit ni
  le TLS ni le cadrage par longueur que Vectispire utilise en TCP et TLS ; rsyslog lit les deux et écrit
  une ligne par événement dans un fichier que Wazuh suit. [`rsyslog-vectispire.conf`](https://github.com/asmolabs/vectispire/blob/main/ci/siem/wazuh/rsyslog-vectispire.conf)
  est le relais (son certificat doit nommer l'hôte saisi dans Vectispire ; épinglez son AC comme AC du
  collecteur), [`ossec-localfile.xml`](https://github.com/asmolabs/vectispire/blob/main/ci/siem/wazuh/ossec-localfile.xml) le bloc à ajouter à `ossec.conf`. Le
  syslog UDP directement vers l'écoute de Wazuh fonctionne aussi, sans chiffrement ni garantie de
  livraison. Le webhook non : Wazuh n'a pas d'entrée HTTP.
- **Décodeur :** [`vectispire_decoders.xml`](https://github.com/asmolabs/vectispire/blob/main/ci/siem/wazuh/vectispire_decoders.xml) dans `/var/ossec/etc/decoders/`.
  Chaque événement donne `vectispire.signature`, `vectispire.name`, `vectispire.severity`,
  `vectispire.action`, `vectispire.outcome`, `vectispire.target`, `vectispire.message`, et les champs
  standard `dstuser` et `srcip`.
- **Règles :** [`vectispire_rules.xml`](https://github.com/asmolabs/vectispire/blob/main/ci/siem/wazuh/vectispire_rules.xml) dans `/var/ossec/etc/rules/`, ID
  120100–120199. Le niveau suit la sévérité CEF — 0–2 → 3, 3–4 → 5, 5–6 → 7, 7–8 → 10, 9–10 → 12 —, si bien
  qu'un nouveau type d'événement est alerté à son poids sans règle propre ; l'échec du contrôle
  d'intégrité du journal d'audit (`VECTI-SEC-018`) monte à 15, les plafonds d'identification
  (`007`–`009`) sont groupés en `authentication_failures` avec MITRE T1110, une détection KEV (`002`) en
  `vulnerability-detector`. Corrélez sur `vectispire.signature`, jamais sur le nom.

Vérifiez une ligne avec `/var/ossec/bin/wazuh-logtest` avant d'activer l'export : la phase 2 liste les
champs, la phase 3 la règle et son niveau.

## Catalogue des événements

L'identifiant de signature est un contrat : les règles de corrélation s'écrivent dessus, et il ne
changera pas de sens. Son préfixe a changé une fois, de `ZAN-SEC-` à `VECTI-SEC-`, dans la
0.10.0 — mêmes numéros, mêmes sens ; voir les [notes de version](../reference/release-notes.md#avant-la-mise-a-jour).

| Signature | Nom | Sévérité CEF | Émis quand |
|---|---|---|---|
| `VECTI-SEC-002` | Actively exploited vulnerability (KEV) detected | 10 | une synchronisation du catalogue CISA KEV — toutes les six heures, ou demandée depuis l'onglet Threat Intelligence — trouve un constat ouvert dont la CVE y est nouvellement listée. Une fois par constat : une CVE déjà marquée n'est pas annoncée à nouveau, et une que le catalogue cesse de lister perd son marquage sans événement |
| `VECTI-SEC-003` | Security gate refused a build | 7 | un verdict de gate CI est un échec |
| `VECTI-SEC-005` | Finding settled by triage | 5 | un constat est déclaré non affecté ou corrigé sans passer par l'approbation, à la main ou par import VEX |
| `VECTI-SEC-006` | MFA backup code consumed | 6 | un code de secours est consommé |
| `VECTI-SEC-007` | Sign-in failure ceiling reached | 7 | le limiteur de connexion par mot de passe refuse une tentative — à la connexion, ou quand un compte connecté change son mot de passe |
| `VECTI-SEC-008` | MFA failure ceiling reached | 7 | un défi de second facteur est détruit après trop de codes faux, ou le second facteur du compte se verrouille |
| `VECTI-SEC-009` | Bearer token failure ceiling reached | 7 | une adresse épuise son quota de jetons refusés — porteur ou `X-API-Key` (une fois par fenêtre) |
| `VECTI-SEC-010` | Account privileges or credentials changed | 6 | un compte est créé, supprimé, change de rôle, d'activation, de mot de passe, de second facteur ou de cibles visibles — depuis l'écran ou par SCIM |
| `VECTI-SEC-011` | Team access grant changed | 6 | les membres ou les cibles d'une équipe changent, un dépôt est classé dans un projet ou déplacé, ou un projet, un dépôt ou une image qui portait des droits est supprimé |
| `VECTI-SEC-012` | API key issued | 5 | une clé d'intégration est émise |
| `VECTI-SEC-013` | API key revoked | 4 | une clé d'intégration est révoquée — à la main, avec le dépôt ou l'image auquel elle était restreinte, ou par la réinitialisation du mot de passe de son compte (un événement par clé) |
| `VECTI-SEC-014` | Agent declared or its credentials changed | 6 | un agent est déclaré, activé, désactivé, supprimé, sa clé de signature épinglée ou retirée, ou sa clé de scellement réinitialisée par un administrateur |
| `VECTI-SEC-015` | Agent result refused: attestation did not verify | 8 | le résultat signé d'un agent ne se vérifie pas |
| `VECTI-SEC-016` | Four-eyes triage request approved | 5 | une seconde personne tranche une demande en attente |
| `VECTI-SEC-017` | Four-eyes triage request refused | 4 | une demande en attente est renvoyée |
| `VECTI-SEC-018` | Audit log integrity verification failed | 10 | une vérification trouve la chaîne de hachage rompue ou des entrées manquantes dans la table |
| `VECTI-SEC-019` | Security-relevant setting changed | 6 | l'export SIEM lui-même, une politique de gate, la visibilité, le double contrôle, un interrupteur d'URL privée ou de modèle distant, une destination de tracker ou de modèle, ou un secret enregistré change |
| `VECTI-SEC-020` | Agent sealing key refused: signature or generation did not verify | 8 | l'annonce de la clé de scellement d'un agent est refusée : sa signature ne se vérifie pas contre la clé de signature épinglée, ou elle est plus ancienne que la clé déjà acceptée ; aucun identifiant n'est scellé pour elle |
| `VECTI-SEC-021` | Analysis plugin registered, changed or activated | 6 | un plugin est enregistré, mis à jour, activé ou désactivé par le gouverneur de la plateforme, autorisé à tourner sans signature ou ne l'est plus, ou activé ou désactivé pour un projet — du code tiers gagne ou perd l'accès en lecture à une partie du source |
| `VECTI-SEC-022` | SARIF import source declared or changed | 6 | une source SARIF est déclarée, activée, désactivée ou supprimée : quelle clé peut déposer des constats, pour quel projet ou dépôt, depuis quels outils |
| `VECTI-SEC-023` | SARIF import refused: undeclared source, scope or tool | 5 | un téléversement SARIF est refusé pour ce qu'il prétend — une clé pour laquelle aucune source n'est déclarée, un dépôt hors du périmètre de sa source, un outil pour lequel sa source n'est pas déclarée |
| `VECTI-SEC-024` | Checklist template version published or retired | 6 | une version de modèle de checklist est publiée, ou une version publiée retirée — ce à quoi chaque projet atteste change. Écarter un brouillon n'est pas signalé |
| `VECTI-SEC-025` | Checklist signed off | 5 | la checklist d'un projet est approuvée — une attestation de mise en production, et qui l'a donnée ; l'entrée dit si le double contrôle exigeait que l'approbateur ne soit aucun de ses auteurs |
| `VECTI-SEC-026` | Checklist sign-off refused or returned | 5 | une approbation est refusée parce que l'approbateur est l'un des auteurs de la checklist sous double contrôle, ou parce qu'une preuve a cessé de tenir depuis la soumission ; ou une checklist soumise est renvoyée à ses auteurs |
| `VECTI-SEC-027` | Report import refused: undeclared source, kind or scope | 5 | un rapport de couverture ou de tests est refusé pour ce qu'il prétend — une clé pour laquelle aucune source active n'est déclarée, un type pour lequel sa source n'est pas déclarée, un dépôt hors du périmètre de sa source |
| `VECTI-SEC-028` | SIEM export switched off or redirected | 7 | l'export est coupé, ou son protocole ou son point d'arrivée change : envoyé de façon synchrone au collecteur quitté, quelle que soit la sévérité minimale (voir [Livraison](#livraison)) |
| `VECTI-SEC-029` | Secret leaked in source code | 8 | un scan trouve un secret de sévérité élevée ou critique qui n'est pas encore un constat — chaque secret que rapporte l'analyseur fourni est classé élevé. Une fois par constat : la même fuite revue par le scan suivant, ou revenue après sa résolution, n'est pas annoncée à nouveau. `cs3` porte la règle, `msg` le fichier ; la valeur trouvée n'est jamais envoyée |
| `VECTI-SEC-030` | Remediation deadline passed | 3–8 | un constat ouvert que personne n'a tranché dépasse son délai de remédiation (première détection + la fenêtre de sa sévérité — voir [Délais de correction](../guide/remediation-delays.md)). Relevé par le tour de maintenance horaire, daté de l'échéance elle-même, une fois par constat. Seules les échéances passées dans les sept derniers jours sont annoncées : le stock déjà en retard à la mise à jour — ou après qu'une fenêtre a été raccourcie — n'est pas annoncé d'un coup ; export coupé, un dépassement n'est pas rejoué quand il est rallumé. **Aussi sévère que le constat en retard** : 8 pour un critique, 7 pour un élevé, 5 pour un moyen, 3 pour un faible — le minimum par défaut (Élevée) transmet donc les dépassements critiques et élevés, Moyenne aussi les moyens. Un événement encore en file lors de la mise à jour depuis 0.10.0, où la sévérité valait 6, part à 6 |
| `VECTI-SEC-031` | Report plugin registered, changed, approved, activated or withdrawn | 6 | un plugin de rapport est enregistré ou reçoit un autre manifeste du gouverneur de la plateforme, un digest de manifeste est approuvé (par une seconde personne sous le double contrôle), le plugin est activé ou désactivé, activé ou désactivé pour un projet, ou un manifeste est retiré ([Plugins de rapport](../administration/report-plugins.fr.md)) — du code tiers gagne ou perd l'accès à l'état trié entier d'un projet, ou le droit de produire des documents sous la clé de l'installation. Le digest est dans le message |
| `VECTI-SEC-032` | Project export left the platform | 4 | l'état trié entier d'un projet a été téléchargé comme son export signé ([Exports](../guide/exports.fr.md#export-de-projet)), ou remis au conteneur d'un plugin de rapport pour une exécution de rapport ([Plugins de rapport](../administration/report-plugins.fr.md#demander-un-rapport)) : qui l'a pris — le demandeur, pour une exécution —, quel projet (la cible est l'identifiant du projet), et le SHA-256 d'`export.json` en tête du message. Une exécution refusée avant le démarrage de son plugin n'a rien remis et n'en lève aucun |
| `VECTI-SEC-033` | Report plugin refused, or its output refused | 6 | un plugin de rapport a été sollicité pour rendre un projet et n'a pas été démarré : le signataire de son image n'a pas été vérifié (`signature_unverified`, `unsigned`), son registre n'a pas pu être lu (`registry_authentication_required`), ou son manifeste lit une version majeure d'export que cette installation ne produit plus ; ou il s'est exécuté et a écrit un fichier qui n'est pas ce que déclare son manifeste — un autre type, une macro, une bombe zip, une page déguisée en CSV — jeté sans signature (`output_refused`, le SHA-256 du fichier dans le message) ([Plugins de rapport](../administration/report-plugins.fr.md#la-verification-de-la-sortie)). C'est ainsi qu'un plugin altéré se trahit. La cible est l'identifiant de l'exécution ; le motif et les mots de cosign ou de la vérification sont dans le message. Une exécution en échec pour une raison ordinaire — un code de sortie, un dépassement de délai — est journalisée, pas signalée |
| `VECTI-SEC-034` | Forge connection created, its token or trust replaced, or deleted | 6 | une connexion en lecture seule à un GitHub ou un GitLab ([Connexions de forge](../administration/forge-connections.fr.md)) a été créée, a reçu un autre jeton, une autre AC épinglée ou une autre déclaration de réseau interne, ou a été supprimée : un accès permanent en lecture à toute la liste des dépôts d'une organisation est apparu, a changé de mains ou a disparu. Le message nomme la forge, l'adresse, le propriétaire, le type de jeton, ses portées et **`CAN WRITE`** pour un jeton classique de GitHub Enterprise Server portant `repo` ; jamais le jeton. Un renommage n'est pas signalé |
| `VECTI-SEC-035` | Repositories imported from a forge | 5 | un administrateur a importé des dépôts depuis la découverte d'une connexion de forge comme cibles ([Connexions de forge](../administration/forge-connections.fr.md#selectionner-et-importer)) : de nombreuses cibles — et les identifiants de clonage qui leur sont attachés — créées d'un seul geste. **Une fois par import, jamais une fois par cible** : le message compte les cibles, solutions et projets créés et les dépôts écartés, dit les premiers scans et l'identifiant de clonage par hôte ; la connexion est la cible. Un import qui n'a rien créé — un rejeu, chaque dépôt déjà présent — est audité et non signalé |
| `VECTI-SEC-036` | Forge connection refused: blocked destination, write scope, or a credential presented to another host | 5 | issue `failure` : une connexion de forge a été refusée parce que son adresse se résout là où aucune connexion ne peut aller — le réseau interne sans que l'administrateur l'ait dit, le point de métadonnées, la base ou le démon Docker de Vectispire — ou parce que la forge déclare son jeton avec une portée au-delà de la lecture (`api`, `write_repository`, `admin:org`…, ou un jeton classique sur github.com). Le premier est l'allure d'une falsification de requête côté serveur par le formulaire, le second d'un identifiant plus large que déclaré. Un jeton mal saisi ou un serveur ancien ne sont pas signalés |
| `VECTI-SEC-999` | SIEM connector health check | 1 | le test de connexion |

Les noms d'événements restent en anglais : ce sont ceux que reçoit le SIEM.

`VECTI-SEC-001` et `VECTI-SEC-004` avaient été déclarés pour une fuite de secret et un dépassement de
SLA sans jamais être émis ; ils restent retirés. Les événements qui portent aujourd'hui ces sens ont
pris de nouveaux numéros, `029` et `030`, pour qu'une règle écrite contre l'ancienne déclaration ne se
mette pas à se déclencher sur une définition pour laquelle elle n'a pas été écrite.

L'authentification unique, l'exigence de second facteur pour elle et les hôtes Git autorisés se
règlent par variables d'environnement et ne changent qu'au redémarrage : ils n'émettent aucun
événement, leur changement est un déploiement et non un réglage.

### Champs CEF

```
CEF:0|Vectispire|ASPM|<version>|VECTI-SEC-007|Sign-in failure ceiling reached|7|rt=1790416800123 outcome=failure suser=alice src=203.0.113.7 act=LOGIN_BLOCKED cs1Label=Target cs1=alice cs2Label=UserAgent cs2=curl/8.5 externalId=5b1c… msg=Attempt refused by the throttle (300s to wait)
```

| Champ | Porte |
|---|---|
| `rt` | le moment, en millisecondes depuis l'époque |
| `outcome` | `success`, `failure` ou `detected`, fixé par type d'événement |
| `suser` | le compte qui a agi, tel que le journal d'audit le nomme |
| `src` | l'adresse du client que l'entrée d'audit a enregistrée (voir la note ci-dessous) |
| `act` | l'opération d'audit (`LOGIN_BLOCKED`, `API_KEY_CREATED`…), ou `GATE_EVALUATED`, `AUDIT_VERIFIED` |
| `cs1` / `cs1Label=Target` | la ressource visée — un constat, un compte, une clé, un réglage, `repository 12` |
| `cs2` / `cs2Label=UserAgent` | l'agent utilisateur de la requête |
| `cs3` / `cs3Label=Identifier` | une CVE, pour un événement KEV |
| `cs4` / `cs4Label=Component` | le paquet, pour un événement KEV |
| `externalId` | l'identifiant du message d'outbox — dédupliquez dessus |
| `msg` | la description de l'entrée d'audit, 1 024 caractères au plus |

La version de l'équipement est la version du produit, vide quand la construction n'en déclare pas.

!!! note "`src` derrière un répartiteur de charge"
    Les événements de connexion, de MFA, de jetons bearer et de gate résolvent l'adresse du client
    au travers de `vectispire.security.trusted-proxies` (voir l'[installation](../getting-started/installation.fr.md)).
    Les changements d'administration — clés, réglages, triage — enregistrent l'adresse vue par le
    serveur, qui derrière un répartiteur est celle du répartiteur. C'est ainsi que le journal d'audit
    les enregistre aujourd'hui, et l'événement dit ce que dit le journal d'audit.

Les valeurs sont échappées comme CEF le demande — `\` et `=` dans les extensions, `\` et `|` dans
l'en-tête, les sauts de ligne en `\n` et `\r` — et tout autre caractère de contrôle devient une
espace. Un nom d'utilisateur saisi comme `x\nCEF:0|…|src=6.6.6.6` arrive sur une seule ligne, avec
`src\=` échappé, et ne peut forger ni un second événement ni un champ.
