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
d'hôte est active — au moyen du magasin de confiance de l'environnement Java. Un collecteur dont le
certificat vient d'une autorité privée demande que cette autorité soit importée dans ce magasin (pour
l'image conteneur, un `cacerts` monté par-dessus celui de la JVM) ; il n'existe pas encore de réglage
d'autorité par collecteur.

### L'en-tête d'autorisation est réservé au webhook

Un webhook peut porter un en-tête `Authorization` — `Bearer <jeton>`, `Splunk <jeton_hec>` —
conservé chiffré. Une trame syslog n'a nulle part où le mettre : le champ est masqué pour les
protocoles syslog, et un en-tête envoyé avec l'un d'eux est refusé. Diriger l'export vers un nouveau
point d'arrivée efface l'en-tête enregistré, à moins de le saisir à nouveau : un en-tête est émis pour
un collecteur.

### Collecteurs privés

Un collecteur sur un réseau privé — le cas habituel — est refusé tant que **Autoriser une URL de
webhook privée** n'est pas activé, comme pour toute destination sortante. L'adresse de métadonnées du
nuage, le proxy du démon Docker et la base de données sont refusés quel que soit ce réglage, en syslog
exactement comme en webhook : l'adresse vers laquelle un nom se résout est vérifiée une fois, et la
connexion est ouverte vers cette adresse-là.

## Sévérité minimale

Chaque événement porte une sévérité CEF de 0 à 10. La sévérité minimale garde les bandes qui
l'atteignent :

| Réglage | Transmet |
|---|---|
| Critique | 9–10 |
| Élevée (par défaut) | 7–10 |
| Moyenne | 4–10 |
| Faible | tout |

Le test de connexion part toujours, quel que soit le seuil.

## Livraison

Un événement est écrit dans l'**outbox, dans la même transaction** que le changement qui l'a causé,
et le planificateur l'envoie **après la validation de cette transaction** — en moins d'une minute par
défaut. Rien n'est envoyé sur le chemin de la requête : une connexion, une ingestion de scan ou une
synchronisation n'attendent jamais votre collecteur.

- **Un changement annulé n'envoie rien.**
- **Un collecteur indisponible est relancé** selon l'attente croissante de l'outbox — huit tentatives
  sur environ quatre heures — puis marqué en échec, où il reste visible.
- **La livraison est au moins une fois.** Un collecteur peut accepter un événement et
  l'enregistrement de cette acceptation échouer : un événement peut donc arriver deux fois.
  Dédupliquez sur `externalId`, identique sur chaque copie.
- **La destination est lue au départ de l'événement.** Corriger une coquille dans le point d'arrivée
  livre ce qui attendait ; couper l'export abandonne ce qui était en file. Le couper n'envoie aucun
  événement « export coupé » — alertez sur l'absence du flux.
- **Les événements de sécurité viennent du journal d'audit.** Un événement existe quand son entrée
  d'audit existe, et porte le même acteur, la même adresse et la même cible.

## Catalogue des événements

L'identifiant de signature est un contrat : les règles de corrélation s'écrivent dessus, et il ne
changera pas de sens.

| Signature | Nom | Sévérité CEF | Émis quand |
|---|---|---|---|
| `ZAN-SEC-002` | Actively exploited vulnerability (KEV) detected | 10 | la synchronisation du renseignement sur les menaces trouve un constat surveillé nouvellement listé par la CISA (KEV) |
| `ZAN-SEC-003` | Security gate refused a build | 7 | un verdict de gate CI est un échec |
| `ZAN-SEC-005` | Finding settled by triage | 5 | un constat est déclaré non affecté ou corrigé sans passer par l'approbation, à la main ou par import VEX |
| `ZAN-SEC-006` | MFA backup code consumed | 6 | un code de secours est consommé |
| `ZAN-SEC-007` | Sign-in failure ceiling reached | 7 | le limiteur de connexion par mot de passe refuse une tentative |
| `ZAN-SEC-008` | MFA failure ceiling reached | 7 | un défi de second facteur est détruit après trop de codes faux, ou le second facteur du compte se verrouille |
| `ZAN-SEC-009` | Bearer token failure ceiling reached | 7 | une adresse épuise son quota de jetons refusés (une fois par fenêtre) |
| `ZAN-SEC-010` | Account privileges or credentials changed | 6 | un compte est créé, supprimé, change de rôle, d'activation, de mot de passe, de second facteur ou de cibles visibles — depuis l'écran ou par SCIM |
| `ZAN-SEC-011` | Team access grant changed | 6 | les membres ou les cibles d'une équipe changent |
| `ZAN-SEC-012` | API key issued | 5 | une clé d'intégration est émise |
| `ZAN-SEC-013` | API key revoked | 4 | une clé d'intégration est révoquée |
| `ZAN-SEC-014` | Agent declared or its credentials changed | 6 | un agent est déclaré, activé, désactivé, supprimé, ou sa clé de signature épinglée ou retirée |
| `ZAN-SEC-015` | Agent result refused: attestation did not verify | 8 | le résultat signé d'un agent ne se vérifie pas |
| `ZAN-SEC-016` | Four-eyes triage request approved | 5 | une seconde personne tranche une demande en attente |
| `ZAN-SEC-017` | Four-eyes triage request refused | 4 | une demande en attente est renvoyée |
| `ZAN-SEC-018` | Audit log integrity verification failed | 10 | une vérification trouve la chaîne de hachage rompue ou des entrées manquantes dans la table |
| `ZAN-SEC-019` | Security-relevant setting changed | 6 | l'export SIEM lui-même, une politique de gate, la visibilité, le double contrôle, un interrupteur d'URL privée ou de modèle distant, une destination de tracker ou de modèle, ou un secret enregistré change |
| `ZAN-SEC-999` | SIEM connector health check | 1 | le test de connexion |

Les noms d'événements restent en anglais : ce sont ceux que reçoit le SIEM.

L'authentification unique, l'exigence de second facteur pour elle et les hôtes Git autorisés se
règlent par variables d'environnement et ne changent qu'au redémarrage : ils n'émettent aucun
événement, leur changement est un déploiement et non un réglage.

### Champs CEF

```
CEF:0|Vectispire|ASPM|<version>|ZAN-SEC-007|Sign-in failure ceiling reached|7|rt=1790416800123 outcome=failure suser=alice src=203.0.113.7 act=LOGIN_BLOCKED cs1Label=Target cs1=alice cs2Label=UserAgent cs2=curl/8.5 externalId=5b1c… msg=Attempt refused by the throttle (300s to wait)
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
