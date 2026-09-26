# 0025 — Les événements SIEM partent par l'outbox, après validation, et leur catalogue est un contrat

**Date :** 2026-09-26 · **Statut :** acceptée · **Décideur :** Laurent Boucher

## Contexte

L'export SIEM existait sous forme d'écran de configuration, et de bien peu d'autre chose. Les
réglages proposaient quatre protocoles et une sévérité minimale ; l'exportateur envoyait chaque
événement en POST HTTP quel que soit le protocole, et ne lisait la sévérité nulle part. Son unique
méthode était `@Async` dans une base de code sans `@EnableAsync` : elle s'exécutait donc de façon
synchrone dans son appelant — la synchronisation du renseignement sur les menaces — avant la
validation de cette transaction : un POST qui tenait les verrous de la synchronisation jusqu'à dix
secondes, annonçant une reclassification qui pouvait encore être annulée. Le catalogue déclarait sept
événements ; un seul était jamais émis.

Trois questions devaient être tranchées ensemble : comment un événement part, quels événements
existent, et sur quoi un SOC peut compter pour les deux.

## Décision

- **Un événement est une ligne de `t_outbox_message`, écrite dans la transaction qui l'a causé** —
  type `siem_event` — et envoyée par le relais après la validation, avec la réservation, l'attente
  croissante et l'abandon du relais (`OutboxRetry` : huit tentatives sur environ quatre heures). Le
  relais avait été construit pour les notifications de scan ; il aiguille désormais les types qui ne
  sont pas des notifications vers un `OutboxHandler`, si bien que le SIEM partage la politique de
  livraison sans se faire passer pour un canal de notification. L'alternative — un rappel après
  validation qui envoie directement — a été écartée : elle perd l'événement sur une panne entre la
  validation et l'envoi, ne retente rien, et remet un appel réseau sur le fil de la requête.
- **Un seul point d'accroche : l'entrée d'audit, après sa propre validation.** `AuditLogService`
  prévient ses écouteurs depuis le rappel après validation de la transaction d'audit ; `SiemEvents`
  met en file un événement pour les entrées qui en signalent un. Les opérations sans ambiguïté le
  signalent d'elles-mêmes (`SecurityEventType.signalledBy`, un switch exhaustif) ; celles qui sont
  trop larges — `LOGIN_BLOCKED`, `SETTING_UPDATED`, `ISSUE_TRIAGED`, `ACCESS_DENIED` — sont nommées
  par leur auteur (`Record.signalling`). Les trois événements sans entrée d'audit derrière eux — une
  reclassification KEV, un refus de la gate, une chaîne d'audit rompue — sont mis en file
  explicitement. Acteur, adresse, cible et action viennent de l'entrée, si bien qu'un événement dit
  ce que dit le journal d'audit — y compris son adresse, que toute entrée résout au travers des
  proxys de confiance. (Jusqu'au 2026-09-26, seules la connexion, la MFA, le plafond des jetons bearer
  et la gate le faisaient ; les entrées écrites par `RequestActors` et le gestionnaire de refus
  nommaient le pair. `ClientAddressFilter` résout désormais l'adresse une fois par requête, et
  `ArchitectureTest` refuse toute lecture du pair hors de `TrustedProxies`.)
- **Au moins une fois.** Un collecteur peut accepter un événement et la transaction qui l'enregistre
  échouer ; l'événement est alors renvoyé. Chacun porte l'identifiant de son message d'outbox en
  `externalId` CEF, sur lequel un SOC déduplique. En UDP, « envoyé » veut dire remis au réseau : rien
  ne revient.
- **L'identifiant de signature est un contrat.** Un SOC écrit ses règles de corrélation sur
  `ZAN-SEC-0xx` ; un identifiant changé les désarme en silence, dans le système de quelqu'un d'autre.
  Les identifiants sont figés par un test, jamais réutilisés, et les deux qui étaient déclarés sans
  jamais être émis (001, 004) sont retirés. Seuls les événements émis sont listés.
- **Un format de point d'arrivée par protocole.** Une URL pour le webhook, `hôte:port` pour les trois
  protocoles syslog, port obligatoire, sans schéma — un schéma serait un second endroit où dire le
  transport. Syslog est au format RFC 5424, préfixé de sa longueur (RFC 6587) en TCP et TLS,
  facilité 10, l'identifiant de signature en MSGID. Un hôte syslog passe par le même classificateur
  d'adresses qu'une URL (`OutboundUrlGuard.validateAndResolveEndpoint`) et la socket est ouverte vers
  l'adresse épinglée. TLS vérifie le nom d'hôte contre le magasin de confiance de la JVM, TLS 1.2 au
  minimum.
- **La sévérité minimale suit les bandes CEF** (critique 9–10, élevée 7–8, moyenne 4–6) ; vide ou
  illisible, tout part, et le test de connexion passe toujours. L'en-tête d'autorisation n'est envoyé
  qu'avec le webhook.

## Conséquences

- Un événement atteint le collecteur dans l'intervalle du relais (une minute par défaut), pas
  immédiatement. Un collecteur indisponible reçoit l'arriéré à son retour, dans le budget de quatre
  heures ; au-delà, la ligne est marquée en échec et reste visible.
- Une nouvelle `AuditOperation` ou un nouveau `Setting` ne compile pas tant que son auteur n'a pas dit
  s'il signale un événement au SOC — les switches n'ont pas de cas par défaut, délibérément.
- Couper l'export arrête le flux en silence : aucun événement « export désactivé » n'est envoyé, parce
  que la destination est lue au moment de l'envoi et qu'elle n'existe plus. Les SOC devraient alerter
  sur l'absence du flux.
- Pas d'autorité de certification propre pour TLS : une AC privée va dans le magasin de confiance de
  la JVM. Une AC par collecteur est une suite à donner.
- Aucune migration : l'outbox, la ligne de configuration et leurs colonnes conviennent déjà.
