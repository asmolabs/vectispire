# Supervision

Le plan de contrôle publie ses métriques au format texte de Prometheus sur `/actuator/prometheus` : la
file d'attente, l'issue des scans et les agents, plus ce que Spring Boot mesure déjà — la JVM, les
requêtes HTTP et le pool de connexions à la base. Chaque série porte un label `application` qui nomme
l'instance, pour que les chiffres d'une flotte ne soient pas additionnés en une seule ligne.

## Qui peut la lire

La page n'est **jamais anonyme**. Elle répond :

- **au jeton de collecte**, envoyé comme bearer : `Authorization: Bearer <jeton>`. Il n'est reconnu que
  sur `/actuator/prometheus` — sur toute autre route, c'est un jeton inconnu, refusé comme tel ;
- **à la session d'un administrateur**, pour un coup d'œil à la main. Aucune autre session, clé d'agent
  ou clé d'intégration ne l'ouvre.

Les sondes de santé (`/actuator/health`, `/actuator/health/liveness`, `/actuator/health/readiness`)
restent ouvertes à tous : la sonde d'un conteneur n'a pas d'identifiant. `/actuator/metrics`, qui liste les
mêmes mesures une à une, reste réservé aux administrateurs.

Le jeton, d'au moins 32 caractères, se fixe de trois façons :

| Où | Comment |
|---|---|
| Environnement | `VECTISPIRE_METRICS_SCRAPE_TOKEN` |
| Un fichier — **à préférer en production** | `VECTISPIRE_METRICS_SCRAPE_TOKEN_FILE=/run/secrets/scrape_token` |
| Helm | un secret Kubernetes nommé par `secrets.metricsScrapeToken.secretName` (clé `metrics-scrape-token`) |

Générez-le avec `openssl rand -base64 32`. Un jeton plus court arrête l'application au démarrage, de même
qu'un fichier illisible. Le fichier est relu à chaque collecte : un secret renouvelé prend effet sans
redémarrage. Sans jeton, la page ne répond qu'à la session d'un administrateur.

## La collecter

```yaml
# prometheus.yml
scrape_configs:
  - job_name: vectispire
    metrics_path: /actuator/prometheus
    scheme: https
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/vectispire-scrape-token
    static_configs:
      - targets: ["vectispire.example.org"]
```

Chaque instance tient ses propres chiffres : collectez chaque réplica plutôt que le répartiteur placé
devant eux, qui vous ferait lire une instance au hasard.

**Kubernetes.** Le chart ne livre pas de `ServiceMonitor` — il exigerait les définitions de ressources de
l'opérateur Prometheus sur chaque cluster où le chart est installé. Avec l'opérateur, appliquez-en un à
côté de la release, qui lit le même secret que le plan de contrôle :

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: vectispire
  namespace: vectispire
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: vectispire
      app.kubernetes.io/component: control-plane
  endpoints:
    - port: http
      path: /actuator/prometheus
      interval: 30s
      authorization:
        type: Bearer
        credentials:
          name: vectispire-metrics      # le secret que nomme secrets.metricsScrapeToken
          key: metrics-scrape-token
```

Avec `networkPolicy.enabled`, ajoutez le namespace de Prometheus à `networkPolicy.ingressFrom`, sinon la
collecte n'atteint jamais le port 3180.

## Les métriques

Noms tels que Prometheus les affiche. Aucun label ne nomme un dépôt, une cible, un utilisateur ou un
agent : chaque label prend deux ou trois valeurs, quelle que soit la taille du parc.

### La file d'attente

| Métrique | Labels | Ce qu'elle dit |
|---|---|---|
| `vectispire_scans_queued` | `kind` (`repository`, `container`) | Scans en attente d'être pris, y compris ceux qui purgent un délai avant nouvel essai. Additionnée sur `kind`, la file. |
| `vectispire_scans_queued_oldest_age_seconds` | `kind` | Depuis combien de temps attend le plus ancien scan en file ; 0 quand rien n'attend. Le chiffre sur lequel alerter : une file peut être courte et bloquée. |
| `vectispire_scans_running` | | Scans pris et pas encore rendus. |
| `vectispire_scans_credential_unserved` | | Scans en attente de dépôts portant un identifiant qu'aucun exécutant habilité à le recevoir ne peut prendre — voir [Agents](agents.md). 0 est sain ; toute autre valeur attend un opérateur. |
| `vectispire_outbox_pending` | | Notifications acceptées mais pas encore remises. |

### Les scans

| Métrique | Labels | Ce qu'elle dit |
|---|---|---|
| `vectispire_scans_started_total` | `kind`, `executor` (`embedded`, `agent`) | Tentatives confiées à un exécutant : le worker intégré qui en démarre une, ou un agent qui reçoit sa tâche. Un scan retenté trois fois compte trois. |
| `vectispire_scans_completed_total` | `kind`, `executor` | Tentatives terminées avec leurs résultats écrits. |
| `vectispire_scans_failed_total` | `kind`, `executor`, `final` (`true`, `false`) | Tentatives terminées sans résultat. `final="true"` : le scan a échoué pour de bon — définitivement, ou ses tentatives sont épuisées. `final="false"` : il est retourné dans la file, ou un autre worker l'avait repris. |
| `vectispire_scans_lapsed_total` | `final` | Scans dont l'exécutant s'est tu jusqu'à l'expiration du bail, repris par le plan de contrôle : remis en file, ou en échec définitif. Aucun exécutant ne les signale, donc rien d'autre ne les compte. |
| `vectispire_scans_duration_seconds` | `kind`, `executor`, `outcome` (`completed`, `failed`) | Durée réelle de la prise au résultat (nombre, somme et maximum). |

Chaque compteur existe à 0 dès le démarrage : une alerte sur `rate()` se déclenche au premier échec et non
au deuxième. Une tentative prise pour un agent qui a raccroché avant de la recevoir est comptée dans
`vectispire_agents_claims_total{outcome="undelivered"}`, pas ici.

### Les agents

| Métrique | Labels | Ce qu'elle dit |
|---|---|---|
| `vectispire_agents_enabled` | | Agents qu'un administrateur a activés. |
| `vectispire_agents_online` | | Agents activés qui se sont manifestés dans les deux dernières minutes — la règle de l'écran **Agents**. |
| `vectispire_agents_last_seen_age_seconds` | | Depuis combien de temps l'agent activé le moins récemment vu est silencieux — depuis sa création s'il n'a jamais interrogé ; 0 quand aucun n'est activé. Un seul agent arrêté est le cas sur lequel alerter, et une moyenne le cacherait. |
| `vectispire_agents_polls_total` | `outcome` (`job`, `idle`) | Long polls répondus avec une tâche, ou sans rien. |
| `vectispire_agents_claims_total` | `outcome` (`delivered`, `undelivered`, `withheld`) | Ce qu'est devenu un scan pris pour un agent : remis ; pris après que l'agent a raccroché et remis aussitôt en file (un proxy qui coupe le long poll, quand ce chiffre monte) ; ou refusé par un 412 parce que l'agent n'a pas de clé vérifiée pour l'identifiant qu'il lui faudrait. |

### La fraîcheur des chiffres

Les jauges qui comptent des lignes — la file, les scans en cours, l'outbox, les agents — **n'interrogent
pas la base à la collecte.** Elles rapportent ce que le tick d'ordonnancement du plan de contrôle a compté,
une fois par minute (`vectispire.jobs.scheduler-interval`), et une collecte le lit sans connexion : une
collecte qui en demanderait une attendrait le pool précisément quand il est épuisé, et les séries
disparaîtraient pendant l'incident pour lequel elles existent. Les âges sont calculés à la collecte : le
plus ancien scan en file continue de vieillir entre deux ticks.

| Métrique | Labels | Ce qu'elle dit |
|---|---|---|
| `vectispire_metrics_snapshot_age_seconds` | `source` (`scans`, `agents`) | L'âge de ces chiffres. Il reste sous la minute et demie ; s'il grandit, le tick s'est arrêté, et les chiffres ci-dessus sont les derniers qu'il a lus. |

Avant le premier tick, une demi-minute après le démarrage, ces jauges valent `NaN` : pas encore mesurées.

### Ce qu'ajoute Spring Boot

`jvm_*` (mémoire, ramasse-miettes, threads, classes), `process_*` et `system_*`, `hikaricp_*` (le pool de
connexions à la base : `hikaricp_connections_pending` au-dessus de zéro signifie que des requêtes
attendent une connexion — voir [Dimensionnement](sizing.md)), `http_server_requests_seconds` (par modèle
de route, méthode et statut), et `application_ready_time_seconds`.

## Alertes suggérées

```yaml
groups:
  - name: vectispire
    rules:
      - alert: VectispireQueueStuck
        expr: max by (instance) (vectispire_scans_queued_oldest_age_seconds) > 3600
        for: 15m
      - alert: VectispireAgentSilent
        expr: vectispire_agents_last_seen_age_seconds > 600
        for: 5m
      - alert: VectispireScansFailingForGood
        expr: sum(rate(vectispire_scans_failed_total{final="true"}[1h])) > 0
      - alert: VectispireCredentialUnserved
        expr: vectispire_scans_credential_unserved > 0
        for: 30m
      - alert: VectispireMetricsStale
        expr: vectispire_metrics_snapshot_age_seconds > 300
```
