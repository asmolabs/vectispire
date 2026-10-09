# Réglages

L'essentiel de la configuration d'exécution vit **dans la base de données** et s'édite ici une
fois l'application lancée — enrichissement, fin de support, rétention, notifications, licences,
tracker, revue par modèle.

Un réglage n'apparaît sur cette page qu'à partir du moment où un service le lit réellement.
Cette règle empêche l'écran de devenir un musée d'options qui ne font rien.

Seul ce qui est nécessaire pour atteindre cet écran est une variable d'environnement. Voir
[Configuration](../reference/configuration.md).

## Qui peut changer quoi

Un CISO écrit l'essentiel de cette page, mais **pas la destination d'un identifiant**. Le jeton du
tracker et la clé OpenAI ne sont réglés que par un administrateur ; les réglages qui décident où
ils partent — l'URL du tracker, *Autoriser une URL de tracker privée*, l'URL OpenAI et
l'acceptation qui laisse partir le code vers un point d'accès distant — sont donc aussi ceux d'un
administrateur, et s'affichent en lecture seule pour les autres. Sans cela, un rôle qui ne peut pas
lire un identifiant pourrait le recueillir en le dirigeant vers son propre hôte.
*Autoriser une destination SIEM privée* revient à un administrateur pour une raison voisine : l'export
SIEM est configuré et testé par un CISO, et l'interrupteur qui décide s'il peut joindre le réseau
interne n'est pas laissé au même rôle.

Trois paramètres décident des règles plutôt que des réglages et reviennent au seul **gouverneur de
plateforme** — qui voit quelles cibles, si un triage demande [deux personnes](four-eyes.fr.md), et si
Vectispire répond aux lignes mesurées d'une checklist (ci-dessous) : qui agit sous une règle ne la lève
pas.

Le formulaire SIEM fonctionne à l'inverse, parce que le même rôle y règle le point d'arrivée et
l'en-tête : changer le point d'arrivée **efface l'en-tête enregistré**, sauf si un nouveau est saisi
avec lui. Un en-tête est émis pour un collecteur. Il n'est envoyé qu'avec le webhook, et refusé avec
un protocole syslog — voir l'[export SIEM](../integrations/siem.md) pour les protocoles, le point
d'arrivée que chacun lit et les événements envoyés.

## Longueur d'une valeur

Un réglage texte contient jusqu'à 16 000 caractères, et un identifiant — le jeton du tracker, les
secrets de webhook, la clé OpenAI — jusqu'à 8 192. Au-delà, le formulaire refuse avec un message.
Les vrais jetons sont bien plus courts : avant cette limite, un identifiant de plus de 160 caractères
environ ne pouvait pas être enregistré du tout.

## Intervalle de réanalyse par défaut {#default-rescan-interval}

Sur l'onglet **Scanners**, sous *Planification des analyses* : la fréquence de réanalyse d'un dépôt ou
d'une image qui n'a ni intervalle ni expression cron — c'est-à-dire toute cible ajoutée sans toucher
à sa planification. **Sept jours** sauf changement (0.11.0). L'intervalle ou l'expression d'une cible
l'emporte toujours, et une cible en *manuel uniquement* n'est jamais réanalysée.

Chaque cible a son propre moment dans l'intervalle, dérivé de son identifiant : un parc de mille
cibles est étalé sur la semaine — quelques-unes par heure — au lieu d'être mis en file en une minute,
et chacune garde son moment d'un passage à l'autre. Un passage est sauté quand un scan de la cible
attend déjà ou est en cours.

**Zéro : pas de défaut** — une cible sans planification propre n'est alors plus réanalysée, comme
dans toutes les versions avant la 0.11.0. Changer la valeur déplace les moments ; l'activer après une
période à zéro rend dues d'un coup toutes les cibles jamais planifiées : attendez-vous à une heure
chargée.

## Enrichissement

Scores EPSS et statut CISA KEV, tous deux lus dans des copies que le plan de contrôle synchronise —
le catalogue de la CISA toutes les six heures, le fichier EPSS quotidien du FIRST une fois par jour,
ou les miroirs que désignent `VECTISPIRE_KEV_URL` et `VECTISPIRE_EPSS_URL`
([Configuration](../reference/configuration.md#threat-intelligence)) — chacun affiché avec sa date
dans l'onglet **Threat Intelligence**. Un scan n'interroge ni l'un ni l'autre : la liste des CVE
d'un dépôt ne quitte jamais le plan de contrôle.

Un déploiement isolé du réseau garde l'enrichissement actif et pointe les deux variables vers des
miroirs internes au parc. Le désactiver vous coûte la capacité de classer par exploitabilité, qui
est le classement qui fonctionne — voir [Lire les résultats](../getting-started/reading-results.md).

## Fin de support

Le catalogue endoflife.date, qui transporte des noms de produits et des versions. La couverture
est délibérément limitée aux produits — langages, exécutions, cadriciels, distributions —
plutôt qu'à chaque bibliothèque.

## Licences

La liste de blocage évaluée contre les données du SBOM. Ce qui doit y figurer est la décision
de votre organisation : l'AGPL est fatale pour un produit propriétaire distribué et sans objet
pour un service interne jamais livré.

## Checklists de sécurité

**Répondre automatiquement aux lignes mesurées des checklists** (`checklist_auto_answer`, **activé par
défaut**) décide si Vectispire répond aux lignes d'une [checklist de sécurité](../guide/security-checklists.fr.md#reponses-automatiques)
en brouillon qu'une règle mesure — *oui* quand la mesure est atteinte, *non* avec la mesure pour
commentaire quand elle ne l'est pas, rien sans données — quand une analyse ou un import se termine sur
l'un des dépôts du projet, et quand une checklist est ouverte ou passée à une autre version. Ses
réponses sont marquées comme étant de Vectispire, ne remplacent jamais celle d'une personne, et la
soumission comme l'approbation restent des actes de personnes.

Il décide qui peut écrire une réponse dans un document que des personnes signent : c'est une règle et
non un paramètre, **seul un gouverneur de plateforme le change**, et un changement est audité et
signalé au SIEM comme paramètre de sécurité. Désactivé, plus rien n'est répondu automatiquement ; les
réponses déjà écrites restent jusqu'à ce que quelqu'un y réponde par-dessus, et la réponse « comme
mesuré » en un clic demeure.

## Rétention

Combien de temps les scans et leurs artefacts bruts sont conservés, et — à part — combien de
temps les preuves le sont : *Evidence kept for (days)* (`evidence_retention_days`). Voir
[Rotation et purge](maintenance.md).

## Notifications

Destinations webhook, Teams et courriel, leurs secrets, et le rapport de posture hebdomadaire.
Couvert sous [Notifications](../integrations/notifications.md).

## Tracker

GitLab ou Jira : URL, projet, jeton. Couvert sous [Tickets](../integrations/ticketing.md).

## Revue de code par IA

Désactivée par défaut. Un modèle de langage relit le code source avec une invite d'« architecte
sécurité », en complément léger de Grype, gitleaks et checkov — et non en remplacement d'aucun
d'eux. Une fois activée, elle s'exécute sur les scans de dépôt, et son résultat narratif ainsi que
ses constats normalisés apparaissent dans le détail du scan. Ses constats sont marqués comme venant
d'un modèle et exclus de la barrière par défaut : le code relu est écrit par qui est audité, et peut
chercher à orienter le modèle.

**Le fournisseur décide où va le code** (`ai_review_provider`) :

- **`ollama`** (le défaut) — un modèle sur une machine que vous exploitez.
- **`openai`** — tout point d'accès parlant le protocole chat-completions d'OpenAI, à
  `ai_review_openai_url` (par défaut `https://api.openai.com/v1`), avec `ai_review_openai_key`
  (conservée chiffrée, jamais renvoyée) et `ai_review_model`. Laissé à l'adresse d'OpenAI, **le code
  source de chaque dépôt analysé — privés compris, et tout secret encore commité dedans — est envoyé
  à OpenAI**, un tiers qui y applique sa propre conservation et sa propre juridiction. Vérifiez ce que
  dit votre contrat avec le fournisseur sur la conservation et l'entraînement, et si le code que vous
  analysez est à vous d'envoyer. Pointé vers vLLM, LM Studio, llama.cpp ou une passerelle interne, le
  code reste sur votre réseau.

**Un point d'accès public est refusé tant qu'il n'est pas reconnu.** Les deux URL passent par la garde
sortante ; une destination hors de votre réseau — l'API d'OpenAI, ou un Ollama public — exige
le réglage **Allow a public model endpoint** (`ai_review_allow_remote_url`, désactivé par défaut).
L'activer enregistre, côté serveur, le compte qui a accepté le risque et la date
(`ai_review_risk_acknowledged_by` / `_at`, et le journal d'audit) ; le désactiver les efface.
`ai_review_timeout_seconds` (300 par défaut) borne l'attente.

### Avec Ollama

Posez l'URL d'Ollama (`ai_review_ollama_url`, par défaut `http://localhost:11434`) et choisissez un modèle. La liste
est lue en direct depuis le `/api/tags` d'Ollama, si bien que ce que vous avez réellement
téléchargé s'y trouve. Si Ollama est injoignable, la liste déroulante retombe sur deux
suggestions plutôt que d'être vide — ce qui est aussi le symptôme à reconnaître.

Il n'y a délibérément aucun réglage pour dire *où* Ollama tourne. En natif ou en conteneur,
Vectispire lui parle en HTTP simple dans les deux cas, et le choix concerne l'accès au GPU sur
votre hôte plutôt que quoi que ce soit que Vectispire fasse.

```bash
ollama pull gemma4:12b-it-qat   # ~7,2 Go, ~9–10 Go de RAM/VRAM — recommandé
ollama pull gemma4:e4b-it-qat   # ~6,1 Go, plus léger et plus rapide, revue de moindre qualité
```

!!! note "Apple Silicon"
    Docker Desktop n'a ni passage GPU ni Metal sur Apple Silicon : un Ollama en conteneur y
    tourne uniquement sur processeur et l'inférence est nettement plus lente. Installez-le en
    natif sur ces machines.

## Personnalisation

`VECTISPIRE_BRAND_NAME` pose le nom d'instance affiché dans l'en-tête, dans les rapports PDF et
dans les exports SARIF, VEX et CSAF.
