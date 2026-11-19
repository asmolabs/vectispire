# 0048 — Vectispire 2.0.0 est une réécriture en Rust derrière les contrats externes, pas un portage

**Date :** 2026-11-19 · **Statut :** proposé · **S'appuie sur :** [0003](0003-long-polling-for-agents.md), [0007](0007-none-is-not-an-empty-list.md), [0024](0024-integration-api-keys-act-for-an-account.md), [0043](0043-what-1-0-promises.md), [0045](0045-on-a-cluster-without-docker-agents-run-each-scanner-as-a-pod.md) · **Décideur :** Laurent Boucher

## Contexte

Le 2026-10-16, le responsable produit a demandé « un portage en Rust » de Vectispire : l'agent d'abord, puis tout le
plan de contrôle. Le mot a été pris au pied de la lettre. Le portage du plan de contrôle
(`vectispire-rust/crates/cp-*`) reproduit l'application Java **comportement pour comportement** : chacune des 322
opérations d'`openapi.json`, le même schéma sous le même historique Flyway, et les mêmes octets sur le fil — les phrases
d'erreur de Spring, la lecture d'un champ absent par Jackson, l'arrondi de `BigDecimal`, le décodage d'`URLDecoder`,
l'ordre d'itération d'un `HashMap` Java là où une réponse l'expose. La parité est prouvée en enregistrant le trafic
HTTP de la suite Java et en le rejouant contre le binaire Rust (`cp-contract`, `golden/`) : environ une heure par
exécution complète, avec des enregistrements qu'on ne peut pas rejouer du tout (doublures Mockito, faux serveurs sur la
boucle locale) ou qui dépendent du temps (une fenêtre de limitation par minute).

Au 2026-11-19, le portage servait environ 250 des 322 opérations, pour un coût que le responsable produit n'avait pas
anticipé ; il a précisé ce jour-là ce qui était voulu : **une réécriture en Rust, écrite comme du Rust, pas un
portage**. Le même jour, le portage du plan de contrôle a été mis en pause et tout l'effort Rust est passé sur l'agent.

Trois constats du portage façonnent cette décision :

- **L'essentiel de l'effort achète de la parité, pas du produit.** Une grande part de chaque module reproduit le
  comportement accessoire du framework pour que le rejeu reste vert. Ce travail n'a plus de valeur une fois Java retiré.
- **Le gain de sécurité du plan de contrôle en Rust est modeste.** Java est déjà sûr en mémoire. Rust supprime des
  classes de failles propres à l'écosystème de la JVM — chaînes de désérialisation, liaison par réflexion, langages
  d'expression, résolutions JNDI — et réduit l'image et l'arbre de dépendances. Mais les vrais risques du plan de
  contrôle sont logiques : les quatre pièges d'`AGENTS.md`, les routes qui servaient les données d'autres comptes, le
  refus qui confirmait une existence. Ils sont tenus par des règles et des tests, dans l'un ou l'autre langage.
- **C'est pour l'agent que Rust rapporte le plus.** Il tourne sur les machines des clients, analyse le contenu de
  dépôts et des sorties de scanners non fiables, et parle au plan de contrôle par un contrat déjà externe (0003, 0043
  §2). Son portage est un bon portage : le protocole doit de toute façon rester identique.

## Décision

1. **L'agent reste un portage et sort en premier.** Ses chantiers (recensement de l'espace de travail et découverte
   d'API, greffons et vérification cosign, l'exécuteur Kubernetes de 0045, puis une image reproductible et deux
   semaines de résultats identiques à côté de l'agent Java dans la nightly) sont inchangés. Il ne dépend que du protocole
   d'agent : il sert indifféremment un plan de contrôle 1.x ou 2.0.

2. **Le plan de contrôle de la 2.0 est une réécriture.** Il est conçu et écrit en Rust — des types qui rendent les
   états illégaux irreprésentables, les erreurs comme des valeurs, des transactions explicites, aucune reproduction du
   comportement accessoire de Spring ou de Jackson. **Il ne doit la parité avec la 1.x que sur les contrats externes
   listés au point 3.** Tout le reste — routes internes, formes de réponse que seule l'interface lit, schéma, frontières
   des modules — est repensé.

3. **Les contrats externes sont la frontière, et ils sont listés.** Les intégrations, les agents et les preuves d'une
   installation 1.x doivent continuer à fonctionner, sans changement, face à la 2.0 :

   | Contrat | Aujourd'hui | Ce que « sans changement » veut dire |
   |---|---|---|
   | Protocole d'agent | `/api/v1/agent/*` (9 routes), `AgentContract` `OLDEST_SERVED`–`CURRENT` | un agent 1.x de la mineure précédente réclame, analyse et rend compte face à la 2.0 (le job CI `previous-agent`) |
   | API d'intégration | les 47 routes marquées `@AcceptsApiKey` (0024) : la barrière, les imports SARIF et de rapports, les analyses, les problèmes, l'inventaire, la conformité, les exports, CycloneDX, VEX, CSAF, le conseiller IA | mêmes chemins, méthodes, paramètres, champs de réponse et codes de statut ; une clé d'intégration émise par la 1.x fonctionne toujours |
   | Webhooks entrants | le webhook des gestionnaires de tickets (`/api/v1/tickets/webhook/{provider}`) | même vérification de la signature du fournisseur, mêmes effets |
   | Identité | provisionnement SCIM 2.0, connexion OIDC | un fournisseur d'identité configuré continue de provisionner et de connecter |
   | Formats sortants | SIEM (CEF sur syslog et webhook), webhooks de notification et leur signature, tickets créés | un collecteur, un récepteur ou un gestionnaire de tickets voit les mêmes messages |
   | Contrats de greffons | greffons d'analyse émettant du SARIF (0017), greffons de rapport | une image de greffon construite pour la 1.x tourne sous la 2.0 |
   | Documents | SARIF, CycloneDX (0016), VEX, CSAF, documents de checklist signés, l'export d'audit | un document produit par la 1.x se vérifie toujours ; un document produit par la 2.0 est lu par les mêmes outils |
   | Modèles CI | `ci/gitlab/vectispire-gate.gitlab-ci.yml` et ses pairs | un pipeline qui utilise le modèle ne change pas |
   | Exploitation | la configuration que pose un opérateur (variables d'environnement, propriétés), la collecte Prometheus | une configuration 1.x démarre la 2.0, ou la 2.0 la refuse au démarrage en nommant chaque clé à changer — jamais une valeur par défaut silencieuse |

   Chaque ligne reçoit une **suite de tests de contrat** écrite avant le code qui la sert, exécutée d'abord contre la
   1.x (elle doit y passer) puis contre la 2.0. L'enregistreur de trafic Java peut encore produire les données de ces
   suites, pour les routes externes seulement.

4. **L'interface web reste en Angular.** Elle passe à l'API interne repensée dans les mêmes versions. Une interface en
   Rust (Dioxus, Leptos) n'est pas adoptée : aucune n'a passé la 1.0, et remplacer une interface qui fonctionne — son
   système de design, ses deux langues, sa suite Playwright — achète de la cohérence, rien qu'un utilisateur voie. La
   frontière HTTP laisse la question ouverte pour plus tard.

5. **Les données migrent une fois, vers l'avant, après répétition.** La 2.0 a son propre schéma, sur MySQL seulement
   (comme la 1.0, décision 0043 §3). Un outil de migration lit une base 1.x (dernière migration 1.x, aujourd'hui V102)
   et écrit une base 2.0 ; la base 1.x n'est pas touchée, si bien que revenir en arrière consiste à y rebrancher la 1.x.
   Avant qu'une installation bascule, l'outil tourne sur une copie de ses données et un contrôle compare au moins :
   - les **comptes** de chaque type d'enregistrement ;
   - les **empreintes des problèmes**, identiques — une empreinte changée résout le problème et perd son triage, en
     silence ;
   - le **triage et son historique**, les exceptions et leurs échéances ;
   - la **chaîne du journal d'audit**, vérifiable de bout en bout — les entrées 1.x gardent leurs empreintes, et la
     première entrée 2.0 s'enchaîne à la dernière entrée 1.x ;
   - les **secrets scellés** (clés de déploiement, jetons, clés de signature), lisibles sous la même `ENCRYPTION_KEY` et
     les mêmes contextes, ou rescellés et comptés par le recensement du chiffrement ;
   - les **identifiants sortis du produit** — identifiants de problèmes dans les liens des gestionnaires de tickets et
     les documents exportés, identifiants d'analyse dans le SARIF — conservés, ou mis en correspondance avec la table
     publiée.

6. **Les leçons de la 1.x sont reprises comme du code, pas comme des souvenirs.** Chaque piège d'`AGENTS.md` et chaque
   règle exécutable des tests d'architecture 1.x est reformulé pour la 2.0 en type, en frontière de crate ou en test,
   avant que le module qu'il gouverne soit écrit : visibilité appliquée dans la requête et refus répondu 404, jamais
   403 ; absent n'est pas vide (0007) ; l'empreinte comme contrat de données ; l'agent sans connexion à la base (0003) ;
   tout appel sortant par la garde ; un câblage prouvé sur un binaire démarré.

7. **Le travail déjà fait est trié crate par crate, pas jeté.** À cette décision l'espace de travail compte environ
   183 000 lignes de Rust (`vectispire-rust/crates/`, sources seulement), en cinq groupes :

   | Groupe | Crates | Lignes | Dans la 2.0 |
   |---|---|---|---|
   | L'agent et ce qu'il partage | `agent`, `scanners`, `container`, `runner`, `protocol`, `crypto`, `tls`, `git`, `testkit`, `domain` | ~25 700 | **gardés tels quels** — l'agent en sort (point 1) ; les aides de compatibilité Java de `domain` (`java`, `wire`) restent pour le protocole |
   | Le côté serveur du protocole d'agent | `cp-agents` | ~4 000 | **gardé, au plus près de sa forme actuelle** : le protocole est un contrat externe, c'est donc le seul endroit où la parité avec la 1.x reste la règle |
   | Fondations | `cp-outbound` (la garde et l'émetteur épinglé), `cp-crypto` (le scellement sous les contextes 1.x), `cp-audit` (la chaîne d'empreintes), `cp-db`, `cp-http`, `cp-outbox`, `cp-maintenance`, `cp-runtime`, `cp-settings`, `cp-arch-tests` | ~23 600 | **gardées et adaptées** : la garde, le scellement et la chaîne sont nécessaires tels quels pour la migration (point 5) ; la chaîne de requête, la configuration et les règles d'architecture sont remodelées selon la conception de la 2.0 |
   | Modules métier | `cp-access`, `cp-checklists`, `cp-scanning`, `cp-issues`, `cp-targets`, `cp-forges`, `cp-inventory`, `cp-compliance`, `cp-posture`, `cp-threatintel`, `cp-gate`, `cp-tickets`, `cp-rules`, `cp-siem`, `cp-notifications`, `cp-ai`, `cp-platform`, `cp-app` | ~122 000 | **la source dont part la réécriture, pas son résultat** : les règles qu'ils encodent (visibilité, triage, verdict de la barrière, flux KEV et EPSS, synchronisation des constats en problèmes) sont reprises dans les modules 2.0 avec leurs tests ; les couches de parité qui les entourent — messages de conversion de Spring, lectures de Jackson, formes de réponse que seule l'interface lit — sont abandonnées |
   | Outillage de parité | `cp-contract` (le rejeu de la suite Java), `migrate` (l'historique Flyway reproduit) | ~9 400 | **restreint** : `cp-contract` garde les contrôles de contrat des routes externes (point 3) et abandonne le rejeu de toute la suite ; `migrate` devient le lecteur d'un schéma 1.x pour l'outil de migration (point 5) |

   Les pièces écrites côté Java pour le portage suivent le même tri : les jeux de référence des scanners de l'agent et
   du protocole restent ; l'enregistreur de trafic n'enregistre plus que les routes externes.

8. **La 1.x reste le produit maintenu jusqu'à ce que la 2.0 passe la répétition.** Les nouvelles fonctionnalités
   n'arrivent dans la 1.x que si elles ne peuvent pas attendre ; un module déjà réécrit pour la 2.0 reçoit les
   corrections 1.x par le changement qui les fait. La 2.0 ne sort qu'après la répétition de migration sur une copie de
   production et une période côte à côte en préproduction, comme décidé pour la bascule le 2026-10-28.

## Conséquences

- Le coût de la 2.0 est celui du produit, pas celui de l'alignement sur le comportement accessoire de Java ; cela
  reste un gros projet, à chiffrer par le spike des questions ouvertes avant le début de la réécriture.
- Les suites de contrat deviennent les tests les plus importants du produit : ce qu'elles ne couvrent pas est libre de
  changer, si bien qu'un contrat qu'elles oublient peut être cassé sans que personne ne le voie. Les écrire est le
  premier livrable.
- Faire tourner la 1.x et la 2.0 côte à côte signifie deux bases de code pendant un temps ; le point 8 borne cette
  fenêtre, et c'est la partie la plus risquée du plan (une correction qui n'arrive que d'un côté).
- Sur les ~183 000 lignes déjà écrites, le côté agent (~26 000) et le côté serveur du protocole sont gardés ; les
  fondations (~24 000) sont adaptées ; les modules métier (~122 000) deviennent la source de la réécriture plutôt que
  son résultat ; l'outillage de parité (~9 000) est restreint aux contrats externes.

## Alternatives envisagées

- **Poursuivre le portage jusqu'à la parité complète, puis faire évoluer en Rust.** Rejeté : on paie la parité deux
  fois — pour l'atteindre puis pour la défaire — et l'oracle enregistré ne couvre pas ce que la suite Java n'a jamais
  exercé.
- **Arrêter Rust pour le plan de contrôle et garder Java.** Reste une issue valable : si le spike montre que la
  réécriture ne vaut pas son coût, la 2.0 garde le plan de contrôle Java et l'agent Rust. Cette décision ne tranche pas
  cette question ; elle fixe comment se fait une réécriture si elle se fait.
- **Une réécriture complète en Rust avec une interface Rust (Dioxus).** Rejetée pour l'instant, pour les raisons du
  point 4.

## Questions ouvertes, à trancher avant le début de la réécriture

1. **Un spike** : une tranche verticale — problèmes, triage et barrière, avec leurs routes externes et la migration de
   leurs données — réécrite de bout en bout, sa suite de contrat passant sur la 1.x et la 2.0, pour mesurer le coût réel
   par module.
2. **La configuration** : quelles clés 1.x la 2.0 accepte telles quelles, lesquelles elle renomme, et comment elle le
   dit.
3. **Les identifiants** : si la 2.0 garde les identifiants numériques de la 1.x ou les met en correspondance, vu les
   liens que tiennent les gestionnaires de tickets et les documents.
4. **La chaîne d'audit à travers la migration** : la forme exacte du pont entre la dernière entrée 1.x et la première
   entrée 2.0, et la manière dont un vérificateur lit les deux.
5. **Le dépôt** : si le plan de contrôle 2.0 vit dans ce dépôt ou dans un nouveau. Un nouveau dépôt lui donne un
   historique, un pipeline et une feuille de route propres, ce qui convient à une réécriture. Mais l'agent dépend
   aujourd'hui de ce dépôt — ses jeux de référence sont écrits par les tests Java, sa conformité et le job
   `previous-agent` tournent à côté de l'agent Java — et les signatures de version nomment le workflow de ce dépôt, si
   bien qu'un nouveau dépôt est une nouvelle identité de signature à faire connaître aux utilisateurs. S'il est retenu,
   le déménagement vient après la sortie de l'agent depuis ce dépôt et une fois les suites de contrat externes (point 3)
   publiées depuis ce dépôt comme un artefact versionné que le nouveau consomme.
