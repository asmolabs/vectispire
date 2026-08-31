# Installation

Vectispire, c'est deux processus et une base de données : un plan de contrôle Spring Boot qui
sert l'API et l'interface compilée, et — facultativement — un ou plusieurs agents distants. Une
installation sur une seule machine n'a besoin ni de l'agent ni d'aucune configuration d'agent.

## Prérequis

| Prérequis | Pourquoi |
|---|---|
| **Docker**, démarré et joignable | Chaque scanner s'exécute comme un conteneur éphémère à travers le socket Docker. Ce n'est pas facultatif : il y a un seul moteur de scan, et c'est Docker. |
| **PostgreSQL** ou **MySQL 8** | Les deux sont supportés et exercés par la campagne d'intégration. Le moteur est lu depuis l'URL JDBC ; il n'y a pas de réglage de dialecte séparé. |
| **Git** | Vectispire clone ce qu'il analyse. |
| **Node ≥ 24**, **JDK 25** | Uniquement si vous construisez depuis les sources plutôt que d'exécuter les images publiées. |

!!! warning "Accès au socket Docker"
    L'utilisateur qui exécute Vectispire doit avoir accès à `/var/run/docker.sock`. Sous
    Linux, cela signifie généralement l'ajouter au groupe `docker`. Sans cela, chaque scan
    échoue au premier conteneur.

## Le chemin le plus court : Docker Compose

```bash
cp .env.example .env      # puis éditez-le — voir ci-dessous
docker compose up -d
```

Cela démarre PostgreSQL et le plan de contrôle sur `http://localhost:3180`. Pour lancer aussi
un agent distant dédié :

```bash
docker compose --profile with-agent up -d
```

## Avant le premier démarrage

La plupart des réglages vivent dans la base de données et s'éditent depuis **Réglages** une
fois l'application lancée. Quatre choses doivent être justes *avant* le premier démarrage,
parce qu'elles sont nécessaires pour atteindre cet écran.

### La base de données

```bash
VECTISPIRE_DB_URL=jdbc:postgresql://localhost:5432/vectispire
VECTISPIRE_DB_USER=vectispire
VECTISPIRE_DB_PASSWORD=…
```

Pour MySQL, pointez la même variable dessus — `jdbc:mysql://localhost:3306/vectispire` — et ne
changez rien d'autre.

Le schéma appartient aux **migrations Flyway**, appliquées au démarrage. Il n'y a pas de
commande de migration séparée à lancer, et `ddl-auto` est à `validate` délibérément : un schéma
synthétisé depuis les entités n'est pas celui que la production reçoit, donc tester contre lui
laisserait passer une migration fautive.

### La clé de chiffrement

Vectispire chiffre les secrets qu'il détient — les clés de déploiement avant tout.
**L'enregistrement d'un secret est refusé tant qu'aucune clé n'est posée.**

```bash
ENCRYPTION_KEY_FILE=/run/secrets/vectispire-encryption-key
```

Préférez `ENCRYPTION_KEY_FILE` à `ENCRYPTION_KEY` en production : un fichier est ce qu'un
secret Docker ou Kubernetes monte, et il garde la valeur hors de `/proc/<pid>/environ`, de
`docker inspect` et des journaux de votre orchestrateur. Poser les deux est refusé. Un chemin
qui ne résout pas arrête l'application plutôt que de la démarrer sans clé.

Voir [Rotation et purge](../administration/maintenance.md) pour la changer plus tard.

### Le premier compte {#the-first-account}

Il n'y a pas de page d'inscription. Le premier compte vient de variables d'amorçage, et le
SUPERUSER est créé quand la table des utilisateurs est vide :

```bash
VECTISPIRE_BOOTSTRAP_USERNAME=admin
VECTISPIRE_BOOTSTRAP_PASSWORD=<au moins 8 caractères>
```

Dès qu'un compte existe, les deux variables sont ignorées. Changez ce mot de passe à la
première connexion.

## Où l'exécuter

**Vectispire est conçu pour un réseau interne, pas pour l'Internet public.** C'est une console
d'exploitation destinée à une équipe qui a déjà accès au code qu'elle analyse, et sa conception
suppose que quiconque peut atteindre la page de connexion est quelqu'un à qui vous auriez donné
un compte de toute façon.

Cette hypothèse est portante, donc autant l'énoncer clairement plutôt que de la laisser déduire
des valeurs par défaut :

- Le plan de contrôle publie le port `3180` sur **toutes les interfaces** de son hôte. C'est
  délibéré — il faut bien atteindre l'interface — mais cela signifie qu'un hôte doté d'une
  adresse publique sert Vectispire à Internet dès qu'il démarre. La base de données, elle, est
  publiée en loopback seulement ; la différence est volontaire et visible dans
  `docker-compose.yml`.
- Un utilisateur connecté capable d'enregistrer un dépôt peut faire cloner au plan de contrôle
  une URL qu'il a choisie. C'est le produit qui fonctionne comme prévu, et c'est aussi pourquoi
  *qui peut se connecter* est la frontière qui compte le plus.

Si l'hôte est joignable depuis l'extérieur de votre réseau, mettez-le derrière quelque chose —
un VPN, un proxy qui authentifie, ou une règle de pare-feu — avant toute autre chose. Si vous
terminez TLS devant lui, nommez le proxy dans `vectispire.security.trusted-proxies` ; laissée
vide, la limitation de débit compte l'adresse du proxy plutôt que celle de l'appelant, et cesse
de protéger qui que ce soit.

### Deux réglages qui changent avec la taille de l'installation

| Réglage | Défaut | Le changer quand |
|---|---|---|
| `VECTISPIRE_HOST_SSH` | `true` | **Plus d'une équipe partage l'installation.** Avec le repli actif, un dépôt sans clé propre est cloné avec l'identité `~/.ssh` de l'hôte — donc ajouter une URL suffit à faire cloner Vectispire sous cette identité. Sur une installation mono-équipe, la clé de l'hôte atteint déjà toutes les cibles et le repli ne coûte rien ; sur une installation partagée, mettez-le à `false` et attachez une clé de déploiement par dépôt. |
| `TICKET_WEBHOOK_SECRET` | non posé | **Vous branchez un webhook de tracker.** Non posé, la route de webhook accepte les appels non authentifiés plutôt que de les refuser — choisi pour qu'une mise à jour n'interrompe pas silencieusement une synchronisation de triage existante. Posez-le dès que la route est joignable par quoi que ce soit que vous ne contrôlez pas. Notez que la vérification n'est pas liée à un anti-rejeu : un message légitime rejoué réapplique sa décision. |

Les deux sont consignés avec leur raisonnement dans le modèle de menaces du projet.

## Exécuter depuis les sources

```bash
git clone https://github.com/asmolabs/vectispire.git
cd vectispire
npm install

cd vectispire-java && ./gradlew :vectispire-core:bootRun --args='--server.port=3180'
npm --workspace @vectispire/frontend start    # interface sur :4280, /api relayé vers :3180
```

`npm` ne couvre que l'interface. Le plan de contrôle est une construction Gradle dans
`vectispire-java/` et ne partage rien avec elle que le contrat HTTP.

## Vérifier une release

Chaque release porte quatre fichiers : le jar, son SBOM, et un paquet Sigstore pour chacun.
Vérifiez avant d'exécuter quoi que ce soit — un outil de sécurité que vous avez pris sur
parole est une contradiction.

```bash
cosign verify-blob \
  --bundle vectispire-1.0.0.jar.cosign.bundle \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v1.0.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vectispire-1.0.0.jar
```

Chaque option épingle quelque chose, et en retirer une seule rend l'essentiel de ce pour quoi
la signature existait. `--certificate-identity` nomme le **fichier de workflow et le tag**, pas
le dépôt : ne faire correspondre que le dépôt accepterait une signature émise par n'importe
quel workflow que n'importe qui peut y ajouter, y compris un workflow ajouté dans une demande
de fusion. `--certificate-oidc-issuer` dit que l'identité vient du service de jetons de
GitHub — sans lui, une chaîne qui *ressemble* simplement à l'identité ci-dessus suffit.
Remplacez le tag aux deux endroits pour une autre version ; l'identité est par tag, par
conception.

!!! warning "Les releases signées avant la bascule vers GitHub"
    L'identité de signature appartient à la forge qui a exécuté le workflow : une release
    construite sur l'ancien pipeline GitLab se vérifie contre `https://gitlab.com` et le
    chemin de ce pipeline, pas contre la commande ci-dessus. Vérifier une signature avec le
    mauvais émetteur ne peut pas réussir — et une instruction qui ne peut pas réussir est pire
    que pas d'instruction du tout, parce qu'elle apprend à son lecteur que le contrôle est
    passé le jour où il la tape mal jusqu'à ce qu'elle passe. Utilisez l'identité de la forge
    qui a construit l'artefact que vous détenez.

Il n'y a pas de clé de signature. Sigstore *keyless* signe avec l'identité OIDC du workflow
lui-même, donc il n'y a rien sous la garde de quiconque à voler ou à faire tourner.

Lancez la même commande sur les noms de fichiers du SBOM. Cela vaut la peine : un SBOM est ce
que quelqu'un donne à manger à son propre scanner, et un SBOM non signé est une liste de
dépendances que n'importe qui peut réécrire avant que vous ne la lisiez.

## Suite

[Enregistrer un dépôt et lancer votre premier scan →](first-scan.md)
