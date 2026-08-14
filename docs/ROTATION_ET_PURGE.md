# Identifiants exposés et purge GitHub — ce qu'il reste à faire

Ce document existe parce que ces deux actions ne peuvent pas être faites depuis le
dépôt : l'une demande d'aller révoquer une clé chez un fournisseur, l'autre d'ouvrir un
ticket chez GitHub. Tout le reste — l'inventaire, les vérifications, les commandes — est
préparé ici.

**Contexte.** `zanshin/database.sqlite` a été commité pendant des mois. Il contenait les
hashes de mots de passe et les clés SSH privées « chiffrées » — chiffrées avec une clé
par défaut qui était elle-même publiée dans le dépôt. L'historique a été réécrit et
force-poussé le 2026-08-06, mais un force-push ne supprime pas les objets côté GitHub :
ils deviennent non référencés et restent accessibles par leur empreinte jusqu'à une
purge côté serveur.

**Le dépôt est privé.** Cela réduit fortement l'exposition — seuls les comptes ayant eu
accès au dépôt ont pu cloner — sans l'annuler : toute personne ou tout jeton ayant eu
cet accès a pu récupérer la base, et le retrait d'accès ultérieur n'y change rien.

---

## 1. Rotation — par ordre d'urgence

### 1.1 La clé SSH de déploiement `perso` — critique

Constaté sur la base actuelle : la clé nommée `perso`
(`ae2088e9-e958-40a6-afe2-0cf2de2d3d60`, créée le 2026-07-29) est une **clé privée RSA**
chiffrée avec la clé par défaut `my-secret-encryption-key-32bytes` — une constante qui
était publiée dans le code source de ce dépôt.

Autrement dit : quiconque a obtenu une copie de l'ancien `database.sqlite` détient cette
clé privée en clair. Elle doit être considérée comme compromise.

**Ce que le code fait désormais.** Cette constante a été retirée de
[`backend/src/services/encryption.service.ts`](../backend/src/services/encryption.service.ts) :
l'application ne transporte plus la clé qui ouvre sa propre base, et la valeur ci-dessus
n'est plus essayée au déchiffrement. La ligne `perso` apparaît donc **« Illisible »**
sur la page *Clés SSH* — c'est le résultat attendu, et le remplacement ci-dessous est la
seule suite correcte : réenregistrer le même contenu sous une vraie `ENCRYPTION_KEY` ne
servirait à rien, puisque sa moitié privée est déjà publique.

Si vous avez besoin de la relire une dernière fois (pour identifier chez quel
fournisseur la révoquer, par exemple), donnez l'ancienne clé explicitement, le temps de
l'opération :

```bash
ZANSHIN_PREVIOUS_ENCRYPTION_KEYS="my-secret-encryption-key-32bytes" npm --workspace backend run start:dev
```

À faire, **dans cet ordre** :

1. **Révoquer** la clé publique correspondante chez le fournisseur git (GitHub :
   *Settings → SSH and GPG keys* pour une clé de compte, ou *Repo → Settings → Deploy
   keys*). La révocation vient avant la génération : c'est elle qui arrête l'accès.
2. **Générer** une nouvelle paire :
   ```bash
   ssh-keygen -t ed25519 -C "zanshin-deploy" -f ~/zanshin-deploy
   ```
   Ed25519 plutôt que RSA : plus court, et c'est le défaut recommandé aujourd'hui.
3. **Définir `ENCRYPTION_KEY`** dans l'environnement de Zanshin *avant* d'enregistrer la
   nouvelle clé — sinon l'application refuse de chiffrer (c'est le garde-fou en place, et
   il fait exactement son travail ici) :
   ```bash
   openssl rand -base64 32
   ```
   Cette valeur va dans l'environnement du service, pas dans le dépôt.
4. **Remplacer** la clé depuis la page *Clés SSH*. L'enregistrement la chiffre avec la
   nouvelle `ENCRYPTION_KEY` et la lie à sa ligne (données associées), donc l'ancien
   chiffré n'est plus rejouable ailleurs.
5. **Supprimer** l'ancienne entrée `perso`, puisque son contenu est public de fait.

### 1.2 Le mot de passe du compte `admin`

Le hash bcrypt de ce compte était dans la base commitée. bcrypt résiste bien, mais un
hash exfiltré est un mot de passe à durée de vie limitée, pas un mot de passe protégé.

Le mécanisme est déjà là : mettre `must_change_password` à vrai force le changement à la
prochaine connexion, sans bloquer l'accès. Actuellement ce drapeau est à **faux** pour
`admin`. Un administrateur peut le déclencher depuis la page *Utilisateurs*
(réinitialiser le mot de passe le pose automatiquement), ou en une requête :

```sql
UPDATE "user" SET must_change_password = 1;
```

### 1.3 Le mot de passe de bootstrap

Si `ZANSHIN_BOOTSTRAP_PASSWORD` a été renseigné dans un fichier compose, un fichier
d'environnement ou une variable de CI, il est à changer là aussi — et il est désormais
provisoire par construction : le compte créé avec doit changer de mot de passe à la
première connexion.

### 1.4 Rien d'autre à faire côté réglages

Vérifié : la table `setting` ne contient aujourd'hui **aucun** identifiant
(`notification_webhook_url` est vide, aucun `ticket_token`, aucun
`local_scan_api_token`). Si l'un de ces réglages a été renseigné avant le 2026-08-06, il
était dans la base commitée et doit être tourné — un jeton de webhook Slack ou Teams est
un secret porteur, même s'il ressemble à une URL.

### 1.5 Les clés d'agent ne sont pas concernées

Depuis l'arrivée du scan distribué, un agent s'authentifie avec une clé API portant la
portée `agent` et rien d'autre. Ces clés sont créées après l'exposition, donc **aucune
n'est à faire tourner ici** — la précision est là pour que la question ne se repose pas.
Elles se révoquent depuis la page *Clés API* comme les autres, et un agent qui perd la
sienne ne peut plus réclamer de travail : il ne détient ni accès à la base ni
`ENCRYPTION_KEY`, ce qui est précisément ce qui limite les conséquences d'un agent
compromis.

### 1.6 Faire tourner `ENCRYPTION_KEY` elle-même

Utile au-delà de cet incident, et impossible jusqu'ici : changer `ENCRYPTION_KEY`
rendait tous les secrets stockés illisibles d'un coup, et la procédure documentée était
de ressaisir chaque valeur à la main.

```bash
ENCRYPTION_KEY="<nouvelle clé>" \
ZANSHIN_PREVIOUS_ENCRYPTION_KEYS="<ancienne clé>" \
npm --workspace backend run start:dev
```

L'ancienne clé sert **au déchiffrement uniquement** : toute écriture passe sous la
nouvelle. Les valeurs migrent donc au fur et à mesure des réenregistrements, et la page
*Clés SSH* affiche **« À faire tourner »** tant qu'une ligne dépend encore de l'ancienne
— l'ancienne clé se retire de l'environnement quand plus aucune ne l'affiche. Plusieurs
clés précédentes peuvent être listées, séparées par des virgules, pour une rotation
interrompue.

---

## 2. Purge des objets non référencés chez GitHub

### 2.1 Vérifier d'abord si c'est encore nécessaire

Depuis une session authentifiée (`gh auth login`), un ancien SHA d'avant la réécriture —
par exemple `92df73d`, `7e78c14`, `e934b76`, `54bf480`, `bdd5795` :

```bash
gh api repos/Asmo1973/Zanshin/commits/92df73d --jq .sha   # 404 = purgé, 200 = encore servi
```

Ou dans un navigateur : `https://github.com/Asmo1973/Zanshin/commit/92df73d`. Si la page
s'affiche, l'objet est encore là.

Ces commandes n'ont **pas** pu être exécutées de façon concluante ici : `gh` n'est pas
authentifié sur cette machine et le dépôt est privé, donc les 404 obtenus ne signifient
rien. À refaire de votre côté avant d'écrire à GitHub.

### 2.2 Vérifier les forks

Un fork conserve les objets indépendamment, et c'est le motif habituel d'un refus de
purge. À contrôler :

```bash
gh api repos/Asmo1973/Zanshin --jq '{forks: .forks_count, network: .network_count}'
```

S'il existe un fork, il doit être supprimé avant la purge, sinon l'opération ne servira
à rien.

### 2.3 Le message à envoyer

Via <https://support.github.com/request> (catégorie *Repository / other*) :

> Bonjour,
>
> Le dépôt privé `Asmo1973/Zanshin` a contenu par erreur un fichier de base de données
> SQLite (`zanshin/database.sqlite`) porteur de secrets : hashes de mots de passe et une
> clé SSH privée. L'historique a été réécrit avec `git filter-repo` et force-poussé le
> 6 août 2026, et la branche `main` ne contient plus ce fichier.
>
> Les commits d'avant la réécriture restent cependant accessibles par leur empreinte
> (par exemple `<SHA complet>`), car un force-push ne supprime pas les objets devenus
> non référencés.
>
> Pourriez-vous exécuter une purge (garbage collection) de ce dépôt afin que ces objets
> ne soient plus servis ? Il n'existe aucun fork à ma connaissance.
>
> Merci.

Deux précisions qui accélèrent le traitement : donnez au moins un **SHA complet** (40
caractères) d'un commit d'avant la réécriture, et confirmez explicitement l'absence de
fork. Les SHA courts ci-dessus ne sont plus disponibles en version complète depuis ce
poste — l'historique local a été remplacé — mais ils se retrouvent dans les
notifications GitHub reçues à l'époque, dans un ancien clone, ou dans l'historique de
votre shell (`grep -r 92df73d ~/.zsh_history`).

### 2.4 Ce que la purge ne fait pas

Elle empêche GitHub de continuer à servir ces objets. Elle ne récupère pas ce qui a déjà
été cloné. **La rotation de la section 1 reste nécessaire quel que soit le résultat**, et
c'est elle qui compte : la purge ferme une porte, la rotation invalide ce qui est passé
par elle.
