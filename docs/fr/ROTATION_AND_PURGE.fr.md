# Identifiants exposés et purge GitHub — ce qu'il reste à faire

Ce document existe parce que ces deux actions ne peuvent pas être menées depuis le dépôt :
l'une consiste à aller révoquer une clé chez un fournisseur, l'autre à ouvrir un ticket chez
GitHub. Tout le reste — l'inventaire, les vérifications, les commandes — est préparé ici.

**Contexte.** `vectispire/database.sqlite` a été commité pendant des mois. Il contenait les
empreintes de mots de passe et les clés SSH privées « chiffrées » — chiffrées avec une clé par
défaut elle-même publiée dans le dépôt. L'historique a été réécrit et force-pushé le
2026-08-06, mais un force-push ne supprime pas les objets côté GitHub : ils deviennent
non référencés et restent accessibles par leur empreinte jusqu'à une purge côté serveur.

**Le dépôt est privé.** Cela réduit fortement l'exposition — seuls les comptes ayant accès au
dépôt pouvaient cloner — sans l'annuler : quiconque, ou tout jeton, ayant eu cet accès a pu
récupérer la base, et révoquer l'accès après coup n'y change rien.

---

## 1. Rotation — par ordre d'urgence

### 1.1 La clé SSH de déploiement `perso` — critique

Constaté sur la base actuelle : la clé nommée `perso`
(`ae2088e9-e958-40a6-afe2-0cf2de2d3d60`, créée le 2026-07-29) est une **clé privée RSA**
chiffrée avec la clé par défaut `my-secret-encryption-key-32bytes` — une constante qui a été
publiée dans le code source de ce dépôt.

Autrement dit : quiconque a obtenu une copie de l'ancien `database.sqlite` détient cette clé
privée en clair. Elle doit être considérée comme compromise.

**Ce que fait le code aujourd'hui.** Cette constante a été retirée d'
[`EncryptionService`](../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/services/EncryptionService.java) :
l'application ne transporte plus la clé qui ouvre sa propre base, et la valeur ci-dessus n'est
plus essayée au déchiffrement. La ligne `perso` apparaît donc en **« Illisible »** sur la page
*Clés SSH* — c'est le résultat attendu, et le remplacement ci-dessous est la seule suite
correcte : ré-enregistrer le même contenu sous une véritable `ENCRYPTION_KEY` n'apporterait
rien, puisque sa moitié privée est déjà publique.

S'il faut la lire une dernière fois (pour identifier chez quel fournisseur la révoquer, par
exemple), fournissez l'ancienne clé explicitement, le temps de l'opération :

```bash
VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS="<votre-ancienne-cle>" cd vectispire-java && ./gradlew :vectispire-core:bootRun
```

À faire, **dans cet ordre** :

1. **Révoquer** la clé publique correspondante chez le fournisseur git (GitHub : *Settings →
   SSH and GPG keys* pour une clé de compte, ou *Repo → Settings → Deploy keys*). La
   révocation précède la génération : c'est elle qui coupe l'accès.
2. **Générer** une nouvelle paire :
   ```bash
   ssh-keygen -t ed25519 -C "vectispire-deploy" -f ~/vectispire-deploy
   ```
   Ed25519 plutôt que RSA : plus courte, et c'est la valeur par défaut recommandée aujourd'hui.
3. **Définir `ENCRYPTION_KEY`** dans l'environnement de Vectispire *avant* d'enregistrer la
   nouvelle clé — sinon l'application refuse de chiffrer (c'est le garde-fou en place, et il
   fait exactement son travail ici) :
   ```bash
   openssl rand -base64 32
   ```
   Cette valeur va dans l'environnement du service, pas dans le dépôt.
4. **Remplacer** la clé depuis la page *Clés SSH*. L'enregistrement la chiffre avec la nouvelle
   `ENCRYPTION_KEY` et la lie à sa ligne (données associées), de sorte que l'ancien
   chiffré n'est plus rejouable ailleurs.
5. **Supprimer** l'ancienne entrée `perso`, puisque son contenu est publiquement connu de fait.

### 1.2 Le mot de passe du compte `admin`

L'empreinte bcrypt de ce compte était dans la base commitée. bcrypt tient bien, mais une
empreinte exfiltrée est un mot de passe à durée de vie limitée, pas un mot de passe protégé.

Le mécanisme existe déjà : passer `must_change_password` à vrai force le changement à la
prochaine connexion, sans bloquer l'accès. Ce drapeau est actuellement **faux** pour `admin`.
Un administrateur peut le déclencher depuis la page *Utilisateurs* (réinitialiser le mot de
passe le positionne automatiquement), ou en une requête :

```sql
UPDATE t_user SET must_change_password = 1;
```

### 1.3 Le mot de passe d'amorçage

Si `VECTISPIRE_BOOTSTRAP_PASSWORD` a été renseigné dans un fichier compose, un fichier
d'environnement ou une variable de CI, il doit y être changé également — et il est désormais
provisoire par construction : le compte créé avec doit changer son mot de passe à la première
connexion.

### 1.4 Rien d'autre à faire côté réglages

Vérifié : la table `setting` ne contient actuellement **aucun** identifiant
(`notification_webhook_url` est vide, pas de `ticket_token`, pas de `local_scan_api_token`).
Si l'un de ces réglages a été renseigné avant le 2026-08-06, il se trouvait dans la base
commitée et doit être tourné — un jeton de webhook Slack ou Teams est un secret porteur, même
s'il ressemble à une URL.

### 1.5 Les clés d'agent ne sont pas concernées

Depuis l'arrivée du scan distribué, un agent s'authentifie avec une clé d'API portant la portée
`agent` et rien d'autre. Ces clés ont été créées après l'exposition, donc **aucune n'est à
tourner ici** — la note est là pour que la question ne se repose pas. Elles se révoquent depuis
la page *Clés d'API* comme n'importe quelle autre, et un agent qui perd la sienne ne peut plus
réclamer de travail : il ne détient ni accès base ni `ENCRYPTION_KEY`, ce qui est précisément
ce qui limite les conséquences d'un agent compromis.

### 1.6 Faire tourner `ENCRYPTION_KEY` elle-même

**Déplacée vers [`KEY_ROTATION.fr.md`](KEY_ROTATION.fr.md).** C'était la seule partie de ce
document qui survit à l'incident, et la laisser ici obligeait quiconque cherchait la procédure à
lire le récit d'une exposition d'identifiants pour la trouver.

---

> **L'archive est laissée telle quelle ; seuls les faits qui l'entourent sont tenus à jour.**
> Cette section décrit une purge réellement menée le 6 août 2026 contre le dépôt
> `Asmo1973/Vectispire`. Réécrire les commandes ci-dessous transformerait un compte-rendu de ce
> qui s'est passé en une instruction qui n'a jamais été suivie : elles restent telles qu'elles
> ont été lancées.
>
> **Où vit le projet aujourd'hui, vérifié plutôt que retenu de mémoire.** `git remote -v` répond
> `git@github.com:asmolabs/vectispire.git`. La forge est passée à GitLab après la rédaction de ce
> texte, puis revenue à GitHub le 27 août 2026 ; une révision antérieure de cette note affirmait
> que le remote était GitLab et envoyait son lecteur chercher un formulaire de support GitLab.
> **L'action restante ci-dessous concerne l'ancien dépôt, pas le dépôt actuel** — ce sont deux
> dépôts distincts, et non un renommage.

## 2. Purger les objets non référencés chez GitHub

### 2.1 Vérifier d'abord si c'est encore nécessaire

Depuis une session authentifiée (`gh auth login`), une ancienne empreinte antérieure à la
réécriture — par exemple `92df73d`, `7e78c14`, `e934b76`, `54bf480`, `bdd5795` :

```bash
gh api repos/Asmo1973/Vectispire/commits/92df73d --jq .sha   # 404 = purgé, 200 = encore servi
```

Ou dans un navigateur : `https://github.com/Asmo1973/Vectispire/commit/92df73d`. Si la page
s'affiche, l'objet est toujours là.

**Toujours pas concluant depuis ici, mais pour une raison plus étroite qu'avant.** Lancées sans
authentification le 30 août 2026, `Asmo1973/Vectispire` et les cinq empreintes répondent
**404** — or un 404 non authentifié est exactement ce que produisent un dépôt privé, un dépôt
supprimé et un objet purgé. Cela ne tranche rien. Il faut une session authentifiée ayant accès à
ce dépôt, et c'est votre part du travail.

**Ce qui, en revanche, a été tranché sur le dépôt actuel, qui est public.** Ce sont des faits, pas
des déductions :

| Vérification | Résultat |
|---|---|
| `GET /repos/asmolabs/vectispire` | `visibility: public`, `forks_count: 0`, `network_count: 0`, créé le 2026-08-27 |
| Les cinq anciennes empreintes contre lui | `422` × 5 — les objets ne sont pas dans ce dépôt |
| `git rev-list --objects --all \| grep -iE '\.sqlite\|id_rsa\|\.pem$'` | vide, sur 391 commits |
| `gitleaks detect` sur tout l'historique | 377 commits, aucune fuite |

Le dépôt actuel ne porte donc rien de l'incident et n'a aucun fork pour le propager. Ce qui reste
ouvert, c'est l'ancien.

### 2.2 Vérifier l'absence de forks

Un fork conserve les objets indépendamment, et c'est la raison habituelle du refus d'une purge.
Pour vérifier :

```bash
gh api repos/Asmo1973/Vectispire --jq '{forks: .forks_count, network: .network_count}'
```

Si un fork existe, il doit être supprimé avant la purge, sinon l'opération n'apporte rien.

### 2.3 Le message à envoyer

Via <https://support.github.com/request> (catégorie *Repository / other*) :

> Bonjour,
>
> Le dépôt privé `Asmo1973/Vectispire` a contenu par erreur un fichier de base SQLite
> (`vectispire/database.sqlite`) renfermant des secrets : empreintes de mots de passe et une clé
> SSH privée. L'historique a été réécrit avec `git filter-repo` et force-pushé le 6 août 2026, et
> la branche `main` ne contient plus ce fichier.
>
> Les commits antérieurs à la réécriture restent cependant accessibles par leur empreinte (par
> exemple `<SHA complet>`), car un force-push ne supprime pas les objets devenus non référencés.
>
> Pourriez-vous lancer un ramasse-miettes sur ce dépôt afin que ces objets ne soient plus servis ?
> Il n'existe aucun fork à ma connaissance.
>
> Merci.

Deux détails qui accélèrent le traitement : donner au moins un **SHA complet** (40 caractères)
d'un commit antérieur à la réécriture, et confirmer explicitement l'absence de forks. Les SHA
courts ci-dessus ne sont plus disponibles sous leur forme complète depuis cette machine —
l'historique local a été remplacé — mais ils se retrouvent dans les notifications GitHub reçues à
l'époque, dans un ancien clone, ou dans l'historique de votre shell
(`grep -r 92df73d ~/.zsh_history`).

### 2.4 Ce que la purge ne fait pas

Elle empêche GitHub de continuer à servir ces objets. Elle ne récupère pas ce qui a déjà été
cloné. **La rotation de la section 1 reste nécessaire quelle qu'en soit l'issue**, et c'est la
partie qui compte : la purge ferme une porte, la rotation invalide ce qui est passé par elle.
