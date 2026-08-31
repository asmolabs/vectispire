# Premier scan

## 1. Se connecter

Ouvrez le plan de contrôle — `http://localhost:3180` pour une installation par défaut — et
connectez-vous avec le compte d'amorçage créé au premier démarrage. Changez son mot de passe
immédiatement.

## 2. Enregistrer un dépôt

Allez dans **Dépôts → ajouter**, et renseignez :

| Champ | Notes |
|---|---|
| **URL du dépôt** | L'URL de clonage. HTTPS pour un dépôt public ; SSH s'il faut une clé de déploiement. |
| **Nom affiché** | Le nom sous lequel le tableau de bord le désigne. |
| **Branche** | La branche à analyser. |
| **Sous-chemin** | Pour un monodépôt. Un monodépôt s'enregistre **une fois par projet**, pas une fois. |
| **Niveau de criticité métier** | Niveau 1 · critique pour la mission, niveau 2 · opérationnel, ou niveau 3 · interne. C'est ce qui permet au tableau de bord de classer une CVE critique dans un service vital au-dessus de la même CVE dans un outil interne. |
| **Agent requis** | Laissez vide, sauf si le dépôt n'est joignable que depuis une machine particulière. Voir [Agents](../administration/agents.md). |

### Dépôts privés

Un dépôt privé demande une clé de déploiement. Ajoutez-la d'abord sous
[Clés SSH](../administration/ssh-keys.md), puis sélectionnez-la à l'enregistrement du dépôt. La
moitié privée est chiffrée avec votre `ENCRYPTION_KEY`, et c'est pourquoi l'application refuse
d'en stocker une avant que cette clé soit posée.

Donnez à la clé un accès **en lecture seule** chez votre hébergeur Git. Vectispire ne pousse
jamais.

## 3. Lancer le scan

Utilisez **Scanner maintenant** sur le dépôt. La première exécution est lente : le moteur
Docker télécharge `anchore/syft`, `anchore/grype`, `zricethezav/gitleaks` et
`bridgecrew/checkov` à la demande, la première fois que chacun sert. Les scans suivants
réutilisent les images en cache.

Ce qui se passe, dans l'ordre :

1. Le dépôt est cloné dans un répertoire de travail temporaire.
2. Syft le catalogue et produit un SBOM.
3. Grype rapproche les vulnérabilités connues de ce SBOM.
4. gitleaks cherche les secrets commités ; checkov regarde Terraform et Kubernetes.
5. Les résultats sont normalisés en lignes `Finding`, enrichis des scores EPSS et du statut
   CISA KEV, évalués contre la liste de blocage de licences, et réconciliés avec les issues
   existantes.

Les étapes 2 à 4 s'exécutent **réseau désactivé**. Les seuls appels sortants du pipeline sont
les consultations EPSS et KEV, qui transportent des identifiants CVE et rien d'autre, et le
catalogue de fin de support, qui transporte des noms de produits et des versions.

## 4. Le planifier

Un scan ponctuel vous renseigne sur aujourd'hui. De nouvelles vulnérabilités apparaissent dans
du code qui n'a pas changé : posez donc une récurrence sur le dépôt, soit un **intervalle de
scan**, soit une **expression cron**.

Préférez l'expression cron. Un intervalle dérive de quelques minutes à chaque exécution, si
bien qu'un scan configuré pour les heures creuses finit par tourner en pleine journée. Quand
les deux sont posés, l'expression l'emporte.

## 5. Ajouter une image de conteneur

Les images de conteneur s'enregistrent dans **Conteneurs** et fonctionnent de la même façon :
l'image est cataloguée et rapprochée exactement comme un dépôt, et la distribution sur laquelle
l'image est construite est confrontée au catalogue de fin de support. Ce dernier contrôle
attrape une classe de risque sans CVE attachée : rien ne sera corrigé pour la *prochaine*
vulnérabilité, quelle qu'elle se révèle être.

## Suite

[Ce que veulent dire les résultats →](reading-results.md)
