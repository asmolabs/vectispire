# FAQ et dépannage

## Installation

**Permission refusée sur le socket Docker.** L'utilisateur qui exécute Vectispire doit avoir
accès à `/var/run/docker.sock`. Sous Linux, ajoutez-le au groupe `docker`. Sans cela, chaque
scan échoue au premier conteneur.

**Le premier scan est très lent.** C'est attendu. Les images — `anchore/syft`,
`anchore/grype`, `zricethezav/gitleaks`, `bridgecrew/checkov`, `semgrep/semgrep` — sont
téléchargées à la demande la première fois que chacune sert. Les scans suivants réutilisent le
cache.

**Puis-je utiliser SQLite ?** Non. PostgreSQL et MySQL 8 sont les moteurs supportés. SQLite
n'existe dans la construction que comme fixture de test.

**L'application refuse de démarrer : le chemin de la clé de chiffrement ne résout pas.**
Délibéré. Démarrer sans clé reviendrait à refuser toute écriture de secret des heures plus
tard, à un endroit sans rapport avec l'erreur réelle.

## Connexion

**« Identifiants incorrects ou compte inactif ».** Soit les identifiants sont faux, soit
l'indicateur `is_active` du compte est à `false`. Vérifiez sous **Utilisateurs** avec un
administrateur existant.

**J'ai perdu le compte d'amorçage.** Les variables d'amorçage ne sont honorées que lorsque la
table des utilisateurs est vide. Un autre SUPERUSER peut réinitialiser le mot de passe ; sinon,
la réinitialisation est une opération en base.

**L'authentification unique fonctionne mais l'utilisateur n'a aucun accès.** C'est attendu :
aucun compte n'est créé à la connexion. Un administrateur le crée d'abord, et le rôle reste la
décision de Vectispire. Voir [Authentification unique](../administration/sso.md).

## Scan

**Un scan a échoué et le tableau de bord paraît quand même vert.** Un backlog vide passe toutes
les politiques. La vue d'ensemble Sécurité nomme « jamais analysée » et « dernier scan échoué »
exactement pour cette raison — voir
[Lire les résultats](../getting-started/reading-results.md#two-states-with-an-empty-backlog).

**Rien n'est pris en charge et la file grossit.** Soit l'agent intégré est désactivé sans
qu'aucun agent distant ne soit connecté, soit les cibles sont épinglées à un agent qui ne s'est
jamais annoncé. Voir [Agents](../administration/agents.md).

**Un dépôt privé ne se clone pas.** La clé de déploiement doit être enregistrée sous
[Clés SSH](../administration/ssh-keys.md), sélectionnée sur le dépôt, et dotée d'un accès en
lecture seule chez votre hébergeur.

**Une clé SSH s'affiche comme illisible.** Aucune clé configurée ne la déchiffre — le plus
probable est qu'elle précède tout `ENCRYPTION_KEY`. Cet ancien défaut a été retiré et sa moitié
privée est publique : remplacez la paire de clés chez votre hébergeur.

**Semgrep ne trouve presque rien.** Vectispire n'embarque qu'une seule règle, parce que les
jeux de règles publics ne sont pas redistribuables. Installez le vôtre — voir
[Jeux de règles Semgrep](../administration/rule-sets.md).

## Résultats

**Pourquoi la même CVE n'a-t-elle pas créé une nouvelle issue après un changement de
version ?** Par conception. L'empreinte ignore la version du paquet : une dépendance vulnérable
sur trois correctifs successifs garde un historique et une décision.

**J'ai supprimé une issue et elle est toujours ouverte.** Par conception également. `state`
n'est écrit que par le pipeline ; le triage n'est écrit que par une personne. Les confondre
rendrait « résolu » vide de sens.

**Une issue supprimée est revenue.** Sa date de réexamen est arrivée et elle est repassée en
*en cours d'examen*, avec sa justification et son commentaire intacts. Voir
[Constats et triage](../guide/issues.md#review-dates).

**Le MTTR est vide plutôt qu'à zéro.** Rien n'a été résolu sur cette période. Zéro se lirait
comme « corrigé le jour de son apparition ».

## CI

**Ma `policy` dans la requête a été ignorée.** Une requête ne peut que **durcir** la politique
stockée, jamais l'assouplir. Changez la politique stockée sous
[Politiques de barrière](../administration/gate-policies.md).

**Le verdict ne correspond pas à ce que je vois dans l'interface.** Lisez quelle politique le
verdict nomme — une redéfinition par cible peut s'appliquer, ou le défaut intégré là où rien
n'est stocké.

**Les constats de qualité ne font jamais échouer ma construction.** C'est exact, et ce n'est
pas configurable. Voir [Qualité du code](../guide/quality.md).

## Notifications

**Teams ne reçoit rien.** Teams est atteint par un **workflow** Power Automate ; le connecteur
Office 365 qu'il remplace a été retiré. Recréez la destination sous forme de workflow.

**Une notification est arrivée deux fois.** Chaque destination a sa propre ligne de file
d'envoi précisément pour qu'un échec sur l'une ne duplique pas une autre. Un vrai doublon vers
une seule destination mérite d'être signalé.

**Rien ne se déclenche sur une semaine calme.** Par conception — les notifications se
déclenchent quand quelque chose apparaît. Activez le
[rapport de posture hebdomadaire](../integrations/notifications.md#the-weekly-posture-report),
qui nomme aussi ce qui n'a jamais été analysé.

## Revue par IA

**La liste des modèles ne montre que deux suggestions.** Ollama est injoignable à l'URL
configurée. Vérifiez qu'il tourne et rafraîchissez la liste.

**La revue est lente.** C'est attendu avec Ollama dans Docker sur Apple Silicon — ni passage
GPU ni Metal, donc l'inférence est uniquement sur processeur. Installez-le en natif, ou
utilisez le modèle plus léger.

## Signaler un problème de sécurité

N'ouvrez pas de ticket public. Voir
[SECURITY.md](https://github.com/asmolabs/vectispire/blob/main/SECURITY.md).
