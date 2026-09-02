# Utilisateurs et équipes

## Comptes

Il n'y a **aucune page d'inscription**. Un administrateur crée chaque compte.

Le premier vient des variables d'amorçage au premier démarrage, et seulement quand la table des
utilisateurs est vide — voir
[Installation](../getting-started/installation.md#the-first-account). Ensuite, les deux
variables sont ignorées.

Un compte porte un indicateur `is_active`. Un compte désactivé ne peut pas se connecter, et son
historique reste intact — ce qui est tout l'intérêt de désactiver plutôt que de supprimer.

## Rôles

Les rôles décident de ce qu'une personne peut **faire** ; les équipes décident de ce qu'elle peut
**voir**. Les deux sont indépendants, et c'est voulu : donner un rôle n'élargit pas le périmètre,
sauf pour les trois rôles qui portent explicitement une portée globale.

| Rôle | Ce qu'il peut faire |
|---|---|
| **Utilisateur** | Voit et qualifie les constats de ses cibles. Ne peut pas approuver seul une décision qui clôt une anomalie lorsque la double validation est active. |
| **Référent sécurité** | Comme ci-dessus, et peut approuver un triage — dans le seul périmètre que ses équipes lui donnent. |
| **Auditeur** | Voit tout le parc et **ne change rien**, nulle part. Lit le journal d'audit, les preuves de conformité, la politique de barrière, les jeux de règles et la configuration SIEM. N'approuve aucun triage. |
| **Responsable Sécurité / CISO** | Voit tout le parc, approuve les triages, et **écrit** la gouvernance : barrières, jeux de règles, destination SIEM, politique de licences, réglages. N'administre pas les comptes. |
| **Administrateur** | Tout ce qui précède, plus les comptes, les équipes, les clés API, les clés SSH et les agents. |
| **Super-administrateur** | Identique à l'administrateur aujourd'hui. Créé par l'amorçage de l'installation. |

**L'auditeur mérite un mot.** Il existe parce que « regarder » et « pouvoir changer » étaient la
même permission : la seule façon d'ouvrir le journal d'audit à quelqu'un était de lui donner aussi
le droit de réécrire la politique qu'il venait vérifier. Si vous devez montrer votre posture à un
commissaire, à un client ou à un service interne, c'est ce rôle-là et pas le CISO.

Distribuez les rôles administratifs avec parcimonie : le journal d'audit n'a de sens qu'à
proportion du nombre de gens capables de changer ce qu'il enregistre.

## Équipes et visibilité

Les équipes décident de ce qu'une personne peut **voir**. Les cibles appartiennent à des
équipes, et chaque liste, chaque export et chaque série de tendance est restreint par la
visibilité du lecteur — la série « backlog dans le temps » du tableau de bord comprise.

Cette restriction est uniforme à dessein. Une vue qui l'ignorerait discrètement laisserait
quelqu'un déduire la forme d'un parc qu'il ne peut pas ouvrir.

## Cibles sans étiquette

Une cible n'appartenant à aucune équipe n'est visible que de ceux qui voient tout. Il vaut la
peine de les chercher après un import en masse : une cible sans propriétaire est une cible dont
personne n'est responsable, et ses scans continuent de compter dans le tableau de bord de
personne.

## Voir aussi

- [Authentification unique](sso.md) — déléguer l'authentification sans déléguer l'autorisation.
- [Clés d'API](api-keys.md) — pour des machines plutôt que pour des personnes.
- [Journal d'audit](audit-log.md) — ce qui est enregistré de tout cela.
