# Checklists de sécurité

La **checklist de sécurité** d'un projet est la checklist propre à votre organisation — un
[modèle de checklist](../administration/checklist-templates.fr.md) que votre fonction sécurité a
importé et publié — remplie pour un projet, ligne par ligne, par ceux qui le construisent, puis
approuvée par un approbateur. Chaque réponse garde son auteur et son instant, chaque preuve sa date,
et une révision approuvée n'est plus jamais modifiée.

Ouvrez-la depuis **Solutions et projets** : chaque projet que vous voyez en entier porte un lien
**Checklist de sécurité**. La décision
[0032](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/fr/decisions/0032-security-checklists.md)
consigne pourquoi elle fonctionne ainsi.

!!! info "Le projet entier, ou rien"
    Une checklist parle pour chaque dépôt de son projet. Elle est montrée à un compte dont la
    visibilité est totale, à un compte à qui le projet est accordé comme tel, et à un compte qui voit
    chacun des dépôts du projet — et il y en a au moins un. À tout autre, il est dit que le projet
    *n'existe pas ou ne lui est pas visible*, les mêmes mots pour les deux : un lecteur qui voit une
    partie d'un projet lirait sinon, en une ligne, l'état de dépôts qui lui sont cachés. Un projet
    que vous ne voyez qu'en partie n'a pas de lien de checklist dans l'arbre.

## Qui peut faire quoi

| | Administrateur, RSSI, security champion | Utilisateur | Auditeur | Gouverneur de la plateforme |
|---|---|---|---|---|
| Lire la checklist, ses lignes, son historique et ses révisions antérieures | oui | oui | oui | oui |
| L'ouvrir, répondre, joindre et retirer des preuves, soumettre, renvoyer, rouvrir, passer à une autre version | oui | oui | non | non |
| L'approuver | oui — [double validation](../administration/four-eyes.fr.md) active, **pas un auteur de la révision** | non | non | non |

L'auditeur lit tout et ne change rien. Le gouverneur de la plateforme décide des règles — il peut
écrire les modèles — et ne prend aucune décision sous elles : il ne répond ni n'approuve. Un compte
qui ne peut pas écrire voit la checklist sans un seul contrôle qui la modifie.

## 1. Ouvrir la checklist

Un projet sans checklist propose les versions **publiées** des modèles. Choisissez-en une et
**Ouvrir la checklist** : la révision 1 s'ouvre en **brouillon**, vous comme auteur, chaque ligne sans
réponse. Une version en brouillon ou retirée n'est jamais proposée.

Un projet a **une seule révision ouverte à la fois**. Si quelqu'un en a ouvert une après que vous avez
chargé la page, votre ouverture est refusée et l'écran propose de recharger — vous voyez la sienne
plutôt que d'en ouvrir une seconde.

## 2. Répondre aux lignes

Les lignes sont groupées comme le modèle les groupe : par domaine, puis par objectif, dans l'ordre de
la feuille. Chacune montre son contrôle, son contact et son KPI dans les mots du modèle, la preuve
qu'un « oui » demande, et ce qui l'empêche encore d'être soumise :

| Affiché sur la ligne | Que faire |
|---|---|
| Pas encore de réponse | Y répondre. |
| En attente de confirmation | Une réponse reportée sur une ligne qui a changé : y répondre de nouveau, ou **Confirmer la réponse**. |
| Commentaire requis | Un *non* ou *non applicable* sans sa raison : répondre de nouveau avec un commentaire. |
| Preuve requise | Un *oui* sur une ligne qui demande une preuve, sans aucune jointe (ou seulement un lien là où un fichier est demandé). |
| Preuve périmée | Toutes les preuves jointes ont dépassé leur validité : en joindre une plus récente. |

**Répondre** à une ligne par *oui*, *non* ou — seulement sur une version dont l'importateur y a associé
un mot — *non applicable* ; le mot du modèle est montré à côté de chacun. **Un *non* ou un *non
applicable* demande un commentaire** (4 000 caractères au plus) : le lecteur de la checklist a besoin
de la raison précisément sur ces lignes-là. L'écran refuse une réponse sans commentaire avant de rien
envoyer.

Répondre ne réécrit jamais une réponse : cela ajoute une ligne à l'**historique** de la ligne, sous
votre nom — le compte connecté, jamais un nom saisi quelque part — et la plus récente est la réponse
de la ligne. **Historique** sur une ligne liste chaque réponse donnée dans cette révision, de la plus
ancienne à la plus récente, avec qui et quand, et chaque preuve, retirées comprises.

Une équipe remplit une checklist ensemble. Votre réponse n'est refusée que lorsque **cette ligne-là** a
changé depuis que vous l'avez chargée — quelqu'un d'autre y a répondu ou y a joint une preuve —
jamais parce qu'une autre ligne a changé ; l'écran le dit sur la ligne et propose de recharger.

## 3. Joindre des preuves

**Ajouter une preuve** sur une ligne joint une preuve, avec **le jour où le travail a été fait** — un
jour, et pas dans le futur :

- **un lien** — une adresse `https:` ou `http:` avec un hôte, 2 000 caractères au plus ;
- **un fichier** — **25 Mo** au plus. L'écran refuse un fichier plus gros avant d'envoyer un octet,
  avec la phrase que le serveur répondrait ; joignez un document plus gros par un lien.

Un fichier n'est rendu **qu'en téléchargement**, comme des octets opaques, quel que soit le type qu'il
déclare : un fichier HTML ou SVG téléversé puis ouvert dans la page serait un script exécuté sur
l'origine du plan de contrôle. Son nom, sa taille et son SHA-256 sont montrés sur la ligne.

Quand une ligne dit combien de temps une preuve vaut, chaque preuve est **valable jusqu'au** jour
où le travail a été fait plus ce nombre de mois, et la ligne affiche *Preuve périmée* dès qu'aucune ne
vaut plus. Une preuve n'est demandée qu'à un *oui* — un *non* dit que le contrôle n'est pas en place,
et son commentaire dit pourquoi. Une ligne qui demande un fichier n'est pas satisfaite par un lien.

**Retirer** une preuve tant que la révision est un brouillon. Elle n'est jamais supprimée : elle cesse
de compter, et elle reste dans la liste, barrée, avec qui l'a retirée et quand.

## 4. Soumettre, renvoyer

**Soumettre pour approbation** est grisé, les lignes nommées, tant que chaque ligne n'est pas prête :
répondue, chaque *non* et *non applicable* commenté, chaque preuve qu'un *oui* demande jointe et
valable, et aucune réponse reportée en attente de confirmation. Une révision soumise n'est plus
répondue.

Quiconque peut écrire peut la **Renvoyer à ses auteurs** avec une raison, conservée sur la révision et
montrée dans son en-tête : elle redevient un brouillon, à remplir.

Une soumission, un renvoi, une approbation, une réouverture et un passage de version sont refusés
quand **quoi que ce soit** a changé dans la révision depuis que vous l'avez chargée — ce qui est soumis
ou approuvé est ce que vous avez relu, ligne pour ligne. L'écran explique le refus et propose de
recharger.

## 5. Approuver

Un administrateur, un RSSI ou un security champion **approuve** une révision soumise : l'attestation
de mise en production. [Double validation](../administration/four-eyes.fr.md) active, l'approbateur
ne doit être **aucun des auteurs de la révision** — quiconque l'a ouverte, a répondu à, reporté ou
confirmé une ligne, joint ou retiré une preuve, ou l'a soumise. L'en-tête liste ces auteurs, et le
bouton **Approuver** est grisé pour l'un d'eux avec la raison : *une deuxième personne doit
l'approuver*. Le serveur décide — le refus est inscrit au journal d'audit et envoyé au SIEM
(`VECTI-SEC-026`). Double validation éteinte, un approbateur peut approuver ce qu'il a écrit.

Une approbation est aussi refusée quand une preuve a cessé de valoir depuis la soumission — sa validité
a expiré entre-temps. Renvoyez la révision à ses auteurs, qui joignent une preuve plus récente et
soumettent de nouveau.

Une révision approuvée indique dans son en-tête qui l'a soumise, qui l'a approuvée et quand, et si la
double validation exigeait que les deux diffèrent.

## 6. Rouvrir

Une révision approuvée n'est jamais modifiée. **Rouvrir en nouvelle révision** ouvre la révision
suivante sur la **même version**, chaque réponse et chaque preuve reportées comme actuelles — rien à
confirmer, puisqu'aucune ligne n'a changé. La révision approuvée reste telle qu'elle a été approuvée,
listée plus bas.

Rouvrir ou changer de version fait de vous l'auteur de la nouvelle révision — vous l'avez ouverte, et
chaque réponse y a été reportée sous votre nom — si bien que, double validation active, quelqu'un
d'autre approuve cette révision.

## 7. Passer à une version plus récente

Quand une version plus récente du modèle est publiée, **Passer à une autre version** ouvre une nouvelle
révision dessus et **reporte** les réponses de la plus récente :

| La ligne dans la nouvelle version | Sa réponse |
|---|---|
| Inchangée | Reportée comme actuelle. |
| Modifiée — son libellé, son KPI, son exigence de preuve ou sa règle liée a bougé, ou elle a été appariée à la main avec une ligne reformulée | Reportée **en attente de confirmation** : y répondre de nouveau ou la confirmer avant que la révision puisse être soumise. |
| Ajoutée | Commence sans réponse. |
| Supprimée | Sa réponse reste dans la révision où elle a été donnée. |

Un *non applicable* reporté sur une version qui ne le propose pas attend lui aussi une nouvelle
réponse. Chaque réponse reportée garde le nom et l'instant de qui l'a donnée, et nomme qui l'a
reportée et quand ; les preuves d'une ligne inchangée ou modifiée la suivent, les retirées exceptées,
redatées selon la validité de la nouvelle ligne. **Passer à un autre modèle ne reporte rien** : les
mêmes mots dans une autre checklist sont une autre question.

La révision quittée devient *remplacée* si elle était un brouillon ou soumise ; une révision approuvée
reste approuvée. Dans les deux cas elle reste lisible.

## Révisions antérieures

**Révisions** liste chaque révision de la checklist du projet, de la plus récente à la plus ancienne,
avec son statut, sa version, qui l'a ouverte et qui l'a approuvée. **Lire** en montre une telle
qu'elle est, en lecture seule : seule la révision la plus récente fait l'objet d'actions.

## Quand le serveur refuse

Chaque refus est nommé par sa cause, et l'écran le dit en une phrase :

| L'écran dit | Ce qui s'est passé |
|---|---|
| La checklist a changé depuis que vous l'avez lue | Quelqu'un d'autre a modifié la révision après que vous l'avez chargée. Rechargez, regardez, réessayez. |
| Quelqu'un d'autre a écrit sur cette ligne | Une autre réponse ou preuve est arrivée sur la même ligne. Rechargez pour la voir. |
| Cette révision n'est plus un brouillon / n'attend plus d'approbation | Elle a été soumise, approuvée, renvoyée ou mise de côté entre-temps. |
| Seule une révision approuvée se rouvre / une révision plus récente existe | Agissez sur la révision la plus récente. |
| Toutes les lignes ne sont pas prêtes | Des lignes demandent encore de l'attention ; elles sont nommées. |
| Principe des quatre yeux : une deuxième personne doit l'approuver | Vous avez écrit une partie de cette révision. |
| Cette version n'est plus publiée / déjà sur cette version | Choisissez une autre version ; après une approbation, rouvrez plutôt. |
| Plus de réponse reportée en attente / preuve déjà retirée | Quelqu'un l'a fait avant vous. |

## Ce qui est consigné

L'ouverture, le passage de version, la réouverture, chaque réponse et chaque confirmation, chaque
preuve jointe ou retirée, la soumission, le renvoi, l'approbation et une approbation refusée sont
inscrits au [journal d'audit](../administration/audit-log.fr.md). Une approbation est signalée au SIEM
comme `VECTI-SEC-025` ; une approbation refusée et un renvoi comme `VECTI-SEC-026`.

## À lire aussi

- [Modèles de checklists](../administration/checklist-templates.fr.md) — où un modèle est importé,
  apparié avec sa version précédente et publié.
- [Double validation](../administration/four-eyes.fr.md) — le réglage qui décide qui peut approuver.
- [Solutions et projets](../administration/solutions-and-projects.fr.md) — les projets auxquels une
  checklist appartient, et les droits qui décident qui en voit un en entier.
