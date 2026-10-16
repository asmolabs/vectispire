# 0044 — Les contacts d'une checklist sont liés à des comptes et rappelés chaque semaine

**Date :** 2026-10-16 · **Statut :** acceptée · **S'appuie sur :** [0032](0032-security-checklists.md), [0023](0023-solutions-projects-and-repositories.md) · **Décideur :** Laurent Boucher

## Contexte

La colonne de contact d'un modèle de checklist dit à qui chaque ligne doit être demandée — sous la forme
d'un rôle, pas d'une personne : les classeurs de l'organisation contiennent *PO*, *BA*, *Arch*, *SII*,
*PO / BA*, et *AUTO* sur les lignes auxquelles une analyse répond. La décision
[0032](0032-security-checklists.md) l'a gardée en texte (question 16) et a laissé de côté « l'affectation
des lignes à des comptes depuis la colonne de contact, les rappels, les échéances, les notifications ».

Un premier déploiement en production change cela : une checklist ouverte pour un projet est remplie sur
plusieurs semaines par plusieurs personnes, et rien ne dit à aucune d'elles que des lignes l'attendent. Le
responsable sécurité les relance à la main, projet par projet, depuis une colonne qui nomme un rôle auquel
personne n'est rattaché.

Ce sur quoi s'appuyer : la colonne est stockée par ligne (`t_checklist_item.contact`) ; le rapport de
posture hebdomadaire tourne déjà sur la tâche horaire et garde son « envoyé cette semaine » dans le journal
d'audit ; le relais de messagerie est configuré par le déploiement, mais n'envoie qu'aux destinataires
globaux d'un paramètre ; les comptes portent une adresse e-mail facultative ; et chaque route de checklist
refuse un projet que l'appelant ne voit pas entier.

## Décision

1. **Un profil est une valeur de la colonne de contact, lue dans les cellules.** Chaque valeur est un
   profil, sauf `AUTO`, qui marque une ligne que Vectispire mesure. Une cellule est découpée sur `/` —
   *PO / BA* est la ligne des deux profils — et comparée après la même normalisation que les mots du
   modèle, en majuscules : *Arch* et *ARCH* sont un seul profil, affiché comme il a été écrit la première
   fois. Pas de liste fermée PO, BA, architecte : une liste dans le code ne rappellerait personne du profil
   qu'elle oublie (*SII*), et la colonne appartient à l'organisation.
2. **Un projet lie chaque profil à un compte** (`t_checklist_contact`, V91), conservé par la clé du profil
   plutôt que par une ligne, pour que le lien survive à la version du modèle sur laquelle il a été fait. Les
   profils listés sont ceux de la version de la révision la plus récente ; un profil qu'une version plus
   récente ne nomme plus garde son lien, inutilisé.
3. **Le compte lié peut remplir la checklist** : actif, d'un rôle qui répond aux checklists
   (`canCauseEffects` — ni l'auditeur, ni le gouverneur de plateforme), et voyant le projet entier avec son
   propre compte, sous le mode de visibilité en vigueur. Sinon le lien est refusé, avec une seule phrase
   pour un compte qui n'existe pas et pour un compte qui ne peut pas la remplir. Lier et délier revient à
   qui écrit — qui peut répondre à la checklist — et est consigné (`CHECKLIST_CONTACT_CHANGED`). Les comptes
   proposés sont listés par identifiant et par un nom, jamais une adresse e-mail, ni un nom qui en est une.
4. **Ce qui reste à remplir est une ligne du brouillon ouvert sans réponse courante, ou dont la réponse
   reportée attend une confirmation.** Une révision soumise n'est à remplir par personne tant qu'elle n'est
   pas renvoyée. Les autres problèmes d'une ligne — un commentaire ou une preuve manquants, une mesure
   contredite — reviennent à qui soumet, et bloquent déjà la soumission.
5. **Une fois par semaine, chaque compte lié reçoit un e-mail** à sa propre adresse, qui nomme chacune de
   ces lignes pour ses profils, sur tous ses projets. **Un profil qui a de telles lignes et personne à
   rappeler revient aux CISO** : lié à personne, ou à un compte supprimé depuis, désactivé, qui ne peut plus
   remplir la checklist, ou sans adresse. Chaque CISO actif qui a une adresse reçoit la liste de ces profils
   avec la raison, chacun seulement pour les projets que son propre compte voit entiers.
6. **Désactivé par défaut** (`checklist_reminders_enabled`, un paramètre de notification, celui du
   responsable sécurité comme le rapport de posture) : un déploiement mis à jour ne se met pas à écrire à ses
   utilisateurs. Il nécessite le relais de messagerie ; sans relais, rien n'est envoyé ni réessayé.
7. **La comptabilité est le journal d'audit, une entrée par destinataire** (`CHECKLIST_REMINDER_SENT`, sa
   ressource le lundi de la semaine et le destinataire), écrite après l'envoi : un relais qui refuse une
   adresse est réessayé l'heure suivante pour cette adresse seule. Aucune des deux entrées n'est signalée au
   SIEM : qui est sollicité pour remplir une checklist relève du travail, pas d'un événement de sécurité.

## Conséquences

- Le canal de messagerie gagne un envoi à des adresses données (`MailNotificationChannel.sendTextTo`) ; le
  module `checklists` dépend de `notifications`.
- Un compte supprimé par SCIM laisse son lien ne nommer personne — le profil indique `account_gone` et ses
  lignes vont aux CISO jusqu'à ce qu'il soit de nouveau lié. Pas de clé étrangère : les tables des
  checklists n'en ont pas ([V52](0032-security-checklists.md)), et les liens d'un projet sont purgés avec lui
  par `ChecklistPurge`.
- Deux plans de contrôle peuvent envoyer dans la même heure, comme le rapport de posture ; un doublon est
  préféré à un verrou.
- Le message est en texte brut, en anglais, comme chaque e-mail que Vectispire envoie : il n'y a ni moteur
  de gabarits ni traduction côté serveur.

## Rejeté

- **Une liste fixe PO, BA, architecte.** Les classeurs portent déjà *SII* ; une liste fixe laisserait ces
  lignes à personne, sans le dire.
- **Lier un profil à une équipe.** La question 16 de 0032 le suggérait. Une équipe est un droit d'accès, et
  un rappel à une équipe de douze n'est lu par aucun d'eux ; une personne responsable par profil est ce que
  demande la colonne.
- **Rappeler chaque ligne qui a un problème.** Un commentaire ou une preuve manquants, une mesure
  contredite, sont à résoudre par qui soumet, et refusent la soumission en nommant la ligne ; le rappel
  concerne les lignes auxquelles personne n'a répondu.
- **Envoyer aux destinataires e-mail globaux.** C'est le canal de l'équipe sécurité pour les alertes
  d'analyse ; le rappel s'adresse à la personne qui doit agir.
