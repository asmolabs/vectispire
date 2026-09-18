# Déclaration d'applicabilité

Ce que votre organisation **affirme** d'un contrôle, confronté à ce que le parc **mesure**. Ce qui
sert n'est ni l'une ni l'autre moitié prise seule : c'est la ligne où les deux se contredisent.

La clause 6.1.3 d de l'ISO/IEC 27001 exige une déclaration d'applicabilité : pour chaque contrôle,
s'il s'applique, s'il est en place, et pourquoi un contrôle exclu l'est. Vectispire conserve cette
déclaration et la rapproche, contrôle par contrôle, de ce qu'il peut observer.

## Pourquoi le désaccord est le sujet

Un contrôle déclaré *en place* que le parc mesure *non conforme* est exactement ce qu'un
évaluateur relève. Aucune des deux moitiés du produit ne pouvait le voir seule : la déclaration
est un document que personne ne vérifie, la mesure est un chiffre dont personne n'avait rien
affirmé.

L'écran trie donc par **gravité d'écart**, et non par identifiant de contrôle. Le serveur rend les
lignes dans l'ordre du standard, qui est le bon pour imprimer le document et le mauvais pour
l'ouvrir : la question posée devant cet écran est « qu'est-ce qui ne va pas », et elle se répond en
haut.

| Écart | Ce qu'il signifie |
|---|---|
| **Contredit** | Déclaré en place, mesuré non conforme. L'organisation n'est pas seulement en défaut : elle a écrit le contraire. |
| **Surévalué** | Déclaré en place, mesuré partiel. Un document en avance sur la pratique — autre classe de problème qu'une affirmation fausse. |
| **Sous-évalué** | Déclaré prévu, mesuré conforme. Le document a décroché derrière la pratique. |
| **Non déclaré** | Personne n'a traité ce contrôle. |
| **Exclu sans justification** | La clause 6.1.3 d autorise une exclusion et exige qu'elle soit argumentée. |
| **Non mesuré ici** | La preuve vit dans un autre système ; Vectispire refuse de juger. |

## Une instance neuve affiche des constats, et c'est correct

La clause 6.1.3 d demande que *chaque* contrôle soit traité. Le silence est le manque : un document
vide rapporte donc un constat par contrôle plutôt qu'une page propre. Trier les non déclarés en bas
aurait fait passer un document vide pour un document fini.

## Les preuves qui vivent ailleurs

`evidence_source` est le champ qui empêche cet écran de mentir. Vectispire mesure une tranche de
chaque contrôle, jamais sa totalité. Un contrôle dont la preuve est une revue d'accès IAM ou un
questionnaire fournisseur est affiché **non mesuré ici** : c'est un renvoi vers l'autre document,
pas un constat contre vous.

Un contrôle dont la preuve est **à la fois** ici et ailleurs reste jugé, sur la tranche mesurée ici.

## Revues échues

Une déclaration porte une date de revue. Le compteur de revues échues ouvre sur la liste, tous
référentiels confondus — un chiffre qu'on ne peut pas ouvrir n'est pas une trace de revue, c'est un
reproche. Une revue échue se compte à part de l'écart : l'affirmation peut toujours correspondre au
parc, et ce qui a expiré est sa confirmation.

L'écran ouvre sur **ISO 27001**, et non sur le premier référentiel de la liste.

## À lire aussi

- [Conformité](compliance.fr.md) — la moitié mesurée, et le bundle de preuves.
- [Périmètre certifié](certified-scope.fr.md) — ce à quoi les contrôles s'appliquent.
- [Exceptions](exceptions.fr.md) — ce qu'on a délibérément laissé, et sous quelles conditions.
