# Attestation

À quoi ressemblait le parc, à une heure donnée, preuve jointe.

## Pourquoi une page et non un cinquième lien

Les quatre écrans dont un auditeur a besoin existent déjà — le journal d'audit et sa vérification de
chaîne, le résumé de conformité, la politique de barrière, le bundle de preuves — et **aucun ne
porte d'heure**.

Un auditeur ne demande pas « où en êtes-vous ». Il demande « où en étiez-vous le jour où j'ai
regardé », et un écran sans heure ne peut pas y répondre.

## La chaîne d'abord, parce que c'est la seule preuve de cette page

Tout le reste est une mesure. La chaîne d'audit est la seule affirmation qui se démontre sur-le-champ :
chaque entrée porte l'empreinte de la précédente, si bien qu'une entrée modifiée ou supprimée après
coup rompt la chaîne à un endroit qu'on peut nommer.

Deux nombres l'accompagnent, à ne pas confondre :

- **rompue** nomme l'entrée où la chaîne échoue. C'est une alarme.
- **invérifiable** compte les entrées antérieures au chaînage. C'est de l'histoire, pas une
  altération, et le lire comme une alarme ferait passer une vieille installation pour compromise.

## Ce que contient le bundle

Un clic exporte le bundle de preuves signé. Les neuf sections sont décrites plutôt que listées : les
noms de fichiers appartiennent au serveur, et les recopier ici créerait une seconde liste qui
divergerait au premier renommage sans que rien ne le signale. Nommer ce qu'elles contiennent reste
vrai plus longtemps que nommer comment elles s'appellent.

La signature est ce qui rend le paquet plus qu'une capture d'écran : elle atteste que ce bundle est
celui que Vectispire a produit, non modifié.

## Le périmètre et la conformité se lisent ensemble

Une attestation sans périmètre est la mesure d'une chose qu'on n'a pas nommée. La page affiche la
posture de conformité à côté de l'état de la chaîne, et l'échec de l'une n'efface pas l'autre : une
conformité indisponible ne doit pas emporter une chaîne vérifiée.

## À lire aussi

- [Conformité](compliance.fr.md) — les référentiels derrière la posture.
- [Périmètre certifié](certified-scope.fr.md) — ce sur quoi l'attestation porte.
- [Journal d'audit](../administration/audit-log.fr.md) — la chaîne elle-même, et son miroir hors base.
