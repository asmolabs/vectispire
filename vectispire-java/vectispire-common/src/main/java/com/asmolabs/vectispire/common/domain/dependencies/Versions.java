package com.asmolabs.vectispire.common.domain.dependencies;

import java.util.Collection;
import java.util.Comparator;
import java.util.Optional;

/**
 * Comparer deux versions comme un humain les lit, et non comme un tri de chaînes les range.
 *
 * <p><b>Ce que cette classe rend possible.</b> L'écran de remédiation dit quelle version installer.
 * La réponse est dans les constats — chacun porte les versions qui corrigent la vulnérabilité qu'il
 * décrit — mais il y en a plusieurs par paquet, et choisir la bonne veut dire les comparer.
 * Lexicographiquement, {@code "2.9.0"} passe après {@code "2.17.1"}, et l'écran conseillerait
 * d'installer une version qui laisse la faille ouverte.
 *
 * <p><b>Ce n'est pas une implémentation de semver.</b> Les versions ici viennent de six écosystèmes
 * et n'en respectent aucun de façon fiable. Ce qui est fait : découper sur les points, les tirets
 * et les soulignés, comparer numériquement ce qui est numérique et alphabétiquement le reste, et
 * traiter les segments absents comme des zéros pour que {@code 2.17} et {@code 2.17.0} soient
 * égaux. Ce qui n'est pas fait : la préséance des pré-versions de semver — {@code 1.0.0-alpha}
 * passe ici <em>après</em> {@code 1.0.0} et non avant. C'est un choix : conseiller une version un
 * cran trop haute est sans danger, conseiller une version trop basse laisse la faille.
 */
public final class Versions {

    /** Les séparateurs des six écosystèmes suivis, réunis. */
    private static final String SEPARATORS = "[._\\-+]";

    public static final Comparator<String> ASCENDING = Versions::compare;

    /**
     * La plus haute d'un ensemble, en ignorant ce qui n'est pas une version.
     *
     * <p>Vide plutôt qu'un texte de remplacement : « aucune version corrigée publiée » et
     * « passez à celle-ci » sont deux réponses différentes, et l'écran doit pouvoir les dire
     * différemment. Le champ portait la chaîne {@code "latest-patch"}, affichée telle quelle
     * derrière une flèche sur le tableau de bord — ni une version, ni un aveu d'ignorance.
     */
    public static Optional<String> highest(Collection<String> candidates) {
        if (candidates == null) {
            return Optional.empty();
        }
        return candidates.stream()
                .filter(candidate -> candidate != null && !candidate.isBlank())
                .map(String::trim)
                .max(ASCENDING);
    }

    /**
     * Les versions d'une liste séparée par des virgules, telle que les scanners la remontent.
     *
     * <p>{@code fix_versions} n'est pas une version mais une énumération : « 2.12.2, 2.3.2,
     * 2.17.1 » quand une branche de maintenance a été corrigée en même temps que la principale.
     */
    public static java.util.List<String> split(String commaSeparated) {
        if (commaSeparated == null || commaSeparated.isBlank()) {
            return java.util.List.of();
        }
        return java.util.Arrays.stream(commaSeparated.split(","))
                .map(String::trim)
                .filter(part -> !part.isEmpty())
                .toList();
    }

    public static int compare(String left, String right) {
        String[] leftParts = left.split(SEPARATORS);
        String[] rightParts = right.split(SEPARATORS);

        int length = Math.max(leftParts.length, rightParts.length);
        for (int index = 0; index < length; index++) {
            // Un segment absent vaut zéro, sans quoi 2.17 et 2.17.0 différeraient par leur
            // écriture et non par ce qu'elles désignent.
            String leftPart = index < leftParts.length ? leftParts[index] : "0";
            String rightPart = index < rightParts.length ? rightParts[index] : "0";

            int verdict = comparePart(leftPart, rightPart);
            if (verdict != 0) {
                return verdict;
            }
        }
        return 0;
    }

    private static int comparePart(String left, String right) {
        boolean leftIsNumber = isNumber(left);
        boolean rightIsNumber = isNumber(right);

        if (leftIsNumber && rightIsNumber) {
            // Comparé comme un entier long et non comme une chaîne : « 10 » vient après « 9 ».
            // Les segments trop longs pour un long existent (des dates compactées, des identifiants
            // de build) et retombent alors sur la comparaison textuelle plutôt que de lever.
            try {
                return Long.compare(Long.parseLong(left), Long.parseLong(right));
            } catch (NumberFormatException overflow) {
                return left.length() != right.length()
                        ? Integer.compare(left.length(), right.length())
                        : left.compareTo(right);
            }
        }
        if (leftIsNumber != rightIsNumber) {
            // Un chiffre l'emporte sur un mot : `2.0` est postérieure à `2.rc`, et un suffixe
            // textuel désigne presque toujours une pré-version dans les écosystèmes suivis.
            return leftIsNumber ? 1 : -1;
        }
        return left.compareToIgnoreCase(right);
    }

    private static boolean isNumber(String part) {
        if (part.isEmpty()) {
            return false;
        }
        for (int index = 0; index < part.length(); index++) {
            if (!Character.isDigit(part.charAt(index))) {
                return false;
            }
        }
        return true;
    }

    private Versions() {}
}
