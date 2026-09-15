package com.asmolabs.vectispire.common.domain.remediation;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Ce que le plan de remédiation peut atteindre, et ce qu'il ne peut pas.
 *
 * <h2>Pourquoi un écran de remédiation doit se dénoncer lui-même</h2>
 *
 * <p><b>Le classement ne regarde que les vulnérabilités portant un nom de paquet.</b> C'est
 * délibéré et c'est juste : une ligne du plan est une montée de version, et une montée de version
 * est la seule chose qui referme quatorze constats d'un coup. Mais la conséquence ne se voit nulle
 * part — un dépôt dont le retard est fait de secrets exposés affiche une seule action face à des
 * centaines de constats ouverts, et rien sur l'écran ne dit que ce n'est pas une erreur de calcul.
 *
 * <p>C'est exactement la lecture qu'un utilisateur en a faite. Le produit avait raison et
 * paraissait cassé, ce qui coûte plus cher qu'un chiffre faux : un chiffre faux se corrige, une
 * défiance se garde. <b>Ce modèle est donc l'aveu du plan, calculé plutôt que rédigé</b> — il
 * compte les constats que le classement écarte et dit de quelle famille ils sont, pour que
 * l'écran puisse dire comment on les referme autrement.
 *
 * <h2>Ce qui n'est pas compté ici</h2>
 *
 * <p>{@link FindingType#AI_REVIEW} est écarté du total comme il l'est de l'estimation d'effort :
 * sa sévérité est inventée par un modèle local lisant un dépôt qui peut être hostile. L'inclure
 * dans « ce qui reste à faire » laisserait un dépôt gonfler son propre reste-à-faire.
 *
 * <h2>Des constats, et non des vulnérabilités distinctes</h2>
 *
 * <p><b>Tout ce qui est compté ici est un constat ouvert</b>, alors qu'une ligne du plan annonce
 * des identifiants distincts — le même CVE sur deux dépôts est une montée de version et deux
 * constats. {@link #addressableByUpgrade} ne s'additionne donc pas en
 * {@code sum(cveCountResolved)}, et c'est voulu : la question à laquelle ce modèle répond est
 * « combien de lignes de mon retard ce plan peut-il fermer », qui se pose en constats.
 */
public record RemediationCoverage(
        long openFindings,
        long addressableByUpgrade,
        long beyondUpgrades,
        List<RemediationGap> gaps) {

    /**
     * La famille des vulnérabilités qu'aucun paquet ne nomme.
     *
     * <p>Une vulnérabilité sans paquet est bien une vulnérabilité, et il n'y a pourtant rien à
     * monter : le scanner l'a rapportée sur une cible sans dire de quel composant elle vient. Elle
     * a donc sa propre famille plutôt que d'être diluée dans {@code vulnerability}, où elle
     * laisserait croire que le plan l'a simplement classée trop bas.
     */
    public static final String UNPACKAGED = "unpackaged";

    /**
     * Une famille ouverte, telle que la base la compte.
     *
     * @param type le nom de transport du type, tel que la ligne le porte. <b>Comparé à la lettre
     *     et non traduit en {@link FindingType}</b> : le classement du plan filtre sur la chaîne
     *     {@code vulnerability} exacte, et un type inconnu de cette version que l'on rangerait par
     *     défaut parmi les vulnérabilités serait annoncé comme couvert par un plan qui ne le
     *     regarde pas. Inconnu, il devient donc un manque portant son propre jeton — l'écran le
     *     nommera faute de mieux, et il sera compté
     * @param packageNamed combien de ces constats portent un nom de paquet
     * @param unnamed combien n'en portent pas
     */
    public record OpenFamily(String type, long packageNamed, long unnamed) {}

    /**
     * Répartit les familles ouvertes entre ce qu'une montée de version referme et le reste.
     *
     * <p>Les manques sont rendus du plus nombreux au moins nombreux, à égalité par nom : un écran
     * qui nomme d'abord la famille la plus grosse répond à « pourquoi une seule ligne » dès la
     * première phrase, et deux lectures des mêmes données s'accordent.
     */
    public static RemediationCoverage of(List<OpenFamily> families) {
        long addressable = 0;
        long beyond = 0;
        List<RemediationGap> gaps = new ArrayList<>();

        for (OpenFamily family : families) {
            if (FindingType.AI_REVIEW.wireName().equals(family.type())) {
                continue;
            }
            if (FindingType.VULNERABILITY.wireName().equals(family.type())) {
                addressable += family.packageNamed();
                if (family.unnamed() > 0) {
                    beyond += family.unnamed();
                    gaps.add(new RemediationGap(UNPACKAGED, family.unnamed()));
                }
                continue;
            }
            long all = family.packageNamed() + family.unnamed();
            if (all > 0) {
                beyond += all;
                gaps.add(new RemediationGap(family.type(), all));
            }
        }

        gaps.sort(Comparator.comparingLong(RemediationGap::findings).reversed()
                .thenComparing(RemediationGap::family));

        return new RemediationCoverage(addressable + beyond, addressable, beyond, List.copyOf(gaps));
    }
}
