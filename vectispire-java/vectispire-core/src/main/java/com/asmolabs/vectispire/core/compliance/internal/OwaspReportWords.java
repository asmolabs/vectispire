package com.asmolabs.vectispire.core.compliance.internal;

import com.asmolabs.vectispire.common.domain.aireview.AdviceLanguage;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import java.util.Locale;
import java.util.stream.Collectors;

/**
 * The OWASP report PDF's own words, in the two languages the interface is read in.
 *
 * <p><b>Why the server holds sentences here, when decision 0019 sends tokens to the screens.</b> A PDF is
 * rendered on the server and leaves it: no client is there to translate it. So the document's fixed labels
 * and the grid's reasons are written here in both languages, from the same codes the screen translates
 * ({@link OwaspCoverage.ReasonCode}); the English is the domain's own sentence, so the document in English
 * says exactly what the route's {@code because} says. <b>The model's text is never translated</b>: it is
 * what the model wrote, and rewording it would be putting words in its mouth.
 *
 * <p>The French reasons are the interface's French bundle (`owasp_grid.reason.*`, `owasp_grid.gap.*`),
 * spelt again: a change to one is a change to the other.
 */
enum OwaspReportWords {
    TITLE("OWASP Top 10:2021 — posture report", "OWASP Top 10:2021 — rapport de posture"),
    VERSION("version %s", "version %s"),
    OPEN_FINDINGS("Open findings at the time of writing: %d", "Constats ouverts au moment de la rédaction : %d"),
    BUILT_FROM("Built from scan #%d", "Établi à partir du scan #%d"),
    SCANNED_AT(" of %s", " du %s"),
    WRITTEN_BY("Written by %s", "Rédigé par %s"),
    GENERATED("Generated %s", "Généré le %s"),
    HOW_TO_READ("How to read this", "Comment le lire"),
    READ_FACTS("Every fact below comes from an automated scanner. ", "Chaque fait ci-dessous provient d'un scanner automatisé. "),
    READ_PLACED_BY_RULE(
            "Each finding sits under the OWASP category Vectispire's own rules place it in — the same placement as "
                    + "the OWASP coverage grid — and a finding they place nowhere is listed apart. A language model grouped "
                    + "them and wrote the prose; ",
            "Chaque constat figure sous la catégorie OWASP où le placent les règles de Vectispire — le même placement "
                    + "que la grille de couverture OWASP — et un constat qu'elles ne placent nulle part est listé à part. Un "
                    + "modèle de langage les a regroupés et a rédigé le texte ; "),
    READ_PLACED_BY_MODEL(
            "A language model grouped those findings under the OWASP categories and wrote the prose; ",
            "Un modèle de langage a regroupé ces constats sous les catégories OWASP et a rédigé le texte ; "),
    READ_CAVEAT(
            "it detected nothing itself, and nothing it says becomes an issue or reaches a build gate. A category with "
                    + "no finding is not a clean bill of health: either no scanner here can examine it, or none is set to, "
                    + "or one examined the part it can see and found nothing open. The OWASP coverage grid below says which.",
            "il n'a rien détecté lui-même, et rien de ce qu'il dit ne devient une issue ni n'atteint une barrière. Une "
                    + "catégorie sans constat n'est pas un certificat de bonne santé : soit aucun scanner d'ici ne peut "
                    + "l'examiner, soit aucun n'est réglé pour, soit l'un d'eux a examiné la part qu'il peut voir et n'y a "
                    + "rien trouvé d'ouvert. La grille de couverture OWASP ci-dessous dit lequel."),
    /**
     * Said only where the labels are not English. The model is asked in English and its language is not
     * recorded, so the line says the text is as written rather than naming a language nobody checked.
     */
    BODY_AS_WRITTEN(
            "",
            "Le texte rédigé par le modèle, après la grille, est reproduit tel qu'il l'a écrit et dans sa langue : "
                    + "seuls les libellés de ce document sont traduits."),
    GRID_TITLE("OWASP Top 10:2021 coverage, by rule", "Couverture de l'OWASP Top 10:2021, par règle"),
    GRID_INTRO(
            "Computed for this repository by Vectispire's rules when this document was generated — not by the model, "
                    + "and not as of the scan the report was written from.",
            "Calculée pour ce dépôt par les règles de Vectispire à la génération de ce document — non par le modèle, "
                    + "et non à la date du scan dont le rapport est tiré."),
    GRID_FIGURES(
            "%d of 10 categories any scanner here can see  ·  %d with open findings  ·  %d covered but unmeasured",
            "%d catégories sur 10 qu'un scanner d'ici peut voir  ·  %d avec des constats ouverts  ·  %d couvertes mais "
                    + "non mesurées"),
    STATE_FINDINGS("Findings (%d)", "Constats (%d)"),
    STATE_NOT_MEASURED("Not measured", "Non mesurée"),
    STATE_NOT_COVERED("No scanner here", "Aucun scanner ici"),
    STATE_NO_FINDING("Nothing found", "Rien trouvé"),
    EMPTY_REPORT("The model returned an empty report.", "Le modèle a renvoyé un rapport vide."),
    FOOTER("%s — OWASP Top 10:2021 report — %s", "%s — rapport OWASP Top 10:2021 — %s");

    private final String english;
    private final String french;

    OwaspReportWords(String english, String french) {
        this.english = english;
        this.french = french;
    }

    String in(AdviceLanguage language, Object... values) {
        String template = language == AdviceLanguage.FRENCH ? french : english;
        return values.length == 0 ? template : String.format(Locale.ROOT, template, values);
    }

    /** A line's state in words, with its count where it has one. */
    static String state(OwaspCoverage.CoverageLine line, AdviceLanguage language) {
        return switch (line.state()) {
            case FINDINGS -> STATE_FINDINGS.in(language, line.findings());
            case NOT_MEASURED -> STATE_NOT_MEASURED.in(language);
            case NOT_COVERED -> STATE_NOT_COVERED.in(language);
            case NO_FINDING -> STATE_NO_FINDING.in(language);
        };
    }

    /**
     * Why a line reads what it reads. In English, the domain's sentence as the route sends it; in French, the
     * same code and values in the interface's words.
     */
    static String reason(OwaspCoverage.CoverageLine line, AdviceLanguage language) {
        if (language != AdviceLanguage.FRENCH) {
            return line.because();
        }
        OwaspCoverage.CoverageReason reason = line.reason();
        String types = reason.types().stream().map(OwaspReportWords::frenchType).collect(Collectors.joining(", "));
        return switch (reason.code()) {
            case NO_SCANNER -> "Aucun scanner de ce déploiement ne produit de constat dans cette catégorie.";
            case CODE_ANALYSIS_OFF ->
                    "L'analyse de code est désactivée, ou seule la règle livrée avec ce produit est installée.";
            case DETECTION_OFF -> "La détection est désactivée pour " + types
                    + " : cette catégorie n'est donc pas mesurée.";
            case DETECTION_AND_CODE_ANALYSIS_OFF -> "La détection est désactivée pour " + types
                    + ", et l'analyse de code est désactivée ou seule la règle livrée avec ce produit est installée : "
                    + "cette catégorie n'est donc pas mesurée.";
            case OPEN_FINDINGS -> "Des constats ouverts sont placés ici par règle.";
            case NOTHING_SCANNED -> "Rien n'a encore été scanné : aucun constat de cette catégorie ne pouvait exister.";
            case TARGET_KIND_NOT_EXAMINED -> "Rien ici n'examine ce type de cible pour " + types
                    + " : le scan d'une image ne lit que ses dépendances.";
            case CODE_ANALYSIS_READS_REPOSITORIES_ONLY ->
                    "Seule l'analyse de code place des constats ici, et elle lit les dépôts, pas les images.";
            case NO_EXAMINABLE_TARGET_IN_SCOPE -> "Aucune cible de ce périmètre ne peut être examinée pour " + types
                    + " : le scan d'une image ne lit que ses dépendances, et ce périmètre ne contient aucun dépôt.";
            case NO_REPOSITORY_IN_SCOPE ->
                    "Seule l'analyse de code place des constats ici, et ce périmètre ne contient aucun dépôt à lire.";
            case EXAMINED_NOTHING_OPEN -> "Examinée par " + types
                    + " — le dernier scan de chaque cible concernée l'a examinée — sans rien d'ouvert.";
            case CODE_EXAMINED_NOTHING_OPEN -> "Examinée par l'analyse de code — le dernier scan de chaque dépôt "
                    + "concerné l'a examinée — sans rien d'ouvert.";
            case TARGETS_NOT_EXAMINED -> unexamined(reason, "des cibles concernées", "examinée", "examinées", types);
            case REPOSITORIES_NOT_EXAMINED ->
                    unexamined(reason, "des dépôts concernés", "examiné", "examinés", "l'analyse de code");
        };
    }

    private static String unexamined(
            OwaspCoverage.CoverageReason reason, String which, String one, String many, String by) {
        long missing = reason.missing() == null ? 0 : reason.missing();
        String why = reason.gaps().stream()
                .map(OwaspReportWords::frenchGap)
                .collect(Collectors.joining(", "));
        return missing + " " + which + " par cette catégorie (" + reason.applicable() + " au total) "
                + (missing == 1 ? "n'a pas été " + one : "n'ont pas été " + many) + " pour elle par " + by + " (" + why
                + ") : un zéro ici ne serait pas un résultat.";
    }

    private static String frenchGap(OwaspCoverage.GapCount gap) {
        long count = gap.targets();
        return count + switch (gap.gap()) {
            case NEVER_SCANNED -> count == 1 ? " n'a jamais terminé de scan" : " n'ont jamais terminé de scan";
            case LAST_SCAN_FAILED -> " dont le dernier scan a échoué";
            case UNRECORDED -> " dont le dernier scan précède l'enregistrement de ce qu'il a examiné";
            case STEP_ABSENT -> " dont le dernier scan n'a pas terminé cette étape";
            case LANGUAGES_UNRECORDED -> " dont le dernier scan n'a pas enregistré ses langages, ni ceux de ses règles";
            case NO_RULE_FOR_ITS_LANGUAGES -> " dans les langages desquels aucune règle installée ne déclare cette catégorie";
        };
    }

    /** The interface's names of the finding types (`issues.types.*`), lower-cased as they sit in a sentence. */
    private static String frenchType(String wireName) {
        return switch (wireName) {
            case "vulnerability" -> "vulnérabilité";
            case "secret" -> "secret exposé";
            case "iac" -> "configuration d'infrastructure";
            case "eol" -> "fin de support";
            case "license" -> "licence";
            case "sast" -> "code vulnérable";
            default -> wireName;
        };
    }
}
