package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.remediation.RemediationDistribution;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * La distribution des délais, comme le fil l'épelle.
 *
 * <h2>Une seule différence avec le record du domaine, et elle a coûté un test</h2>
 *
 * <p><b>La gravité en minuscules.</b> Le domaine porte l'énumération {@link Severity}, ordonnée du
 * pire au moins grave, et c'est ce qui la rend comparable. Sérialisée telle quelle, elle sort en
 * {@code CRITICAL} — alors que toutes les autres routes de cette API passent par
 * {@link Severity#wireName()} et envoient {@code critical}. Cette route était la seule à en
 * décider autrement, et rien ne le disait.
 *
 * <p>Un client qui branche sur la gravité devait donc connaître deux orthographes. Le test de
 * l'écran cherchait {@code severity === 'low'} et ne trouvait aucune ligne ; sa fixture écrivait
 * {@code 'low'} aussi, donc l'absence ne levait pas et le test restait vert. <b>Deux erreurs qui
 * s'accordent font un test qui ne mesure rien.</b>
 *
 * <h2>Pourquoi pas un {@code @JsonValue} sur l'énumération</h2>
 *
 * <p>Il aurait corrigé les deux champs d'un coup, et bien davantage : Jackson applique
 * {@code @JsonValue} aux <em>clés</em> des cartes, et {@code countsBySeverity} comme
 * {@code backlogBySeverity} en sont. Les écrans les indexent par {@code ['CRITICAL']}. La
 * correction la plus élégante cassait le tableau de bord — vérifié avant d'être écartée, pas après.
 *
 * <h2>Pourquoi une vue plutôt qu'une annotation sur le record</h2>
 *
 * <p>{@code vectispire-common} est le module domaine et ne dépend d'aucune annotation web : y
 * mettre {@code @Schema} aurait fait entrer springdoc dans une couche qui n'en veut pas.
 * {@link ViolationView} existe pour exactement cette raison, et dit exactement cela.
 *
 * <p>La liste des valeurs est recopiée dans {@code @Schema} parce qu'un accesseur qui rend une
 * {@code String} ne laisse rien à énumérer. Une liste recopiée dérive : c'est
 * {@code RemediationSeverityWireTest} qui l'en empêche, en comparant ce que le document publie à
 * {@code Severity.values()}.
 */
public record RemediationDistributionView(
        int windowDays, List<BySeverityView> bySeverity, Long oldestOpenDays, String oldestOpenSeverity) {

    /** Les six valeurs de {@link Severity}, dans la forme que cette API emploie partout. */
    static final String[] WIRE_SEVERITIES = {"critical", "high", "medium", "low", "negligible", "unknown"};

    public static RemediationDistributionView of(RemediationDistribution distribution) {
        return new RemediationDistributionView(
                distribution.windowDays(),
                distribution.bySeverity().stream().map(BySeverityView::of).toList(),
                distribution.oldestOpenDays(),
                wire(distribution.oldestOpenSeverity()));
    }

    private static String wire(Severity severity) {
        return severity == null ? null : severity.wireName();
    }

    /** @see RemediationDistribution.BySeverity */
    public record BySeverityView(
            @Schema(allowableValues = {"critical", "high", "medium", "low", "negligible", "unknown"})
                    String severity,
            int windowDays,
            long withinSla,
            long late,
            Double percentageWithinSla,
            Double medianDays,
            Double ninetiethDays,
            long openOverdue,
            Long oldestOpenDays) {

        static BySeverityView of(RemediationDistribution.BySeverity row) {
            return new BySeverityView(
                    wire(row.severity()),
                    row.windowDays(),
                    row.withinSla(),
                    row.late(),
                    row.percentageWithinSla(),
                    row.medianDays(),
                    row.ninetiethDays(),
                    row.openOverdue(),
                    row.oldestOpenDays());
        }
    }

    /** La même énumération que ci-dessus, sur le champ du haut. */
    @Schema(allowableValues = {"critical", "high", "medium", "low", "negligible", "unknown"})
    @Override
    public String oldestOpenSeverity() {
        return oldestOpenSeverity;
    }
}
