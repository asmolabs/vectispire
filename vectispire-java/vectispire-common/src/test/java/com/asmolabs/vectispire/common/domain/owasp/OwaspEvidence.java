package com.asmolabs.vectispire.common.domain.owasp;

import com.asmolabs.vectispire.common.domain.gate.Observation;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Evidence;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Measurement;
import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** The evidence the grid's cases are read over, spelled once for the three test classes. */
final class OwaspEvidence {

    /** What a repository's completed scan with every built-in step produces. */
    static final Set<FindingType> EVERY_STEP = EnumSet.of(
            FindingType.VULNERABILITY, FindingType.EOL, FindingType.LICENSE, FindingType.SECRET,
            FindingType.IAC, FindingType.SAST, FindingType.QUALITY);

    private OwaspEvidence() {}

    /** A Java repository whose latest scan examined everything, its rules reaching these categories. */
    static Evidence examinedRepository(long id, String... codeReaches) {
        return new Evidence(new ScanTarget.Repository(id), Observation.OK, Optional.of(EVERY_STEP),
                Optional.of(Set.of(Language.JAVA)), Optional.of(Set.of(codeReaches)));
    }

    static Evidence repository(long id, Set<FindingType> examined, String... codeReaches) {
        return new Evidence(new ScanTarget.Repository(id), Observation.OK, Optional.of(examined),
                Optional.of(Set.of(Language.JAVA)), Optional.of(Set.of(codeReaches)));
    }

    /** An image whose scan read its dependencies, as every image scan does. */
    static Evidence examinedImage(long id) {
        return new Evidence(new ScanTarget.Container(id), Observation.OK,
                Optional.of(EnumSet.of(FindingType.VULNERABILITY, FindingType.EOL, FindingType.LICENSE)),
                Optional.empty(), Optional.empty());
    }

    static Evidence failedRepository(long id) {
        return new Evidence(new ScanTarget.Repository(id), Observation.LAST_SCAN_FAILED, Optional.empty(),
                Optional.empty(), Optional.empty());
    }

    /** Every setting on, nothing declared by rules, over one repository examined for everything. */
    static Measurement measured(Map<FindingType, Long> open) {
        return new Measurement(true, true, open, Set.of(), Map.of(), List.of(examinedRepository(1)));
    }

    static Measurement over(List<Evidence> targets, Map<FindingType, Long> open, Set<String> declared,
            Map<String, Long> byCategory) {
        return new Measurement(true, true, open, declared, byCategory, targets);
    }
}
