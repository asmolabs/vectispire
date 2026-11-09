package com.asmolabs.vectispire.core.plugins;

import java.util.List;

/** A repository's newest test report, with its suites — what a suite rule reads (decision 0032 §6). */
public record LatestTestReport(TestReportImportView report, List<TestSuiteResultView> suites) {

    public LatestTestReport {
        suites = List.copyOf(suites);
    }
}
