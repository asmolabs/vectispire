package com.asmolabs.vectispire.common.domain.reportplugins;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;

/**
 * Why a report plugin's output is not what its manifest declares — thrown inside {@link ReportOutputCheck} and
 * caught there, never past it: the check answers a {@link ReportOutputCheck.Verdict}. An {@link
 * InvalidInputException} only because {@code SafeXml} builds its refusals as one.
 */
final class OutputRefused extends InvalidInputException {

    OutputRefused(String why) {
        super(why);
    }
}
