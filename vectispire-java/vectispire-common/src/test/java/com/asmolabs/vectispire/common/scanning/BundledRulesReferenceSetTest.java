package com.asmolabs.vectispire.common.scanning;

import com.asmolabs.vectispire.common.rust.ReferenceSet;
import org.junit.jupiter.api.Test;

/**
 * The rules the jar ships, byte for byte, for the Rust port to embed — `scanners::rules::BUNDLED`
 * includes these files, so the two agents scan with the same rules or a build fails.
 *
 * <p><b>The gitleaks configuration is the one that matters most</b>: without it the scanner falls back
 * to a configuration the scanned repository supplies. And a rule's id enters the fingerprint.
 */
class BundledRulesReferenceSetTest {

    @Test
    void theRulesTheRustPortEmbeds() {
        StringBuilder list = new StringBuilder();
        for (String file : BundledRules.expected()) {
            ReferenceSet.expect("sast/bundled-rules/" + file, BundledRules.contentOf(file));
            list.append(file).append('\n');
        }
        ReferenceSet.expect("sast/bundled-rules.list", list.toString());
    }
}
