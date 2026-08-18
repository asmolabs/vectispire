package com.asmolabs.zanshin.common.domain.gate;

import com.asmolabs.zanshin.common.domain.issues.Severity;

/**
 * What a caller said about the severity threshold — including having said nothing.
 *
 * <p>Three states, and all three are distinct. "Absent" is not "null": a caller that omits the
 * field is accepting the stored policy, while one that sends {@code null} is asking to switch
 * the severity rule off. Collapsing them means every request that omits the field gets told
 * its relaxation was refused, on every call — the NestJS version needed a {@code 'key' in
 * object} check to avoid exactly that.
 *
 * <p>A sealed interface rather than a nullable field, so the switch that handles it has to
 * handle all three.
 */
public sealed interface SeverityRequest {

    /** The caller did not mention it. */
    record Unset() implements SeverityRequest {}

    /** The caller asked for no severity rule at all. */
    record Disabled() implements SeverityRequest {}

    /** The caller asked for this threshold. */
    record Threshold(Severity severity) implements SeverityRequest {}

    SeverityRequest UNSET = new Unset();
}
