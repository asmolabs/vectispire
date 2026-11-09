package com.asmolabs.vectispire.common.domain.gate;

import java.util.EnumMap;
import java.util.Map;

/**
 * What a caller actually sent.
 *
 * <p><b>The presence of a field matters, not its value.</b> A flag absent from the map was not
 * mentioned; one present was. Without the distinction, every caller omitting a field would look
 * like it was requesting the schema default and would be told its request was refused, on every
 * call.
 */
public record RequestedPolicy(SeverityRequest failOnSeverity, Map<PolicyFlag, Boolean> flags) {

    public RequestedPolicy {
        flags = flags.isEmpty() ? Map.of() : Map.copyOf(flags);
    }

    /** A request that asks for nothing: the stored policy applies unchanged. */
    public static RequestedPolicy none() {
        return new RequestedPolicy(SeverityRequest.UNSET, Map.of());
    }

    public RequestedPolicy with(PolicyFlag flag, boolean value) {
        Map<PolicyFlag, Boolean> updated = new EnumMap<>(PolicyFlag.class);
        updated.putAll(flags);
        updated.put(flag, value);
        return new RequestedPolicy(failOnSeverity, updated);
    }

    public RequestedPolicy with(SeverityRequest severity) {
        return new RequestedPolicy(severity, flags);
    }
}
