package com.asmolabs.vectispire.common.domain.gate;

import java.util.List;
import java.util.Optional;

/**
 * Which policy applies to a target, and <b>where it comes from</b>.
 *
 * <p>The provenance is part of the answer, not debugging information. A pipeline whose build
 * fails needs to know whether these are its own rules, its target's, or the organization's
 * default — otherwise the first reflex is to loosen its own settings, which then changes
 * nothing and costs an afternoon.
 */
public final class PolicyResolution {

    private PolicyResolution() {}

    /** Where a policy came from. */
    public enum Source {
        /** The target's own policy. */
        TARGET("the target's"),
        /** The organization-wide policy. */
        GLOBAL("the global"),
        /** Nothing was stored; {@link GatePolicy#BUILT_IN} applied. */
        BUILT_IN(null);

        private final String scopeLabel;

        Source(String scopeLabel) {
            this.scopeLabel = scopeLabel;
        }
    }

    /**
     * A stored policy and the version it was saved under.
     *
     * <p>The version is carried beside the policy rather than inside it: it identifies the row,
     * not the rules, and a {@link GatePolicy} that held one could not be compared to another by
     * value — which is how {@code harden} decides whether anything actually changed.
     */
    public record StoredPolicy(GatePolicy policy, int version) {}

    /**
     * @param version the stored policy's version, empty when the built-in one applied
     * @param ignoredRelaxations the fields the request asked to loosen and did not get
     */
    public record ResolvedPolicy(
            GatePolicy policy, Source source, Optional<Integer> version, List<String> ignoredRelaxations) {

        public ResolvedPolicy {
            ignoredRelaxations = List.copyOf(ignoredRelaxations);
        }

        /** What a pipeline reads when its verdict surprises it. */
        public String describeSource() {
            return source == Source.BUILT_IN
                    ? "the application's default policy"
                    : source.scopeLabel + " policy v" + version.map(String::valueOf).orElse("?");
        }
    }

    /**
     * What is on file, before a request is weighed against it.
     *
     * @param forTarget the target's active policy, if it has one
     * @param global the active organization-wide policy, if there is one
     */
    public record PolicyLookup(Optional<StoredPolicy> forTarget, Optional<StoredPolicy> global) {

        public static PolicyLookup of(StoredPolicy forTarget, StoredPolicy global) {
            return new PolicyLookup(Optional.ofNullable(forTarget), Optional.ofNullable(global));
        }
    }

    /** Which policies a resolution is allowed to consider. */
    public enum Scope {
        /**
         * A question about one target: its own policy first, the global one next.
         *
         * <p><b>A target's policy replaces the global one entirely</b>, it does not merge with
         * it. A half-inherited policy is impossible to reason about when a build fails, and
         * "this repository's rules" has to be readable in one place.
         */
        TARGET,

        /** A question about the organization: the global policy, and nothing else. */
        GLOBAL
    }

    /**
     * Resolves the applicable policy, then lets the caller's request tighten it.
     *
     * <p>{@code requested} can only <b>tighten</b>: without that, any pipeline would turn
     * whatever it liked green from its own request body. Refused relaxations come back in the
     * result rather than being dropped silently — a pipeline that believes it has switched a
     * rule off needs to find out that it has not.
     */
    public static ResolvedPolicy resolve(PolicyLookup lookup, RequestedPolicy requested, Scope scope) {
        Optional<StoredPolicy> stored = Optional.empty();
        Source source = Source.GLOBAL;

        if (scope == Scope.TARGET && lookup.forTarget().isPresent()) {
            stored = lookup.forTarget();
            source = Source.TARGET;
        } else if (lookup.global().isPresent()) {
            stored = lookup.global();
        }

        GatePolicy base = stored.map(StoredPolicy::policy).orElse(GatePolicy.BUILT_IN);
        Optional<Integer> version = stored.map(StoredPolicy::version);
        if (stored.isEmpty()) {
            source = Source.BUILT_IN;
        }

        PolicyGate.Hardened hardened = PolicyGate.harden(base, requested);
        return new ResolvedPolicy(hardened.policy(), source, version, hardened.ignoredRelaxations());
    }
}
