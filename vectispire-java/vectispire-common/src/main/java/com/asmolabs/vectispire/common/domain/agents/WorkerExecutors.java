package com.asmolabs.vectispire.common.domain.agents;

import com.asmolabs.vectispire.common.domain.scans.FailureReason;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

/**
 * What a worker can run scans with, as it last said: each executor it has, whether that executor can run
 * anything right now, and which kinds of target it scans.
 *
 * <p><b>Why the claim asks.</b> A worker whose Docker daemon is down, or whose Kubernetes API refuses its
 * service account, used to claim scans all the same, and every step that needed the executor failed on the
 * scan — an attempt spent per claim, three claims and the scan failed for good, for a fault that was the
 * worker's and not the target's. A worker that says none of its executors can run a kind is not handed a scan
 * of that kind; the scan waits for one that can, and the agents screen says why it waits.
 *
 * <p><b>Absent is unknown, never "nothing available".</b> An agent older than this record announces nothing,
 * and it claims exactly as it did (decision 0043 §2: the control plane serves the previous minor's agent). An
 * agent that announced an empty list said it has no executor at all, which is a different statement and claims
 * nothing.
 *
 * @param executors in the order the worker gave them; never null
 */
public record WorkerExecutors(List<Executor> executors) {

    /** More than any worker has: a list past it is cut, not refused — see {@link #bounded}. */
    public static final int MAX_EXECUTORS = 8;

    /** The longest kind kept: "docker" and "kubernetes" fit many times over. */
    public static final int MAX_KIND_LENGTH = 20;

    /** The longest reason kept. It is shown on a screen, and an executor's error can be a stack's worth. */
    public static final int MAX_DETAIL_LENGTH = 500;

    private static final ObjectMapper JSON = new ObjectMapper()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

    public WorkerExecutors {
        executors = executors == null ? List.of() : executors.stream().filter(Objects::nonNull).toList();
    }

    /** The kinds of target a scan examines, by the names the wire and the screens use. */
    public enum Target {
        /** A Git repository, cloned. */
        REPOSITORY,

        /**
         * A container image, exported from its registry. The Kubernetes executor does not scan these yet: the
         * copy step of decision 0045 §8 is not built.
         */
        CONTAINER;

        private final String wireName = name().toLowerCase(Locale.ROOT);

        public String wireName() {
            return wireName;
        }

        public static Optional<Target> byWireName(String value) {
            return Stream.of(values()).filter(target -> target.wireName.equals(value)).findFirst();
        }
    }

    /**
     * One executor.
     *
     * @param kind {@code docker} or {@code kubernetes} today; any other name is kept and shown, since a later
     *     agent may have one this control plane has never heard of — what it runs is {@code targets}, not the name
     * @param available whether it could run a scanner when the worker last asked it
     * @param targets the kinds of target it scans, by wire name; a name this version does not know is ignored
     * @param detail why it is unavailable, in the executor's words; null when it is available
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Executor(String kind, boolean available, List<String> targets, String detail) {

        public Executor {
            targets = targets == null ? List.of() : targets.stream().filter(Objects::nonNull).toList();
        }

        /** The targets this version knows, in their order. */
        public Set<Target> knownTargets() {
            Set<Target> known = new LinkedHashSet<>();
            targets.forEach(name -> Target.byWireName(name).ifPresent(known::add));
            return known;
        }
    }

    /**
     * What the worker may be handed: the targets of the executors that are available now.
     *
     * <p>Empty when none is — or when the worker has none — and the claim then takes nothing.
     */
    public Set<Target> claimable() {
        Set<Target> claimable = EnumSet.noneOf(Target.class);
        executors.stream().filter(Executor::available).forEach(executor -> claimable.addAll(executor.knownTargets()));
        return claimable;
    }

    /**
     * The targets a worker may be handed when it may have said nothing: {@link #claimable} when it did, every
     * kind when it did not — the claim of an agent older than this record.
     */
    public static Set<Target> claimable(WorkerExecutors announced) {
        return announced == null ? EnumSet.allOf(Target.class) : announced.claimable();
    }

    /**
     * Clipped to the bounds, never refused, as every other field an agent says about itself is: a refusal
     * would drop the announcement, and the agent would claim as an unknown — the opposite of what it said.
     *
     * <p><b>The detail is scrubbed as a failure's reason is</b> ({@link FailureReason#scrub}), here and so on
     * each side that bounds it — the agent before it sends, the control plane on arrival, the built-in worker:
     * it is an executor's own error text, shown on a screen, and an API server's message can quote a URL with
     * its credentials. Blank becomes none.
     */
    public WorkerExecutors bounded() {
        List<Executor> kept = new ArrayList<>();
        for (Executor executor : executors.subList(0, Math.min(executors.size(), MAX_EXECUTORS))) {
            String kind = executor.kind() == null ? "" : executor.kind().strip();
            String detail = executor.detail() == null ? "" : FailureReason.scrub(executor.detail());
            kept.add(new Executor(
                    clip(kind, MAX_KIND_LENGTH),
                    executor.available(),
                    executor.knownTargets().stream().map(Target::wireName).toList(),
                    detail.isEmpty() ? null : clip(detail, MAX_DETAIL_LENGTH)));
        }
        return new WorkerExecutors(kept);
    }

    /** The stored form: the JSON the wire carries, so the column reads as what the agent said. */
    public String write() {
        try {
            return JSON.writeValueAsString(executors);
        } catch (JsonProcessingException impossible) {
            throw new IllegalStateException("A list of records did not serialize.", impossible);
        }
    }

    /**
     * The stored form read back, or empty when there is none.
     *
     * <p>Unreadable reads as none too, and the worker then claims as before: only the control plane writes the
     * column, from a list it has already read, so an unreadable value is a row edited by hand — and keeping a
     * worker from every scan over it would be the worse failure.
     */
    public static Optional<WorkerExecutors> read(String stored) {
        if (stored == null || stored.isBlank()) {
            return Optional.empty();
        }
        try {
            List<Executor> parsed = JSON.readValue(stored, new TypeReference<List<Executor>>() {});
            return Optional.of(new WorkerExecutors(parsed));
        } catch (JsonProcessingException | IllegalArgumentException unreadable) {
            return Optional.empty();
        }
    }

    private static String clip(String text, int max) {
        return text.length() <= max ? text : text.substring(0, max);
    }
}
