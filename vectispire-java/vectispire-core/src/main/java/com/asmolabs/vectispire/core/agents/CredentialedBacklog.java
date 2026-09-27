package com.asmolabs.vectispire.core.agents;

import com.asmolabs.vectispire.common.domain.agents.AgentLabels;
import com.asmolabs.vectispire.core.access.AgentView;
import com.asmolabs.vectispire.core.agents.internal.AgentViews;
import com.asmolabs.vectispire.core.agents.persistence.AgentRepository;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.ScanDispatcher;
import com.asmolabs.vectispire.core.scanning.WorkerProperties;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;

/**
 * The waiting scans that need a credential and that <b>no executor able to be handed one</b> can
 * take.
 *
 * <p><b>Why this is its own figure.</b> An agent that cannot be handed a delegated credential — in
 * {@code delegated} mode without a sealing key signed by its pinned key — no longer claims the scans
 * that need one (decision 0031): they wait, pending and costing nothing, for an executor that can run
 * them. When there is none, they wait for ever, and nothing on the control plane said so — the queue
 * gauge counts them among everything else, the 412 is in the agent's own log, on another machine.
 * This is the number that says it.
 *
 * <p><b>Precisely:</b> the waiting scans of repositories carrying an SSH key or an HTTPS token whose
 * routing label — or absence of one — no <em>capable</em> executor serves. Capable: an enabled agent
 * for which the dispatcher's own predicate holds ({@link ScanDispatcher#canBeHandedCredentials} — a
 * {@code local} agent, or a delegated one with a verified sealing key), and the built-in worker when it
 * is switched on and this control plane has a runner. An agent that is enabled but silent still
 * counts as capable: whether it is up is the agents screen's question, not this one's. A scan whose
 * label nobody serves at all is counted here too when it needs a credential — it is waiting for a
 * capable executor like the others — and {@code unroutable} counts it as well, by label.
 *
 * <p><b>Cheap on purpose</b>, since a gauge reads it at every scrape: the enabled agents, one grouped
 * count of the waiting scans, and — only for the rows no capable executor serves, which is none on a
 * healthy installation — which of their repositories carry a credential.
 */
@Service
public class CredentialedBacklog {

    private final AgentRepository agents;
    private final ScanCatalog scans;
    private final TargetCatalog targets;
    private final WorkerProperties worker;
    private final ScanDispatcher dispatcher;

    public CredentialedBacklog(
            AgentRepository agents,
            ScanCatalog scans,
            TargetCatalog targets,
            WorkerProperties worker,
            ScanDispatcher dispatcher) {
        this.agents = agents;
        this.scans = scans;
        this.targets = targets;
        this.worker = worker;
        this.dispatcher = dispatcher;
    }

    /**
     * @param scans how many wait
     * @param labels the labels they require, {@code ""} standing for none, sorted
     * @param keptAgents the enabled agents that would take them but cannot be handed a credential —
     *     the ones a pinned signing key and an update would bring back — sorted by name
     */
    public record Unserved(long scans, List<String> labels, List<String> keptAgents) {

        public static final Unserved NONE = new Unserved(0, List.of(), List.of());
    }

    public Unserved unserved() {
        List<AgentView> enabled = agents.findByEnabledTrue().stream().map(AgentViews::of).toList();
        List<AgentView> capable = enabled.stream().filter(ScanDispatcher::canBeHandedCredentials).toList();
        boolean workerRuns = worker.enabled() && dispatcher.runsScansHere();

        Set<String> servedLabels = new HashSet<>();
        capable.forEach(agent -> servedLabels.addAll(AgentLabels.parse(agent.labels())));
        if (workerRuns) {
            servedLabels.addAll(AgentLabels.parse(worker.labels()));
        }
        // A scan requiring no label goes to anybody, so any capable executor serves it; one requiring a
        // label goes only to an executor carrying it — the claim's own `is null or in :labels`.
        boolean anyCapable = workerRuns || !capable.isEmpty();

        List<ScanCatalog.WaitingScans> unserved = scans.waitingRepositories().stream()
                .filter(row -> !anyCapable || (row.requiredLabel() != null && !servedLabels.contains(row.requiredLabel())))
                .toList();
        if (unserved.isEmpty()) {
            return Unserved.NONE;
        }
        Set<Long> carrying = targets.carryingCredentials(
                unserved.stream().map(ScanCatalog.WaitingScans::repoId).collect(Collectors.toSet()));
        List<ScanCatalog.WaitingScans> needing = unserved.stream()
                .filter(row -> carrying.contains(row.repoId()))
                .toList();
        if (needing.isEmpty()) {
            return Unserved.NONE;
        }

        Set<String> labels = needing.stream()
                .map(row -> Objects.requireNonNullElse(row.requiredLabel(), ""))
                .collect(Collectors.toCollection(TreeSet::new));
        List<String> kept = enabled.stream()
                .filter(agent -> !ScanDispatcher.canBeHandedCredentials(agent))
                .filter(agent -> serves(AgentLabels.parse(agent.labels()), needing))
                .map(AgentView::name)
                .sorted()
                .toList();
        return new Unserved(
                needing.stream().mapToLong(ScanCatalog.WaitingScans::scans).sum(), List.copyOf(labels), kept);
    }

    private static boolean serves(Collection<String> agentLabels, List<ScanCatalog.WaitingScans> rows) {
        return rows.stream().anyMatch(row -> row.requiredLabel() == null || agentLabels.contains(row.requiredLabel()));
    }
}
