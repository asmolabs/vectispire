package com.asmolabs.vectispire.core.settings;

import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException;
import com.asmolabs.vectispire.common.domain.integrations.IntegrationInUseException;
import com.asmolabs.vectispire.core.settings.persistence.IntegrationEntity;
import com.asmolabs.vectispire.core.settings.persistence.IntegrationRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * The integrations' registry (decision 0040): which outside systems this installation may talk to, and
 * the refusal every adapter's entry calls before it does.
 *
 * <p><b>In {@code settings}, the foundation</b>, because every module owning an adapter — {@code forges},
 * {@code siem}, {@code ai}, {@code notifications}, {@code tickets} — has to ask it, and a domain module
 * there would be one more line in five lists and an edge against the direction some of them point. It
 * uses nothing but its own table, as this module must: every module reads its settings. The governor's
 * gesture — the audit entry, the SIEM signal — is {@code platform}'s, which may use {@code audit}.
 *
 * <p><b>A key without a row is disabled.</b> V83 seeded every integration that existed when the registry
 * was introduced, enabled; one added to an adapter's enum later has no row and reads off until a governor
 * enables it, so an upgrade never widens what an installation reaches (0040 §5). A row whose key no
 * integration has any more is ignored, as {@code t_setting} ignores a retired setting.
 *
 * <p><b>What is in use is not switched off</b> (0040 §3). The registry asks every {@link InUse} the
 * modules above it contribute — the SIEM export for its transport — and refuses with {@link
 * IntegrationInUseException}; the question is asked here, in the switch's own transaction, rather than by
 * the governor's route before it, so that no caller of {@link #switchTo} can go round it and no
 * configuration can start using the integration between the answer and the switch (see {@link
 * #holdEnabled}).
 */
@Service
public class Integrations {

    /**
     * Port: a module whose configuration may be using an integration answers whether it is, and the registry
     * refuses to switch it off while it is (0040 §3). Declared here and implemented by the module that owns
     * the configuration, because the owners sit above the foundation: the registry may use none of them.
     *
     * <p>Called inside the switch's transaction once the integration's row is locked. A configuration that
     * starts using an integration takes that same row through {@link #holdEnabled}, so the answer read here
     * is still true when the switch commits.
     */
    public interface InUse {

        /**
         * @return what uses the integration and what to change first, as the sentence the refusal ends with;
         *     empty when nothing of this module's uses it
         */
        Optional<String> use(Integration integration);
    }

    private final IntegrationRepository rows;
    private final List<InUse> uses;
    private final Clock clock;

    public Integrations(IntegrationRepository rows, List<InUse> uses, Clock clock) {
        this.rows = rows;
        this.uses = List.copyOf(uses);
        this.clock = clock;
    }

    /** What a switch did: the integration as it now stands, and whether this call changed it. */
    public record Switched(IntegrationView integration, boolean changed) {}

    /** Every integration this version knows, in {@link Integration#all()}'s order, with its state. */
    @Transactional(readOnly = true)
    public List<IntegrationView> list() {
        Map<String, IntegrationEntity> stored =
                rows.findAll().stream().collect(Collectors.toMap(IntegrationEntity::getKey, Function.identity()));
        return Integration.all().stream().map(integration -> view(integration, stored.get(integration.key()))).toList();
    }

    @Transactional(readOnly = true)
    public boolean isEnabled(Integration integration) {
        return rows.findById(integration.key()).map(row -> Boolean.TRUE.equals(row.getEnabled())).orElse(false);
    }

    /**
     * What an adapter's entry calls before it does anything — offers a form, opens a connection, sends.
     *
     * @throws IntegrationDisabledException when the integration is off: 409 {@code integration-disabled},
     *     naming it
     */
    @Transactional(readOnly = true)
    public void requireEnabled(Integration integration) {
        if (!isEnabled(integration)) {
            throw new IntegrationDisabledException(integration);
        }
    }

    /**
     * What a configuration calls, in the transaction that writes it, before it starts using an integration:
     * refused when the integration is off, and otherwise held on until that transaction ends.
     *
     * <p><b>Held, because checking is not enough.</b> A save that read "enabled" and a governor's switch
     * that read "not in use" could both commit — the save before the switch's question, the switch before
     * the save — and leave the configuration on a transport that is off. The row is read {@code for
     * share}: the switch, which takes it {@code for update} before it asks {@link InUse}, waits for the
     * save to commit and then sees it; a save that comes second waits for the switch and then reads "off".
     *
     * @throws IntegrationDisabledException when the integration is off
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public void holdEnabled(Integration integration) {
        boolean enabled = rows.lockForUse(integration.key()).map(row -> Boolean.TRUE.equals(row.getEnabled()))
                .orElse(false);
        if (!enabled) {
            throw new IntegrationDisabledException(integration);
        }
    }

    /**
     * Switches an integration on or off, attributing the change; the same state again changes nothing and
     * writes nothing — the caller records an audit entry only for a change.
     *
     * <p>Switching off an integration a module reports in use is refused, and changes nothing. The row is
     * locked before the question is asked, and the lock is the transaction's first statement: on MySQL's
     * repeatable read the snapshot the owners' reads see is taken after it, so a configuration that
     * committed while this switch waited for the row is read, not the state from before.
     *
     * <p>A key with no row — an integration that arrived after V83 — gets one when it is enabled. Two first
     * enablings of such a key at once would both insert and the second fail on the key; that is a gesture
     * made at human speed, once per adapter's lifetime, and the error is the honest answer.
     *
     * @throws IntegrationInUseException when switching off what a configuration uses
     */
    @Transactional
    public Switched switchTo(Integration integration, boolean enabled, String by) {
        Instant now = clock.instant();
        boolean changed;
        Optional<IntegrationEntity> locked = rows.lockForSwitch(integration.key());
        if (locked.isPresent()) {
            if (!enabled && Boolean.TRUE.equals(locked.get().getEnabled())) {
                refuseIfInUse(integration);
            }
            changed = rows.switchTo(integration.key(), enabled, now, by) == 1;
        } else if (enabled) {
            IntegrationEntity row = new IntegrationEntity();
            row.setKey(integration.key());
            row.setEnabled(true);
            row.setUpdatedAt(now);
            row.setUpdatedBy(by);
            rows.saveAndFlush(row);
            changed = true;
        } else {
            // Absent reads disabled: switching it off is the same state again, and writes nothing.
            return new Switched(view(integration, null), false);
        }
        return new Switched(view(integration, rows.findById(integration.key()).orElseThrow()), changed);
    }

    private void refuseIfInUse(Integration integration) {
        for (InUse owner : uses) {
            Optional<String> use = owner.use(integration);
            if (use.isPresent()) {
                throw new IntegrationInUseException(integration, use.get());
            }
        }
    }

    private static IntegrationView view(Integration integration, IntegrationEntity row) {
        return new IntegrationView(
                integration.key(),
                integration.family().wireName(),
                integration.name(),
                row != null && Boolean.TRUE.equals(row.getEnabled()),
                row == null ? null : row.getUpdatedAt(),
                row == null ? null : row.getUpdatedBy());
    }
}
