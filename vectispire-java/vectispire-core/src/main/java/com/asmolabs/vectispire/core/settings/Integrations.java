package com.asmolabs.vectispire.core.settings;

import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException;
import com.asmolabs.vectispire.core.settings.persistence.IntegrationEntity;
import com.asmolabs.vectispire.core.settings.persistence.IntegrationRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
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
 */
@Service
public class Integrations {

    private final IntegrationRepository rows;
    private final Clock clock;

    public Integrations(IntegrationRepository rows, Clock clock) {
        this.rows = rows;
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
     * Switches an integration on or off, attributing the change; the same state again changes nothing and
     * writes nothing — the caller records an audit entry only for a change.
     *
     * <p>A key with no row — an integration that arrived after V83 — gets one when it is enabled. Two first
     * enablings of such a key at once would both insert and the second fail on the key; that is a gesture
     * made at human speed, once per adapter's lifetime, and the error is the honest answer.
     */
    @Transactional
    public Switched switchTo(Integration integration, boolean enabled, String by) {
        Instant now = clock.instant();
        boolean changed;
        if (rows.existsById(integration.key())) {
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
