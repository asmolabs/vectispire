package com.asmolabs.vectispire.core.compliance.internal;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.outbox.OutboxService;
import com.asmolabs.vectispire.core.scanning.RepositoryScanned;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * {@code compliance}'s side of {@code scanning}'s port: a repository's completed scan asks for its OWASP
 * report, when an operator turned {@link Setting#AI_REVIEW_OWASP_AFTER_SCAN} on.
 *
 * <p><b>It only queues</b>, like the checklists' answers beside it (decision 0033). The port is called in
 * the scan's transaction, and what is written there is an outbox message, {@value OwaspReportDelivery#TYPE}:
 * it commits with the scan or not at all, so a report is never asked for a scan a rollback undid, and a
 * stop between the commit and the hand-over loses nothing. The model is called much later, by {@link
 * OwaspReportsAfterScans}, on a thread of its own — never here, where minutes of a model would hold the
 * scan's transaction and every lock it took.
 *
 * <p>Nothing is queued while either switch is off: a message whose delivery would do nothing is a row an
 * operator learns to ignore. Both are read again before the model is asked, since they may change between.
 */
@Component
public class OwaspReportOnScan implements RepositoryScanned {

    private final OutboxService outbox;
    private final SettingsService settings;

    public OwaspReportOnScan(OutboxService outbox, SettingsService settings) {
        this.outbox = outbox;
        this.settings = settings;
    }

    @Override
    public void scanned(long repositoryId, long scanId) {
        if (OwaspReportsAfterScans.switchedOn(settings)) {
            outbox.enqueue(Map.of("repository_id", repositoryId, "scan_id", scanId), OwaspReportDelivery.TYPE);
        }
    }
}
