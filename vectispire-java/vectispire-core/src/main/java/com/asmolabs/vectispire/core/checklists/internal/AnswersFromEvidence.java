package com.asmolabs.vectispire.core.checklists.internal;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.outbox.OutboxService;
import com.asmolabs.vectispire.core.plugins.RepositoryReported;
import com.asmolabs.vectispire.core.scanning.RepositoryScanned;
import com.asmolabs.vectispire.core.settings.SettingsService;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * The checklists' side of the two ports below them: a completed scan ({@code scanning}) and an accepted
 * report ({@code plugins}) are new evidence about a repository, and the draft checklist of its project is
 * answered again from it (decision 0032, amendment "the scans answer the lines they measure").
 *
 * <p><b>It only queues</b> (decision 0033). Both ports are called inside the scan's or the import's
 * transaction, and what is written there is an outbox message, {@value ChecklistAnswerDelivery#TYPE}: it
 * commits with the evidence or not at all, and {@link ChecklistAnswerDelivery} answers from it later,
 * with the relay's retry, backoff and abandonment. The answer used to be given here, after the owners'
 * commit, and a stop in between lost it until the next scan.
 *
 * <p>A port each module declares rather than an event: the two owners sit below {@code checklists} and
 * may not name it.
 */
@Component
public class AnswersFromEvidence implements RepositoryScanned, RepositoryReported {

    private final OutboxService outbox;
    private final SettingsService settings;

    public AnswersFromEvidence(OutboxService outbox, SettingsService settings) {
        this.outbox = outbox;
        this.settings = settings;
    }

    @Override
    public void scanned(long repositoryId) {
        queue(repositoryId);
    }

    @Override
    public void reported(long repositoryId) {
        queue(repositoryId);
    }

    /**
     * Nothing is queued when the automatic answers are off: a row whose delivery would do nothing is a row
     * an operator learns to ignore. The delivery reads the setting again, since it may change in between.
     */
    private void queue(long repositoryId) {
        if (settings.isEnabled(Setting.CHECKLIST_AUTO_ANSWER)) {
            outbox.enqueue(Map.of("repository_id", repositoryId), ChecklistAnswerDelivery.TYPE);
        }
    }
}
