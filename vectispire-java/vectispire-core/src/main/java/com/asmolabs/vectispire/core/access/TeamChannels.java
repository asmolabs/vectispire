package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.core.access.persistence.TeamTargetRepository;
import com.asmolabs.vectispire.core.access.persistence.TeamWebhookEntity;
import com.asmolabs.vectispire.core.access.persistence.TeamWebhookRepository;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * Which teams own a target, and where a team is told: what notification routing reads of the teams.
 *
 * <p><b>Here because both tables are this module's.</b> A team's grants and its channel are written by
 * {@link TeamAdministrationService}; {@code notifications} read them through the repositories while the
 * code was packaged by layer, a dependency on access nothing showed. Reads only, and no transaction of
 * their own: the scan-delta routing asks them inside the transaction that queues its messages, as it did.
 */
@Service
public class TeamChannels {

    private final TeamTargetRepository grants;
    private final TeamWebhookRepository webhooks;

    public TeamChannels(TeamTargetRepository grants, TeamWebhookRepository webhooks) {
        this.grants = grants;
        this.webhooks = webhooks;
    }

    /** The teams granted the target {@code kind}/{@code targetId} directly, in the order the grants are read. */
    public List<Long> teamsGranted(String kind, Long targetId) {
        return grants.findByTarget(kind, targetId).stream()
                .map(row -> row.getId().teamId())
                .toList();
    }

    /** Of {@code teamIds}, those that have a channel of their own. */
    public List<Long> withChannel(List<Long> teamIds) {
        return webhooks.findByTeamIdIn(teamIds).stream().map(TeamWebhookEntity::getTeamId).toList();
    }

    /** Whether any team has a channel of its own: notifications are on when one does. */
    public boolean anyTeamHasOne() {
        return webhooks.count() > 0;
    }

    /** The team's channel, as stored; empty when it has none. */
    public Optional<String> webhookUrl(Long teamId) {
        return webhooks.findById(teamId).map(TeamWebhookEntity::getUrl);
    }
}
