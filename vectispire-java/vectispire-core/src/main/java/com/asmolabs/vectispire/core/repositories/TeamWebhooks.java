package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.TeamWebhookEntity;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/** Where each team wants to be told. */
public interface TeamWebhooks extends JpaRepository<TeamWebhookEntity, Long> {

    /**
     * The teams among these that have a channel.
     *
     * <p>One query for the set: a scan's target belongs to few teams, but asking per team would
     * put a round trip inside the loop that queues a notification — inside the transaction that
     * commits a scan's results.
     */
    @Query("select w from TeamWebhookEntity w where w.teamId in :teamIds")
    List<TeamWebhookEntity> findByTeamIdIn(@Param("teamIds") List<Long> teamIds);
}
