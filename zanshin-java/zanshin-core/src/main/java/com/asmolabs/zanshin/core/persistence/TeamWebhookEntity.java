package com.asmolabs.zanshin.core.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * One team's notification channel.
 *
 * <p><b>Its own table rather than a column on {@code t_team}</b>, for the two reasons the
 * changeset gives: adding a column to {@code t_team} destroys the foreign keys of the access
 * tables on SQLite, and a webhook URL is a bearer capability that has no business being carried
 * by every query over teams.
 *
 * <p>The team's identifier is the key: a team has one channel, and a second row for the same team
 * would be a second destination nobody chose.
 */
@Entity
@Table(name = "t_team_webhook")
public class TeamWebhookEntity {

    @Id
    @Column(name = "team_id", nullable = false)
    private Long teamId;

    @Column(name = "url", length = 500, nullable = false)
    private String url;

    public TeamWebhookEntity() {}

    public TeamWebhookEntity(Long teamId, String url) {
        this.teamId = teamId;
        this.url = url;
    }

    public Long getTeamId() {
        return teamId;
    }

    public void setTeamId(Long teamId) {
        this.teamId = teamId;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
