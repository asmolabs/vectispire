package com.asmolabs.zanshin.common.domain.trends;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the Posture and MTTR Trend Analytics domain engine")
class PostureTrendAnalyticsTest {

    @Test
    @DisplayName("calculates multi-echelon MTTR and target scoreboard correctly")
    void calculatesAnalytics() {
        Instant now = Instant.now();
        Instant seen3dAgo = now.minus(Duration.ofDays(3));
        Instant seen10dAgo = now.minus(Duration.ofDays(10));
        Instant resolved2dAgo = now.minus(Duration.ofDays(2));
        Instant resolved5dAgo = now.minus(Duration.ofDays(5));

        List<PostureTrendAnalytics.IssueObservation> observations = List.of(
                // Target 1: Clean resolved quickly
                new PostureTrendAnalytics.IssueObservation(1L, "REPOSITORY", "repo-alpha", "CRITICAL", seen3dAgo, resolved2dAgo), // 1 day
                new PostureTrendAnalytics.IssueObservation(1L, "REPOSITORY", "repo-alpha", "HIGH", seen10dAgo, resolved5dAgo), // 5 days
                // Target 2: Has open criticals
                new PostureTrendAnalytics.IssueObservation(2L, "REPOSITORY", "repo-beta", "CRITICAL", seen3dAgo, null),
                new PostureTrendAnalytics.IssueObservation(2L, "REPOSITORY", "repo-beta", "MEDIUM", seen10dAgo, null));

        PostureTrendAnalytics analytics = PostureTrendAnalytics.calculate(30, now, observations);

        assertThat(analytics.windowDays()).isEqualTo(30);
        assertThat(analytics.totalResolvedInWindow()).isEqualTo(2);
        assertThat(analytics.overallMttrDays()).isEqualTo(3.0); // (1 + 5) / 2
        assertThat(analytics.mttrBySeverity()).containsKey("CRITICAL");
        assertThat(analytics.mttrBySeverity().get("CRITICAL")).isEqualTo(1.0);
        assertThat(analytics.mttrBySeverity().get("HIGH")).isEqualTo(5.0);

        assertThat(analytics.targetScoreboard()).hasSize(2);
        PostureTrendAnalytics.TargetMaturityScore topTarget = analytics.targetScoreboard().get(0);
        assertThat(topTarget.targetName()).isEqualTo("repo-alpha");
        assertThat(topTarget.securityScore()).isEqualTo(100);
        assertThat(topTarget.maturityGrade()).isEqualTo("A");

        PostureTrendAnalytics.TargetMaturityScore lowerTarget = analytics.targetScoreboard().get(1);
        assertThat(lowerTarget.targetName()).isEqualTo("repo-beta");
        assertThat(lowerTarget.openCritical()).isEqualTo(1);
        assertThat(lowerTarget.securityScore()).isLessThan(100);
    }
}
