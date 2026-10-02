package com.asmolabs.vectispire.core.issues;

import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.RemediationSla;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.siem.SecurityEventRaised;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Tells the SOC when an issue passes its remediation deadline — {@code VECTI-SEC-030}, once per issue.
 *
 * <p><b>A crossing has no moment of its own.</b> Nothing happens to the row when its window closes:
 * the deadline is {@code first_seen_at} plus the severity's window ({@link RemediationSla}), computed
 * on every read. So the hourly turn asks which deadlines have passed and were not announced, announces
 * each, and marks it ({@code sla_breach_signalled_at}, V64) in the transaction that queues the event —
 * an event exists exactly when its mark does, and a turn that rolls back leaves both for the next.
 *
 * <p><b>Only the deadlines that passed within the last {@link #LOOKBACK}.</b> Without a lower bound
 * the first turn after the upgrade would announce every issue already late — thousands, on a mature
 * backlog, in a SOC that would learn the channel is noise — and so would a window shortened on the
 * settings screen. Seven days is longer than any outage the turn should outlive; a deadline missed
 * by more than that is a figure on the compliance report, not a fresh alarm.
 *
 * <p><b>Marked whether or not anything was sent.</b> With the export off, the SIEM export
 * queues nothing, and the issue is marked anyway: a breach is announced when it happens, to whoever
 * listens then, and switching the export on does not replay the past week — like every other event.
 *
 * <p><b>As severe as the issue.</b> Each event carries the late issue's severity as its CEF one
 * ({@code SecurityEventType.cefSeverityOf}), and the export's minimum is compared with that. At the
 * type's fixed 6 the factory minimum ({@code HIGH}) let no breach through, a critical issue's included.
 */
@Service
public class SlaBreachSignals {

    /** How far back a passed deadline is still announced. See the class note. */
    static final Duration LOOKBACK = Duration.ofDays(7);

    /** Issues per transaction: a turn that finds many holds no lock for long. */
    static final int BATCH = 200;

    private final SlaService sla;
    private final IssueRepository issues;
    private final ApplicationEventPublisher events;
    private final TransactionTemplate transactions;
    private final Clock clock;

    public SlaBreachSignals(
            SlaService sla, IssueRepository issues, ApplicationEventPublisher events, PlatformTransactionManager transactions, Clock clock) {
        this.sla = sla;
        this.issues = issues;
        this.events = events;
        this.transactions = new TransactionTemplate(transactions);
        this.clock = clock;
    }

    /** Announces the deadlines passed since the last turn, and answers how many. */
    public int signalCrossings() {
        Instant now = clock.instant();
        // Most severe first, so a turn interrupted part way has told the SOC what matters most.
        Map<Severity, Duration> windows = new TreeMap<>(sla.policy().windows());
        int signalled = 0;
        for (Map.Entry<Severity, Duration> window : windows.entrySet()) {
            signalled += signal(window.getKey(), window.getValue(), now);
        }
        return signalled;
    }

    private int signal(Severity severity, Duration window, Instant now) {
        Instant before = now.minus(window);
        Instant since = before.minus(LOOKBACK);
        int signalled = 0;
        long afterId = 0;
        while (true) {
            long from = afterId;
            List<Long> page = transactions.execute(status -> {
                List<IssueEntity> crossed = issues.findUnsignalledBreaches(IssueState.OPEN.wireName(),
                        severity.wireName(), before, since, TriageStatus.settledWireNames(), from, Limit.of(BATCH));
                for (IssueEntity issue : crossed) {
                    events.publishEvent(new SecurityEventRaised(
                            IssueSignals.slaBreach(issue, severity, window, issue.getFirstSeenAt().plus(window))));
                    issue.setSlaBreachSignalledAt(now);
                }
                issues.saveAll(crossed);
                return crossed.stream().map(IssueEntity::getId).toList();
            });
            signalled += page.size();
            if (page.size() < BATCH) {
                return signalled;
            }
            afterId = page.getLast();
        }
    }
}
