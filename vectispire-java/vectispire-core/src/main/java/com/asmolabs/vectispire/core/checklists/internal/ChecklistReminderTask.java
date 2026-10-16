package com.asmolabs.vectispire.core.checklists.internal;

import com.asmolabs.vectispire.core.checklists.ChecklistReminderService;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The weekly checklist reminder, offered every hour (decision 0044) — the only caller of {@link
 * ChecklistReminderService#runOnce}, without which the contacts a project links are a list nobody is ever
 * written to.
 *
 * <p>Hourly for a weekly message, like the posture report: the service decides for itself, per recipient,
 * whether this week's has gone out.
 */
@Component
@Order(MaintenanceTask.Sequence.CHECKLIST_REMINDERS)
public class ChecklistReminderTask implements MaintenanceTask {

    private final ChecklistReminderService reminders;

    public ChecklistReminderTask(ChecklistReminderService reminders) {
        this.reminders = reminders;
    }

    @Override
    public Cadence cadence() {
        return Cadence.HOURLY;
    }

    @Override
    public void run() {
        reminders.runOnce();
    }
}
