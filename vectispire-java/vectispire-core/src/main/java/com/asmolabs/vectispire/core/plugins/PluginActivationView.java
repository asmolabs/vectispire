package com.asmolabs.vectispire.core.plugins;

import com.asmolabs.vectispire.core.plugins.persistence.PluginActivationEntity;
import com.asmolabs.vectispire.core.targets.SolutionAdministrationService.ProjectLabel;
import java.time.Instant;

/**
 * A plugin switched on for a project, under the entity's property names, and the project as a screen
 * names it — the screen loaded the whole solution tree for the names before.
 *
 * <p>Every reader of an activation sees the whole estate ({@code @RequiresGovernanceRead}, {@code
 * @RequiresSecurityLead}), so a project's names are never more than the reader could already list.
 *
 * @param projectName and {@code solutionId}, {@code solutionName}: null when the project row could not
 *     be read — its deletion takes its activations with it, so only a race answers null, never an
 *     invented name
 */
public record PluginActivationView(
        Long id,
        String pluginId,
        Long projectId,
        String projectName,
        Long solutionId,
        String solutionName,
        Instant activatedAt,
        String activatedBy) {

    static PluginActivationView of(PluginActivationEntity activation, ProjectLabel project) {
        return new PluginActivationView(activation.getId(), activation.getPluginId(), activation.getProjectId(),
                project == null ? null : project.name(), project == null ? null : project.solutionId(),
                project == null ? null : project.solutionName(), activation.getActivatedAt(), activation.getActivatedBy());
    }
}
