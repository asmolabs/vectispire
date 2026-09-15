package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.compliance.ComplianceHistory;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.RequiresGovernanceRead;
import com.asmolabs.vectispire.core.services.ComplianceHistoryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * How each framework's verdict moved, month by month.
 *
 * <h2>The question this answers, and the one it refuses to</h2>
 *
 * <p>ISO 27001 clause 9.3 asks a management review to look at the ISMS over time; a point-in-time
 * score answers nothing about that. This is the piece the rest of the evidence was missing — the
 * gate's monthly continuity, the exception reviews and the remediation tail all describe a
 * process running, and none of them says whether it is getting better.
 *
 * <p><b>What it refuses is a single number that goes up.</b> Six frameworks, six series, with the
 * declaration's findings beside them. An aggregate "overall compliance" score gets managed: it
 * improves by adding an easy framework, and a figure that can be improved without touching the
 * estate is a figure somebody eventually improves that way.
 *
 * <h2>Read the attribution before the line</h2>
 *
 * <p>Each month says why it is where it is. The score falls when a repository is registered and
 * when a detector is switched on — in both cases because the estate is being watched more widely,
 * and a chart that reports those as regression teaches a team to watch less. A series whose estate
 * kept changing is reported as <em>not comparable</em> rather than drawn as a trend.
 *
 * <p>Gated on governance read, like the rest of the evidence: a capture describes the whole estate
 * as the deployment saw it, and narrowing it per reader would give each of them a different past.
 */
@Tag(name = "Compliance history", description = "Each framework's verdict over time, with what moved it")
@RestController
@RequestMapping("/api/v1/compliance/history")
@RequiresAccount
public class ComplianceHistoryController {

    private final ComplianceHistoryService history;

    public ComplianceHistoryController(ComplianceHistoryService history) {
        this.history = history;
    }

    @Operation(summary = "Compliance progression", description = "Every framework's monthly captures, each attributed to what plausibly moved it.")
    @ApiResponse(responseCode = "200", description = "Series returned")
    @GetMapping
    @RequiresGovernanceRead
    public List<ComplianceHistory.Series> history() {
        return history.history();
    }
}
