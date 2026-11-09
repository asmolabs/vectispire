package com.asmolabs.vectispire.common.domain.siem;

/**
 * A security event a module raises <b>inside its own transaction</b>, for the SIEM export to queue in
 * that transaction (decision 0033, lot 5).
 *
 * <p>Published as an application event rather than handed to the export by a call, so that the module
 * raising it does not depend on the export: {@code issues}, {@code gate} and {@code threatintel} each
 * listed the SIEM among their dependencies for one call, and naming it here, beside {@link CefEvent}
 * they already build, takes that line out of their {@code allowedDependencies}. The listener is
 * synchronous and joins the publisher's transaction — {@code MANDATORY}, as the call was — so the event
 * still commits with what it describes, or not at all.
 *
 * <p>For a caller whose own work has already committed, the event is {@link SecurityEventRaisedApart}.
 */
public record SecurityEventRaised(CefEvent event) {}
