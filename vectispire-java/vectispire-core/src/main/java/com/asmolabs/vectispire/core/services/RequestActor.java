package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;

/**
 * Who did something, and from where, as an audit entry records it.
 *
 * <p><b>One type, where there were nine.</b> Each service lifted out of a controller declared
 * its own copy — an {@code Actor} here, an {@code Origin} there, one calling the name {@code
 * name} and the others {@code username} — and nine near-identical records are nine places for
 * the audit trail to start disagreeing about what "who" means.
 *
 * <p>Identity only. {@code IssueDecisionService.Caller} also carries what the caller may see, and
 * {@code GateService.Caller} an address resolved against the trusted proxies rather than the
 * servlet's: each is a different thing and keeps its own type.
 *
 * @param username the name the entry is attributed to, already resolved by the route — each
 *     route keeps the fallback it has always written ({@code null}, {@code "unknown"}, {@code
 *     "system"}), because changing it would rewrite how past and future entries compare. Null as
 *     well when the service names the actor itself from what it authenticated: an agent, a
 *     directory, a tracker
 * @param ipAddress the client address the servlet container resolved
 * @param userAgent the {@code User-Agent} header as sent, or null
 */
public record RequestActor(String username, String ipAddress, String userAgent) {

    /** An audit entry attributed to this actor. */
    public AuditLogService.Record entry(AuditOperation operation, String resourceId, String description) {
        return new AuditLogService.Record(operation, resourceId, description, username, ipAddress, userAgent);
    }
}
