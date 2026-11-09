package com.asmolabs.vectispire.common.domain.siem;

/**
 * A security event raised <b>after</b> what it describes was committed, for the SIEM export to queue in
 * a transaction of its own — the counterpart of {@link SecurityEventRaised}, for the fallback where the
 * two could not be written together (a gate verdict recorded alone). Never fails its publisher: the
 * export logs what it cannot queue.
 */
public record SecurityEventRaisedApart(CefEvent event) {}
