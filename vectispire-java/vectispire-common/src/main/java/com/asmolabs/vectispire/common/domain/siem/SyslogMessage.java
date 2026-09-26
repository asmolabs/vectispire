package com.asmolabs.vectispire.common.domain.siem;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * A CEF event as an RFC 5424 syslog message, and its framing on a stream.
 *
 * <pre>
 *   &lt;PRI&gt;1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
 *   &lt;82&gt;1 2026-09-26T10:00:00.123Z vectispire-1 vectispire - ZAN-SEC-007 - CEF:0|Vectispire|…
 * </pre>
 *
 * <ul>
 *   <li><b>Facility 10</b> (security/authorization), which every syslog daemon routes by name as
 *       {@code authpriv}. The severity is derived from the CEF one, so a collector filtering on the
 *       syslog header and one reading the CEF agree about what is urgent.
 *   <li><b>MSGID is the CEF signature identifier</b>, so a collector can route on the header without
 *       parsing the payload.
 *   <li><b>No BOM before MSG.</b> RFC 5424 allows a UTF-8 message without one ({@code MSG-ANY}), and
 *       CEF parsers read {@code CEF:0|} at the first byte: a BOM there makes a well-formed event
 *       unparseable on the receivers that matter.
 * </ul>
 *
 * <p>On TCP and TLS, <b>octet counting</b> (RFC 6587 §3.4.1): the frame is the message's length in
 * bytes, a space, then the message. Newline framing was the alternative, and it is exactly the one
 * a log injection needs — a line break smuggled into a field becomes a second, forged event. CEF
 * escapes line breaks already; octet counting means the framing would not depend on it.
 */
public final class SyslogMessage {

    private SyslogMessage() {}

    /** Security/authorization messages, RFC 5424 §6.2.1. */
    static final int FACILITY = 10;

    static final String APP_NAME = "vectispire";

    private static final String NIL = "-";

    /** Milliseconds, in UTC: RFC 5424 allows up to six fractional digits, and three is what CEF's {@code rt} carries, so the two agree. */
    private static final DateTimeFormatter TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

    /** RFC 5424 limits HOSTNAME to 255 printable characters. */
    private static final int MAX_HOSTNAME = 255;

    /**
     * The syslog message carrying one CEF line.
     *
     * @param hostname this instance's name as the header states it; anything outside printable
     *     US-ASCII is dropped, and nothing left becomes the NILVALUE — a space in the header would
     *     shift every field after it
     */
    public static String format(SecurityEventType type, Instant timestamp, String hostname, String cef) {
        return "<" + priority(type) + ">1 "
                + TIMESTAMP.format(timestamp) + " "
                + headerToken(hostname, MAX_HOSTNAME) + " "
                + APP_NAME + " "
                + NIL + " "
                + headerToken(type.signatureId(), 32) + " "
                + NIL + " "
                + cef;
    }

    /** {@code MSG-LEN SP SYSLOG-MSG}, the length counted in bytes of the UTF-8 encoding, not in characters. */
    public static byte[] octetCounted(String message) {
        byte[] body = message.getBytes(StandardCharsets.UTF_8);
        byte[] prefix = (body.length + " ").getBytes(StandardCharsets.US_ASCII);
        byte[] frame = new byte[prefix.length + body.length];
        System.arraycopy(prefix, 0, frame, 0, prefix.length);
        System.arraycopy(body, 0, frame, prefix.length, body.length);
        return frame;
    }

    /** {@code facility × 8 + severity}. */
    static int priority(SecurityEventType type) {
        return FACILITY * 8 + syslogSeverity(type.cefSeverity());
    }

    /**
     * The CEF band as a syslog severity: very high is critical, high is error, medium is warning,
     * low is notice. Nothing maps to alert or emergency — those page somebody at night, and a
     * forwarded application event has no business deciding that for a SOC.
     */
    static int syslogSeverity(int cefSeverity) {
        if (cefSeverity >= 9) {
            return 2;
        }
        if (cefSeverity >= 7) {
            return 3;
        }
        if (cefSeverity >= 4) {
            return 4;
        }
        return 5;
    }

    private static String headerToken(String value, int maxLength) {
        if (value == null) {
            return NIL;
        }
        StringBuilder printable = new StringBuilder();
        value.chars().filter(c -> c >= 33 && c <= 126).limit(maxLength).forEach(c -> printable.append((char) c));
        return printable.isEmpty() ? NIL : printable.toString();
    }
}
