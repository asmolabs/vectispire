package com.asmolabs.vectispire.common.domain.errors;

/**
 * The {@code code} member of every problem the API answers: what the refusal is, for a program, beside
 * the {@code detail} that says it to a person.
 *
 * <p><b>Why a member and not the sentence.</b> A pipeline that had to tell "the target is not there"
 * from "this key may not ask" from "the gate route moved" matched the English {@code detail}, and the
 * sentence is written for the person reading a log — it changes with its wording, and a match on it
 * breaks on the next edit without anything failing. Decision 0043 §6 has a stable code beside it before
 * 1.0 freezes the API. The gate's own verdict already carried one per violation ({@code rule}); its
 * refusals, and every other route's, did not.
 *
 * <p><b>Added, not substituted.</b> {@code type} stays what it was — {@code about:blank}, or {@code
 * urn:vectispire:problem:<cause>} for a conflict naming its cause, in which case the code <em>is</em>
 * that cause. {@code status} and {@code detail} are unchanged. The codes are lowercase tokens of letters,
 * digits and hyphens, like a conflict's cause, and the set is open as every enum here is (0043 §1): a
 * client meeting a code it does not know falls back on {@code status}.
 *
 * <p><b>Named where the refusal is mapped</b>, so a code is a property of the kind of refusal rather
 * than of the route: every 404 of an absent or hidden row reads {@code not-found}, whichever module
 * answered it, which is also what keeps a hidden row indistinguishable from an absent one.
 */
public final class ProblemCode {

    /** RFC 9457's extension member that carries it. */
    public static final String MEMBER = "code";

    public static final String INVALID_REQUEST = "invalid-request";
    public static final String AUTHENTICATION_REQUIRED = "authentication-required";
    public static final String FORBIDDEN = "forbidden";
    public static final String CREDENTIAL_NOT_ACCEPTED = "credential-not-accepted";
    public static final String IMPORT_REFUSED = "import-refused";
    public static final String PASSWORD_CHANGE_REQUIRED = "password-change-required";
    public static final String NOT_FOUND = "not-found";
    public static final String NO_SUCH_ROUTE = "no-such-route";
    public static final String METHOD_NOT_ALLOWED = "method-not-allowed";
    public static final String NOT_ACCEPTABLE = "not-acceptable";
    public static final String CONFLICT = "conflict";
    public static final String ALREADY_QUEUED = "already-queued";
    public static final String NOT_ATTESTABLE = "not-attestable";
    public static final String SOLUTION_NOT_EMPTY = "solution-not-empty";
    public static final String PLUGIN_CONFLICT = "plugin-conflict";
    public static final String PRECONDITION_FAILED = "precondition-failed";
    public static final String ENCRYPTION_KEY_MISSING = "encryption-key-missing";
    public static final String CREDENTIAL_WITHHELD = "credential-withheld";
    public static final String CONTENT_TOO_LARGE = "content-too-large";
    public static final String UNSUPPORTED_MEDIA_TYPE = "unsupported-media-type";
    public static final String UNSAFE_URL = "unsafe-url";
    public static final String UNPROCESSABLE = "unprocessable";
    public static final String RATE_LIMITED = "rate-limited";
    public static final String UNEXPECTED_FAILURE = "unexpected-failure";
    public static final String UNAVAILABLE = "unavailable";

    private ProblemCode() {}

    /**
     * The code of a refusal known only by its status — Spring's own, a {@code ResponseStatusException},
     * the container's error page. A refusal with a more precise kind is given its code where it is mapped.
     */
    public static String forStatus(int status) {
        return switch (status) {
            case 400 -> INVALID_REQUEST;
            case 401 -> AUTHENTICATION_REQUIRED;
            case 403 -> FORBIDDEN;
            case 404 -> NOT_FOUND;
            case 405 -> METHOD_NOT_ALLOWED;
            case 406 -> NOT_ACCEPTABLE;
            case 409 -> CONFLICT;
            case 412 -> PRECONDITION_FAILED;
            case 413 -> CONTENT_TOO_LARGE;
            case 415 -> UNSUPPORTED_MEDIA_TYPE;
            case 422 -> UNPROCESSABLE;
            case 429 -> RATE_LIMITED;
            case 502, 503, 504 -> UNAVAILABLE;
            default -> status >= 500 ? UNEXPECTED_FAILURE : "http-" + status;
        };
    }
}
