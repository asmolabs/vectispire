package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.core.access.persistence.UserEntity;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The people a document names, by the name it may print: an account's <b>display name</b>, never its
 * e-mail address nor its user name (decision 0035, answer 3).
 *
 * <p><b>Why not the user name the rows record.</b> A triage decision, a checklist answer and a sign-off
 * record who acted by user name, so that the row stays readable after the account is gone. Signed in
 * through an identity provider, that user name is often the person's e-mail address — which a document
 * leaving the platform must not carry. The display name is the one the account chose to be shown by.
 */
@Service
public class AccountNames {

    /** One bind parameter each, and PostgreSQL refuses a statement past 65,535: a document names many. */
    private static final int LOOKUP_BATCH = 1_000;

    /** Anything shaped like an address, anywhere in the name: "Ada <ada@example.org>" is one too. */
    private static final Pattern EMAIL = Pattern.compile("[^\\s@<>]+@[^\\s@<>]+\\.[^\\s@<>]+");

    private final UserRepository users;

    public AccountNames(UserRepository users) {
        this.users = users;
    }

    /**
     * An account as a document names it.
     *
     * @param displayName null where the account has none: its user name is not offered in its place
     */
    public record Named(long accountId, String displayName) {}

    /**
     * The accounts these user names belong to now, by user name. A name no account holds any more is
     * absent from the answer — the document then names nobody rather than print what the row kept.
     */
    @Transactional(readOnly = true)
    public Map<String, Named> byUsername(Collection<String> usernames) {
        List<String> distinct = List.copyOf(new LinkedHashSet<>(usernames.stream().filter(Objects::nonNull).toList()));
        Map<String, Named> named = new HashMap<>();
        for (int from = 0; from < distinct.size(); from += LOOKUP_BATCH) {
            for (UserEntity user : users.findByUsernameIn(distinct.subList(from, Math.min(from + LOOKUP_BATCH,
                    distinct.size())))) {
                named.put(user.getUsername(), new Named(user.getId(), displayName(user)));
            }
        }
        return Map.copyOf(named);
    }

    /** An account by its id, as a document names it; empty for an id no account holds. */
    @Transactional(readOnly = true)
    public Optional<Named> byId(long accountId) {
        return users.findById(accountId).map(user -> new Named(user.getId(), displayName(user)));
    }

    /**
     * The display name, unless it is an e-mail address after all — the account's own, or any. An identity
     * provider without a name claim fills the display name with the address, and a person may type theirs:
     * either way it is the one value a document may not carry, so the document names the account by id.
     */
    private static String displayName(UserEntity user) {
        String stored = user.getDisplayName();
        if (stored == null || stored.isBlank()) {
            return null;
        }
        String name = stored.strip();
        boolean address = EMAIL.matcher(name).find()
                || (user.getEmail() != null && name.equalsIgnoreCase(user.getEmail().strip()));
        return address ? null : name;
    }
}
