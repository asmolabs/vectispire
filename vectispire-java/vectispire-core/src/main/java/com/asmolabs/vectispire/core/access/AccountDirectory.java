package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The accounts another module asks after by id, or as a whole — the checklist contacts, which offer the
 * accounts able to fill a project's checklist in and remind them by their address (decision 0044).
 *
 * <p>A view, never the row: the secrets stay in this module ({@link UserView}). Who may be shown which of
 * these properties is the caller's question — the route listing a project's candidates sends a name and
 * nothing else, the reminder reads the address to send to it.
 */
@Service
public class AccountDirectory {

    private final UserRepository users;

    public AccountDirectory(UserRepository users) {
        this.users = users;
    }

    /** Every active account, by user name. */
    @Transactional(readOnly = true)
    public List<UserView> active() {
        return users.findAllByOrderByUsernameAsc().stream()
                .filter(user -> Boolean.TRUE.equals(user.getIsActive()))
                .map(UserView::of)
                .toList();
    }

    /** An account by its id, active or not; empty for an id no account holds any more. */
    @Transactional(readOnly = true)
    public Optional<UserView> byId(long accountId) {
        return users.findById(accountId).map(UserView::of);
    }
}
