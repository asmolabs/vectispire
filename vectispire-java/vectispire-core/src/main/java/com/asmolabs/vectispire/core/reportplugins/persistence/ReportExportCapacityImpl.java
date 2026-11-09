package com.asmolabs.vectispire.core.reportplugins.persistence;

import java.util.Locale;
import java.util.OptionalLong;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * {@link ReportExportCapacity}, asked of the server. Found by Spring Data because it is the fragment's name plus
 * {@code Impl}; renaming either half leaves the repository unimplementable at startup.
 *
 * <p><b>Asked on the connection the row will be written on, at each run</b>, not configured: the value is the
 * server's, an operator raises it there, and a figure written here would be the day's default on the day it was
 * written. The session's value is the one the driver checks, read when the connection opened.
 */
public class ReportExportCapacityImpl implements ReportExportCapacity {

    private final JdbcTemplate jdbc;

    public ReportExportCapacityImpl(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public OptionalLong largestStatementBytes() {
        Long packet = jdbc.execute((ConnectionCallback<Long>) connection -> {
            if (!connection.getMetaData().getDatabaseProductName().toLowerCase(Locale.ROOT).contains("mysql")) {
                return null;
            }
            try (var statement = connection.createStatement();
                    var result = statement.executeQuery("select @@max_allowed_packet")) {
                return result.next() ? result.getLong(1) : null;
            }
        });
        return packet == null ? OptionalLong.empty() : OptionalLong.of(packet);
    }
}
