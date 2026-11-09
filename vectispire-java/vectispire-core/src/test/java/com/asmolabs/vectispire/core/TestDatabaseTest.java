package com.asmolabs.vectispire.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import org.junit.jupiter.api.Test;

/**
 * The suite's connections write no binary log: on a full disk, MySQL waits for space before a commit
 * that must write it, and a run hung an hour and a half that way (see {@code TestDatabase.UNLOGGED}).
 */
class TestDatabaseTest {

    @Test
    void aConnectionOfTheSuiteWritesNoBinaryLog() throws Exception {
        try (TestDatabase.Scratch scratch = TestDatabase.scratch();
             Connection connection = DriverManager.getConnection(scratch.url(), scratch.user(), scratch.password());
             Statement statement = connection.createStatement();
             ResultSet logged = statement.executeQuery("select @@session.sql_log_bin, @@global.log_bin")) {
            logged.next();
            assertThat(logged.getInt(1)).as("this session's binary log").isZero();
            // The server keeps it on, as a deployment's does: only the suite's sessions are exempt.
            assertThat(logged.getInt(2)).as("the server's binary log").isEqualTo(1);
        }
    }
}
