/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson8Test extends LessonTest {

  @Test
  public void oneAccount() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.8.one"))))
        .andExpect(jsonPath("$.output", containsString("<table><tr><th>")));
  }

  @Test
  public void multipleAccounts() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A' OR '1' = '1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(true)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.8.success"))))
        .andExpect(
            jsonPath(
                "$.output",
                containsString(
                    "<tr><td>96134<\\/td><td>Bob<\\/td><td>Franco<\\/td><td>Marketing<\\/td><td>83700<\\/td><td>LO9S2V<\\/td><\\/tr>")));
  }

  @Test
  public void wrongNameReturnsNoAccounts() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smithh")
                .param("auth_tan", "3SL99A"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.8.no.results"))))
        .andExpect(jsonPath("$.output").doesNotExist());
  }

  @Test
  public void wrongTANReturnsNoAccounts() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smithh")
                .param("auth_tan", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.8.no.results"))))
        .andExpect(jsonPath("$.output").doesNotExist());
  }

  @Test
  public void malformedQueryReturnsError() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A' OR '1' = '1'"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.output", containsString("feedback-negative")));
  }

  /**
   * Regression test: the log() method must use a PreparedStatement, not string concatenation.
   * A classic SQL injection payload in the action parameter must NOT cause an error or alter
   * the query structure — it must be treated as a literal string by the parameterized INSERT.
   */
  @Test
  public void logMethodUsesPreparedStatementForSqlInjectionPayload() throws Exception {
    // This payload would break out of a string-concatenated SQL query and cause a syntax error
    // if the log() method were still using Statement + string concatenation.
    // With PreparedStatement, the single quote is treated as a literal character, not SQL syntax,
    // so the request completes without error.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smith")
                .param("auth_tan", "'); DROP TABLE access_log; --"))
        .andExpect(status().isOk())
        // The lesson should not throw an internal server error;
        // it should return a normal (failed) lesson result.
        .andExpect(jsonPath("$.output", not(containsString("500"))));
  }

  /**
   * Regression test: a payload containing a single quote in auth_tan must not cause an
   * unhandled SQL error from the log() method. Verifies the parameterized log INSERT
   * handles special characters safely.
   */
  @Test
  public void logMethodHandlesSingleQuoteWithoutSqlError() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smith")
                .param("auth_tan", "O'Brien"))
        .andExpect(status().isOk())
        // A single quote in the value should not propagate as a SQL syntax error
        // from the log statement (PreparedStatement handles it as a bound parameter).
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.8.no.results"))));
  }

  /**
   * Unit test: verifies that SqlInjectionLesson8.log() calls prepareStatement() on the
   * connection, not createStatement(). This directly validates that the fix replaced the
   * vulnerable Statement with a PreparedStatement.
   */
  @Test
  public void logMethodCallsPrepareStatementNotCreateStatement() throws SQLException {
    Connection mockConnection = mock(Connection.class);
    PreparedStatement mockPreparedStatement = mock(PreparedStatement.class);

    // The parameterized INSERT query that the fixed log() method should use
    when(mockConnection.prepareStatement("INSERT INTO access_log (time, action) VALUES (?, ?)"))
        .thenReturn(mockPreparedStatement);

    // Must not throw — with PreparedStatement, any action string is safe
    assertDoesNotThrow(
        () ->
            SqlInjectionLesson8.log(
                mockConnection, "') OR '1'='1'; INSERT INTO access_log VALUES ('evil', 'payload"));

    // Verify prepareStatement was called (not createStatement which would be vulnerable)
    verify(mockConnection)
        .prepareStatement("INSERT INTO access_log (time, action) VALUES (?, ?)");

    // Verify the injection payload was bound as a parameter, not concatenated into SQL
    verify(mockPreparedStatement).setString(2, "') OR '1'='1'; INSERT INTO access_log VALUES ('evil', 'payload");
    verify(mockPreparedStatement).executeUpdate();
  }
}
