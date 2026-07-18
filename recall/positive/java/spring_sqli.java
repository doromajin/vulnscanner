import javax.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

/**
 * Spring JdbcTemplate SQL injection TP: JAST-SQL-001 must fire on SQL-concat patterns.
 */
public class SpringSqliTest {
    private JdbcTemplate jdbcTemplate;

    // DANGEROUS: user input concatenated into SQL (first arg is tainted)
    public String getUser(HttpServletRequest request) {
        String id = request.getParameter("id");
        return jdbcTemplate.queryForObject(
            "SELECT name FROM users WHERE id = " + id, String.class);  // JAST-SQL-001 HIGH
    }

    // DANGEROUS: query() with tainted SQL string
    public void listUsers(HttpServletRequest request) {
        String name = request.getParameter("name");
        jdbcTemplate.query(
            "SELECT * FROM users WHERE name = '" + name + "'",
            (rs, rowNum) -> rs.getString("id"));  // JAST-SQL-001 HIGH
    }
}
