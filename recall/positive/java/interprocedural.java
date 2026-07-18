import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.Statement;

/**
 * Java interprocedural taint: this.method() patterns.
 * JAST-SQL-001 must fire for both cases.
 */
public class InterproceduralTest {

    // Case 1: this.helper() inherently reads request — bare call
    private String getParam(HttpServletRequest request) {
        return request.getParameter("input");
    }

    public void processBarCall(HttpServletRequest request, Connection conn) throws Exception {
        String val = getParam(request);  // bare call — already handled
        Statement st = conn.createStatement();
        st.executeQuery("SELECT * FROM t WHERE x='" + val + "'");
    }

    // Case 2: this.helper(tainted_arg) passthrough — this.method() call
    private String sanitize(String x) {
        return x;  // passthrough: taint flows through
    }

    public void processThisCall(HttpServletRequest request, Connection conn) throws Exception {
        String raw = request.getParameter("q");
        String val = this.sanitize(raw);  // this.method(tainted) — was skipped before fix
        Statement st = conn.createStatement();
        st.executeQuery("SELECT * FROM t WHERE x='" + val + "'");
    }
}
