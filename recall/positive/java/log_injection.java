import javax.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Java log injection TP: JAST-LOG-001 must fire.
 */
public class LogInjectionTest {
    private static final Logger logger = LoggerFactory.getLogger(LogInjectionTest.class);

    public void handle(HttpServletRequest request) {
        String user = request.getParameter("user");
        logger.info("Login attempt: " + user);   // JAST-LOG-001 MEDIUM
    }
}
