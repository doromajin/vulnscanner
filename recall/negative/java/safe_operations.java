import java.util.Base64;
import java.util.List;
import java.util.ArrayList;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.LoaderOptions;

/**
 * Safe Java operations — no vulnerabilities expected.
 * Used to catch false positives from overly broad Java rule proposals.
 */
public class SafeOperations {

    // Safe: string/byte operations with no deserialization
    public String encodeData(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    // Safe: XML comment in code (not actual XML deserialization)
    public boolean isValidXml(String input) {
        return input != null && input.startsWith("<") && input.endsWith(">");
    }

    // Safe: collection operations that look like data processing
    public List<String> filterItems(List<String> items, String prefix) {
        List<String> result = new ArrayList<>();
        for (String item : items) {
            if (item.startsWith(prefix)) {
                result.add(item);
            }
        }
        return result;
    }

    // Safe: constant URL (no user input)
    public static final String BASE_URL = "https://api.example.com/v1";

    // Safe: logging with no tainted data
    public void logInfo(String message) {
        System.out.println("[INFO] " + message);
    }

    // Safe: SnakeYAML with SafeConstructor (JAST-DESER-002 must NOT fire)
    public Object safeYamlParse(String input) {
        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
        return yaml.load(input);
    }
}
