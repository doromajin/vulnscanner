import java.beans.XMLDecoder;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import com.thoughtworks.xstream.XStream;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

public class VulnerableDeserialization {

    // DESER-005: ObjectInputStream.readObject() with untrusted data
    public Object deserializeFromRequest(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(
            new java.io.ByteArrayInputStream(data)
        );
        return ois.readObject();
    }

    // DESER-009: XStream.fromXML() — RCE via malicious XML
    public Object xstreamDeserialize(String xml) {
        XStream xstream = new XStream();
        return xstream.fromXML(xml);
    }

    // DESER-010: XMLDecoder — arbitrary object instantiation from XML
    public Object xmlDecoderDeserialize(String filePath) throws Exception {
        XMLDecoder decoder = new XMLDecoder(
            new BufferedInputStream(new FileInputStream(filePath))
        );
        return decoder.readObject();
    }

    // JAST-DESER-002 / JAVA-TLS-002: SnakeYAML without SafeConstructor (CVE-2022-1471)
    public Object yamlDeserialize(String input) {
        Yaml yaml = new Yaml();
        return yaml.load(input);
    }

    // JAST-DESER-002 variant: Yaml with unsafe Constructor
    public Object yamlDeserializeTyped(String input) {
        Yaml yaml = new Yaml(new Constructor(Object.class));
        return yaml.load(input);
    }
}
