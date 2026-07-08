import java.beans.XMLDecoder;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import com.thoughtworks.xstream.XStream;

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
}
