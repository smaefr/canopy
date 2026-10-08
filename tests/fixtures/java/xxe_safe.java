import javax.xml.parsers.DocumentBuilderFactory;

class XxeSafe {
    void run() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.newDocumentBuilder();
    }
}
