/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.shibboleth.tool.xmlsectool;

import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.annotation.Nonnull;

import org.opensaml.security.x509.X509Credential;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

/**
 * Test that signature values are stable.
 * 
 * <p>In particular, they shouldn't include gash CR characters <em>in the Java
 * string content.</em>
 * </p>
 * 
 * @see <a href="https://issues.shibboleth.net/jira/browse/XSTJ-69">XSTJ-69</a>
 */
public class XSTJ69Test extends BaseTest {

    XSTJ69Test() {
        super(XSTJ69Test.class);
    }
    
    /** Character value we are looking for. */
    private static final char CR = '\r';
    
    /**
     * Look at a DOM tree and collect a list of the places it contains CRs.
     *
     * @param badNodes a {@link List} collecting the bad nodes, initially empty
     * @param element a DOM element to start from
     */
    private static void checkNoCRs(@Nonnull final List<Node> badNodes, @Nonnull final Element element) {
        // Check all text node children of the element
        for (Node node = element.getFirstChild(); node != null; node = node.getNextSibling()) {
            /*
             * There are three kinds of child node capable of including character data. We only need to
             * check TEXT_NODEs: CDATA sections and comments can't include CR characters, as
             * character references are not interpreted in either context.
             */
            if (node.getNodeType() == Node.TEXT_NODE && node.getNodeValue().indexOf(CR) >= 0) {
                badNodes.add(element);
            }
            
            /*
             * If it's an element, recurse.
             */
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                checkNoCRs(badNodes, (Element)node);
            }
        }

        // Also check any attributes on the element
        final NamedNodeMap attributes = element.getAttributes();
        for (int index=0; index<attributes.getLength(); index++) {
            final Node attribute = attributes.item(index);
            if (attribute.getNodeValue().indexOf(CR) >= 0) {
                badNodes.add(attribute);
            }
        }

    }

    private Document testSigningWith(@Nonnull final X509Credential cred,
            @Nonnull final CommandLineArguments cli) throws Exception {
        // acquire a document to sign
        final Document xml = readXMLDocument("in.xml");
        
        // perform signature operation
        XMLSecTool.sign(cli, cred, xml);
        
        // verify the signature using our own code for consistency
        XMLSecTool.verifySignature(cli, cred, xml);

        // Look at individual elements of the signature and validate that they do NOT
        // include CR characters. These shouldn't appear within Java strings, only in
        // the serialized output and only on Windows. If they appear as literal CRs in
        // this environment, they will appear in the output file as encoded CRs
        // (&#13; or &#xD; or similar). Some processors of SAML metadata will balk
        // if they see these.
        final var badNodes = new ArrayList<Node>();
        checkNoCRs(badNodes, xml.getDocumentElement());
        if (!badNodes.isEmpty()) {
            var result = badNodes.stream()
                    .map(Node::getNodeName)
                    .collect(Collectors.joining(", "));
            Assert.fail("CRs appear within: " + result);
        }

        return xml;
    }

    @Test
    public void xstj69() throws Exception {
        // acquire credentials to sign with
        final var rsaCredential = getPackageSigningCredential("rsasign2k", "RSA", RSAPublicKey.class);

        // build command-line arguments
        final String[] args = {
                "--sign",
                "--inFile", "in.xml",
                "--outFile", "out.xml",
                "--certificate", "sign.crt",
                "--keyFile", "sign.key"
                };
        final var cli = new CommandLineArguments();
        cli.parseCommandLineArguments(args);
        XMLSecTool.initLogging(cli);

        // Detailed tests on the more common RSA signatures
        final var rsaDocument = testSigningWith(rsaCredential, cli);
        // compare with output from V2.x
        final Document out = readXMLDocument("out.xml");
        zapSignatureValues(rsaDocument);
        zapSignatureValues(out);
        assertXMLIdentical(out.getDocumentElement(), rsaDocument.getDocumentElement());
        
        // Superficial test with EC signature
        final var ecCredential = getPackageSigningCredential("ecsign384", "EC", ECPublicKey.class);
        testSigningWith(ecCredential, cli);

        // Superficial test with DSA signature
        final var dsaCredential = getPackageSigningCredential("dsa1024", "DSA", DSAPublicKey.class);
        testSigningWith(dsaCredential, cli);
    }
}
