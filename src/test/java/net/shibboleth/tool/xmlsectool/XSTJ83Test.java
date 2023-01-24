package net.shibboleth.tool.xmlsectool;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.security.interfaces.ECPublicKey;
import java.util.List;

import javax.annotation.Nonnull;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.KeyValue;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import net.shibboleth.shared.xml.ElementSupport;
import net.shibboleth.shared.xml.SchemaBuilder.SchemaLanguage;

/**
 * Test for basic EC signatures.
 */
public class XSTJ83Test extends BaseTest {

    XSTJ83Test() {
        super(XSTJ83Test.class);
    }

    /**
     * Test a single credential.
     *
     * @param keyFile file holding the EC key
     * @param certFile file holding the certificate
     * @param size expected size of the EC key
     * @param testResource name of the (class-relative) test resource
     *
     * @throws Exception if something goes wrong
     */
    private void testSingle(@Nonnull final File keyFile, @Nonnull final File certFile,
            final int size, @Nonnull final String testResource)
            throws Exception {
        // command-line arguments for signature
        final String[] args = {
                "--sign",
                "--inFile", testResource,
                "--outFile", "out.xml",
                "--keyFile", keyFile.getAbsolutePath(),
                "--certificate", certFile.getAbsolutePath(),
                };
        final CommandLineArguments cli = new CommandLineArguments();
        cli.parseCommandLineArguments(args);
        XMLSecTool.initLogging(cli);

        final var signingCredential = CredentialHelper.getFileBasedCredentials(cli.getKeyFile(), "",
                certFile.getAbsolutePath());
        Assert.assertNotNull(signingCredential);
        final var verifyCredential = CredentialHelper.getFileBasedCredentials(null, "",
                cli.getCertificate());
        Assert.assertNotNull(verifyCredential);

        var pubKey = signingCredential.getPublicKey();
        Assert.assertNotNull(pubKey);
        // System.out.println(pubKey.getClass());
        Assert.assertEquals(pubKey.getAlgorithm(), "EC");
        Assert.assertTrue(pubKey instanceof ECPublicKey);
        var ecPubKey = (ECPublicKey) pubKey;
        Assert.assertEquals(ecPubKey.getParams().getCurve().getField().getFieldSize(), size);

        // acquire a document to sign
        final Document xml = readXMLDocument(testResource);
        
        // perform signature operation
        XMLSecTool.sign(cli, signingCredential, xml);
        
        // verify the signature using our own code for consistency
        XMLSecTool.verifySignature(cli, verifyCredential, xml);

        // take a careful look at the signature
        final Element signatureElement = XMLSecTool.getSignatureElement(xml);
        final Element keyInfoElement = ElementSupport.getFirstChildElement(signatureElement,
                KeyInfo.DEFAULT_ELEMENT_NAME);
        final List<Element> keyInfoChildren = ElementSupport.getChildElements(keyInfoElement);
        Assert.assertFalse(keyInfoChildren.isEmpty());
        final List<Element> keyValues = ElementSupport.getChildElements(keyInfoElement, KeyValue.DEFAULT_ELEMENT_NAME);
        for (final Element keyValue : keyValues) {
            Assert.assertNotNull(ElementSupport.getFirstChildElement(keyValue), "empty KeyValue element");
        }

        // validate the resulting XML; this will also show up any error
        final SchemaValidator validator = new SchemaValidator(SchemaLanguage.XML, getSchemaDirectory());
        validator.validate(new DOMSource(xml));
        
        // Now serialise the document
        final byte[] bytes;
        try (var out = new ByteArrayOutputStream()) {
            final TransformerFactory tfac = TransformerFactory.newInstance();
            final Transformer serializer = tfac.newTransformer();
            serializer.setOutputProperty("encoding", "UTF-8");
            serializer.transform(new DOMSource(xml), new StreamResult(out));
            bytes = out.toByteArray();
        }        
        
        // Read it back in again
        final Document doc2;
        try (final InputStream input = new ByteArrayInputStream(bytes)) {
            doc2 = getParserPool().parse(input);
        }
        
        // verify the signature using our own code for consistency
        XMLSecTool.verifySignature(cli, verifyCredential, doc2);
        
    }

    /**
     * Test with one of our own credentials.
     *
     * @throws Exception if something goes wrong
     */
    @Test
    public void testOpenSSHKey() throws Exception {
        final var keyFile = packageRelativeFile("ecsign384.key");
        final var certFile = packageRelativeFile("ecsign384.crt");
        testSingle(keyFile, certFile, 384, "meta.xml");
    }

    /**
     * Test with the credential from the submission.
     *
     * @throws Exception if something goes wrong
     */
    @Test
    public void testProvidedKey() throws Exception {
        final var keyFile = classRelativeFile("secp256r1.key");
        final var certFile = classRelativeFile("server.pem");
        testSingle(keyFile, certFile, 256, "meta.xml");
    }

}
